// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * sigsnoop	Trace standard and real-time signals.
 *
 * Copyright (c) 2021~2022 Hengqi Chen
 *
 * 08-Aug-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <libgen.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sigsnoop.h"
#include "sigsnoop.skel.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static int target_signals = 0;
static bool failed_only = false;
static bool kill_only = false;
static bool signal_name = false;
static bool verbose = false;

static const char *sig_name[] = {
	[0] = "N/A",
	[1] = "SIGHUP",
	[2] = "SIGINT",
	[3] = "SIGQUIT",
	[4] = "SIGILL",
	[5] = "SIGTRAP",
	[6] = "SIGABRT",
	[7] = "SIGBUS",
	[8] = "SIGFPE",
	[9] = "SIGKILL",
	[10] = "SIGUSR1",
	[11] = "SIGSEGV",
	[12] = "SIGUSR2",
	[13] = "SIGPIPE",
	[14] = "SIGALRM",
	[15] = "SIGTERM",
	[16] = "SIGSTKFLT",
	[17] = "SIGCHLD",
	[18] = "SIGCONT",
	[19] = "SIGSTOP",
	[20] = "SIGTSTP",
	[21] = "SIGTTIN",
	[22] = "SIGTTOU",
	[23] = "SIGURG",
	[24] = "SIGXCPU",
	[25] = "SIGXFSZ",
	[26] = "SIGVTALRM",
	[27] = "SIGPROF",
	[28] = "SIGWINCH",
	[29] = "SIGIO",
	[30] = "SIGPWR",
	[31] = "SIGSYS",
};

const char *argp_program_version = "sigsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "Trace standard and real-time signals.\n"
    "\n"
    "USAGE: sigsnoop [-h] [-x] [-k] [-n] [-p PID] [-s SIGNAL]\n"
    "\n"
    "EXAMPLES:\n"
    "    sigsnoop             # trace signals system-wide\n"
    "    sigsnoop -k          # trace signals issued by kill syscall only\n"
    "    sigsnoop -x          # trace failed signals only\n"
    "    sigsnoop -p 1216     # only trace PID 1216\n"
    "    sigsnoop -s 1,9,15   # trace signal 1, 9, 15\n";

static const struct argp_option opts[] = {
    {"failed", 'x', NULL, 0, "Trace failed signals only.", 0},
    {"kill", 'k', NULL, 0, "Trace signals issued by kill syscall only.", 0},
    {"pid", 'p', "PID", 0, "Process ID to trace", 0},
    {"signal", 's', "SIGNAL", 0, "Signals to trace.", 0},
    {"name", 'n', NULL, 0, "Output signal name instead of signal number.", 0},
    {"verbose", 'v', NULL, 0, "Verbose debug output", 0},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
    {},
};

struct bpf_object {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *events;
                struct bpf_map *values;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *kill_entry;
                struct bpf_program *kill_exit;
                struct bpf_program *tkill_entry;
                struct bpf_program *tkill_exit;
                struct bpf_program *tgkill_entry;
                struct bpf_program *tgkill_exit;
                struct bpf_program *sig_trace;
        } progs;
        struct {
                struct bpf_link *kill_entry;
                struct bpf_link *kill_exit;
                struct bpf_link *tkill_entry;
                struct bpf_link *tkill_exit;
                struct bpf_link *tgkill_entry;
                struct bpf_link *tgkill_exit;
                struct bpf_link *sig_trace;
        } links;
        struct sigsnoop_bpf__rodata {
                pid_t filtered_pid;
                int target_signals;
                bool failed_only;
        } *rodata;
}; 

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, sig;
        char *token;

        switch (key) {
        case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 's':
		errno = 0;
                token = strtok(arg, ",");
                while (token) {
                  sig = strtol(token, NULL, 10);
                  if (errno || sig <= 0 || sig > 31) {
                    warn("Inavlid SIGNAL: %s\n", token);
                    argp_usage(state);
                  }
                  target_signals |= (1 << (sig - 1));
                  token = strtok(NULL, ",");
                }
                break;
        case 'n':
		signal_name = true;
		break;
	case 'x':
		failed_only = true;
		break;
	case 'k':
		kill_only = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (strstr(name, "killsnoop")) {
		kill_only = true;
	}
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (signal_name && e->sig < ARRAY_SIZE(sig_name))
		printf("%-8s %-7d %-16s %-9s %-7d %-6d\n",
		       ts, e->pid, e->comm, sig_name[e->sig], e->tpid, e->ret);
	else
		printf("%-8s %-7d %-16s %-9d %-7d %-6d\n",
		       ts, e->pid, e->comm, e->sig, e->tpid, e->ret);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static inline int
bpf_object__create_skeleton(struct bpf_object *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "sigsnoop_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 3;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "events";
        s->maps[0].map = &obj->maps.events;

        s->maps[1].name = "values";
        s->maps[1].map = &obj->maps.values;

        s->maps[2].name = "sigsnoop.rodata";
        s->maps[2].map = &obj->maps.rodata;
        s->maps[2].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 7;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "kill_entry";
        s->progs[0].prog = &obj->progs.kill_entry;
        s->progs[0].link = &obj->links.kill_entry;

        s->progs[1].name = "kill_exit";
        s->progs[1].prog = &obj->progs.kill_exit;
        s->progs[1].link = &obj->links.kill_exit;

        s->progs[2].name = "tkill_entry";
        s->progs[2].prog = &obj->progs.tkill_entry;
        s->progs[2].link = &obj->links.tkill_entry;

        s->progs[3].name = "tkill_exit";
        s->progs[3].prog = &obj->progs.tkill_exit;
        s->progs[3].link = &obj->links.tkill_exit;

        s->progs[4].name = "tgkill_entry";
        s->progs[4].prog = &obj->progs.tgkill_entry;
        s->progs[4].link = &obj->links.tgkill_entry;

        s->progs[5].name = "tgkill_exit";
        s->progs[5].prog = &obj->progs.tgkill_exit;
        s->progs[5].link = &obj->links.tgkill_exit;

        s->progs[6].name = "sig_trace";
        s->progs[6].prog = &obj->progs.sig_trace;
        s->progs[6].link = &obj->links.sig_trace;

	s->data    = obj_buf;
	s->data_sz = obj_buf_sz;

        obj->skeleton = s;
        return 0;
err:
        bpf_object__destroy_skeleton(s);
        return err;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct bpf_object *obj;
	int err;

	alias_parse(argv[0]);
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

        obj = (struct bpf_object *)calloc(1, sizeof(*obj));
        if (!obj) {
                errno = ENOMEM;
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, NULL);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->filtered_pid = target_pid;
        obj->rodata->target_signals = target_signals;
        obj->rodata->failed_only = failed_only;

	if (kill_only) {
		bpf_program__set_autoload(obj->progs.sig_trace, false);
	} else {
		bpf_program__set_autoload(obj->progs.kill_entry, false);
		bpf_program__set_autoload(obj->progs.kill_exit, false);
		bpf_program__set_autoload(obj->progs.tkill_entry, false);
		bpf_program__set_autoload(obj->progs.tkill_exit, false);
		bpf_program__set_autoload(obj->progs.tgkill_entry, false);
		bpf_program__set_autoload(obj->progs.tgkill_exit, false);
	}

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_object__attach_skeleton(obj->skeleton);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("%-8s %-7s %-16s %-9s %-7s %-6s\n",
	       "TIME", "PID", "COMM", "SIG", "TPID", "RESULT");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	bpf_object__destroy_skeleton(obj->skeleton);

	return err != 0;
}
