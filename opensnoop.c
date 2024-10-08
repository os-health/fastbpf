// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "opensnoop.h"
#include "opensnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES	64
#define PERF_BUFFER_TIME_MS	10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS	100

#define NSEC_PER_SEC		1000000000ULL

static volatile sig_atomic_t exiting = 0;

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#endif

static struct env {
	pid_t pid;
	pid_t tid;
	uid_t uid;
	int duration;
	bool verbose;
	bool timestamp;
	bool print_uid;
	bool extended;
	bool failed;
	char *name;
#ifdef USE_BLAZESYM
	bool callers;
#endif
} env = {
	.uid = INVALID_UID
};

struct object_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *start;
                struct bpf_map *events;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *tracepoint__syscalls__sys_enter_open;
                struct bpf_program *tracepoint__syscalls__sys_enter_openat;
                struct bpf_program *tracepoint__syscalls__sys_exit_open;
                struct bpf_program *tracepoint__syscalls__sys_exit_openat;
        } progs;
        struct {
                struct bpf_link *tracepoint__syscalls__sys_enter_open;
                struct bpf_link *tracepoint__syscalls__sys_enter_openat;
                struct bpf_link *tracepoint__syscalls__sys_exit_open;
                struct bpf_link *tracepoint__syscalls__sys_exit_openat;
        } links;
        struct bpf_object__rodata {
                pid_t targ_pid;
                pid_t targ_tgid;
                uid_t targ_uid;
                bool targ_failed;
        } *rodata;
};

const char *argp_program_version = "opensnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace open family syscalls\n"
"\n"
"USAGE: opensnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID] [-u UID] [-d DURATION]\n"
#ifdef USE_BLAZESYM
"                 [-n NAME] [-e] [-c]\n"
#else
"                 [-n NAME] [-e]\n"
#endif
"\n"
"EXAMPLES:\n"
"    ./opensnoop           # trace all open() syscalls\n"
"    ./opensnoop -T        # include timestamps\n"
"    ./opensnoop -U        # include UID\n"
"    ./opensnoop -x        # only show failed opens\n"
"    ./opensnoop -p 181    # only trace PID 181\n"
"    ./opensnoop -t 123    # only trace TID 123\n"
"    ./opensnoop -u 1000   # only trace UID 1000\n"
"    ./opensnoop -d 10     # trace for 10 seconds only\n"
"    ./opensnoop -n main   # only print process names containing \"main\"\n"
"    ./opensnoop -e        # show extended fields\n"
#ifdef USE_BLAZESYM
"    ./opensnoop -c        # show calling functions\n"
#endif
"";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to trace", 0 },
	{ "extended-fields", 'e', NULL, 0, "Print extended fields", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{ "name", 'n', "NAME", 0, "Trace process names containing this", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread ID to trace", 0 },
	{ "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
	{ "uid", 'u', "UID", 0, "User ID to trace", 0 },
	{ "print-uid", 'U', NULL, 0, "Print UID", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "failed", 'x', NULL, 0, "Failed opens only", 0 },
#ifdef USE_BLAZESYM
	{ "callers", 'c', NULL, 0, "Show calling functions", 0 },
#endif
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	long int pid, uid, duration;

	switch (key) {
	case 'e':
		env.extended = true;
		break;
	case 'h':
		argp_usage(state);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'x':
		env.failed = true;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		env.duration = duration;
		break;
	case 'n':
		errno = 0;
		env.name = arg;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
		break;
	case 'u':
		errno = 0;
		uid = strtol(arg, NULL, 10);
		if (errno || uid < 0 || uid >= INVALID_UID) {
			fprintf(stderr, "Invalid UID %s\n", arg);
			argp_usage(state);
		}
		env.uid = uid;
		break;
#ifdef USE_BLAZESYM
	case 'c':
		env.callers = true;
		break;
#endif
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	struct tm *tm;
#ifdef USE_BLAZESYM
	const blazesym_result *result = NULL;
	const blazesym_csym *sym;
	int i, j;
#endif
	int sps_cnt;
	char ts[32];
	time_t t;
	int fd, err;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	/* name filtering is currently done in user space */
	if (env.name && strstr(e.comm, env.name) == NULL)
		return;

	/* prepare fields */
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (e.ret >= 0) {
		fd = e.ret;
		err = 0;
	} else {
		fd = -1;
		err = - e.ret;
	}

#ifdef USE_BLAZESYM
	sym_src_cfg cfgs[] = {
		{ .src_type = SRC_T_PROCESS, .params = { .process = { .pid = e.pid }}},
	};
	if (env.callers)
		result = blazesym_symbolize(symbolizer, cfgs, 1, (const uint64_t *)&e.callers, 2);
#endif

	/* print output */
	sps_cnt = 0;
	if (env.timestamp) {
		printf("%-8s ", ts);
		sps_cnt += 9;
	}
	if (env.print_uid) {
		printf("%-7d ", e.uid);
		sps_cnt += 8;
	}
	printf("%-6d %-16s %3d %3d ", e.pid, e.comm, fd, err);
	sps_cnt += 7 + 17 + 4 + 4;
	if (env.extended) {
		printf("%08o ", e.flags);
		sps_cnt += 9;
	}
	printf("%s\n", e.fname);

#ifdef USE_BLAZESYM
	for (i = 0; result && i < result->size; i++) {
		if (result->entries[i].size == 0)
			continue;
		sym = &result->entries[i].syms[0];

		for (j = 0; j < sps_cnt; j++)
			printf(" ");
		if (sym->line_no)
			printf("%s:%ld\n", sym->symbol, sym->line_no);
		else
			printf("%s\n", sym->symbol);
	}

	blazesym_result_free(result);
#endif
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static inline int
bpf_object__create_skeleton(struct object_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) { 
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "opensnoop_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 3;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }
        
        s->maps[0].name = "start";
        s->maps[0].map = &obj->maps.start;

        s->maps[1].name = "events";
        s->maps[1].map = &obj->maps.events;
        
        s->maps[2].name = "opensnoo.rodata";
        s->maps[2].map = &obj->maps.rodata;
        s->maps[2].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 4;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "tracepoint__syscalls__sys_enter_open";
        s->progs[0].prog = &obj->progs.tracepoint__syscalls__sys_enter_open;
        s->progs[0].link = &obj->links.tracepoint__syscalls__sys_enter_open;

        s->progs[1].name = "tracepoint__syscalls__sys_enter_openat";
        s->progs[1].prog = &obj->progs.tracepoint__syscalls__sys_enter_openat;
        s->progs[1].link = &obj->links.tracepoint__syscalls__sys_enter_openat;

        s->progs[2].name = "tracepoint__syscalls__sys_exit_open";
        s->progs[2].prog = &obj->progs.tracepoint__syscalls__sys_exit_open;
        s->progs[2].link = &obj->links.tracepoint__syscalls__sys_exit_open;

        s->progs[3].name = "tracepoint__syscalls__sys_exit_openat";
        s->progs[3].prog = &obj->progs.tracepoint__syscalls__sys_exit_openat;
        s->progs[3].link = &obj->links.tracepoint__syscalls__sys_exit_openat;

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
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct object_bpf *obj;
	__u64 time_end = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

        obj = (struct object_bpf *)calloc(1, sizeof(*obj));
        if (!obj) {
                errno = ENOMEM;
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, &open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->targ_uid = env.uid;
	obj->rodata->targ_failed = env.failed;

	/* aarch64 and riscv64 don't have open syscall */
	if (!tracepoint_exists("syscalls", "sys_enter_open")) {
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_enter_open, false);
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_exit_open, false);
	}

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_object__attach_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

#ifdef USE_BLAZESYM
	if (env.callers)
		symbolizer = blazesym_new();
#endif

	/* print headers */
	if (env.timestamp)
		printf("%-8s ", "TIME");
	if (env.print_uid)
		printf("%-7s ", "UID");
	printf("%-6s %-16s %3s %3s ", "PID", "COMM", "FD", "ERR");
	if (env.extended)
		printf("%-8s ", "FLAGS");
	printf("%s", "PATH");
#ifdef USE_BLAZESYM
	if (env.callers)
		printf("/CALLER");
#endif
	printf("\n");

	/* setup event callbacks */
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
        bpf_object__destroy_skeleton(obj->skeleton);
	cleanup_core_btf(&open_opts);
#ifdef USE_BLAZESYM
	blazesym_free(symbolizer);
#endif

	return err != 0;
}
