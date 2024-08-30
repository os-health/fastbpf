/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * exitsnoop	Trace process termination.
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on exitsnoop(8) from BCC by Arturo Martin-de-Nicolas & Jeroen Soeters.
 * 05-Aug-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "exitsnoop.h"
#include "exitsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static pid_t target_pid = 0;
static bool trace_failed_only = false;
static bool trace_by_process = true;
static bool verbose = false;

static struct env {
	char *cgroupspath;
	bool cg;
} env;

struct object_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *cgroup_map;
                struct bpf_map *events;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *sched_process_exit;
        } progs;
        struct {
                struct bpf_link *sched_process_exit;
        } links;
        struct exitsnoop_bpf__rodata {
                bool filter_cg;
                pid_t target_pid;
                bool trace_failed_only;
                bool trace_by_process;
        } *rodata;
};

const char *argp_program_version = "exitsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace process termination.\n"
"\n"
"USAGE: exitsnoop [-h] [-t] [-x] [-p PID] [-T] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    exitsnoop             # trace process exit events\n"
"    exitsnoop -t          # include timestamps\n"
"    exitsnoop -x          # trace error exits only\n"
"    exitsnoop -p 1216     # only trace PID 1216\n"
"    exitsnoop -T          # trace by thread\n"
"    exitsnoop -c CG       # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ "failed", 'x', NULL, 0, "Trace error exits only.", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "threaded", 'T', NULL, 0, "Trace by thread.", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;

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
	case 't':
		emit_timestamp = true;
		break;
	case 'x':
		trace_failed_only = true;
		break;
	case 'T':
		trace_by_process = false;
		break;
	case 'v':
		verbose = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
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

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	time_t t;
	struct tm *tm;
	char ts[32];
	double age;
	int sig, coredump;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%8s ", ts);
	}

	age = (e.exit_time - e.start_time) / 1e9;
	printf("%-16s %-7d %-7d %-7d %-7.2f ",
	       e.comm, e.pid, e.ppid, e.tid, age);

	if (!e.sig) {
		if (!e.exit_code)
			printf("0\n");
		else
			printf("code %d\n", e.exit_code);
	} else {
		sig = e.sig & 0x7f;
		coredump = e.sig & 0x80;
		if (sig)
			printf("signal %d (%s)", sig, strsignal(sig));
		if (coredump)
			printf(", core dumped");
		printf("\n");
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
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
        s->name = "exitsnoop_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 3;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "cgroup_map";
        s->maps[0].map = &obj->maps.cgroup_map;

        s->maps[1].name = "events";
        s->maps[1].map = &obj->maps.events;

        s->maps[2].name = "exitsnoo.rodata";
        s->maps[2].map = &obj->maps.rodata;
        s->maps[2].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 1;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "sched_process_exit";
        s->progs[0].prog = &obj->progs.sched_process_exit;
        s->progs[0].link = &obj->links.sched_process_exit;

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
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

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
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->trace_failed_only = trace_failed_only;
	obj->rodata->trace_by_process = trace_by_process;
	obj->rodata->filter_cg = env.cg;

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
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
		err = 1;
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-16s %-7s %-7s %-7s %-7s %-s\n",
	       "PCOMM", "PID", "PPID", "TID", "AGE(s)", "EXIT_CODE");

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
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
