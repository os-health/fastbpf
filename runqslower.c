// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
//
// Based on runqslower(8) from BCC by Ivan Babrou.
// 11-Feb-2020   Andrii Nakryiko   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "runqslower.h"
#include "runqslower.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting = 0;

struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	bool previous;
	bool verbose;
} env = {
	.min_us = 10000,
};

const char *argp_program_version = "runqslower 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace high run queue latency.\n"
"\n"
"USAGE: runqslower [--help] [-p PID] [-t TID] [-P] [min_us]\n"
"\n"
"EXAMPLES:\n"
"    runqslower         # trace latency higher than 10000 us (default)\n"
"    runqslower 1000    # trace latency higher than 1000 us\n"
"    runqslower -p 123  # trace pid 123\n"
"    runqslower -t 123  # trace tid 123 (use for threads only)\n"
"    runqslower -P      # also show previous task name and TID\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread TID to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "previous", 'P', NULL, 0, "also show previous task name and TID", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

struct runqslower_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *start;
                struct bpf_map *events;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *sched_wakeup;
                struct bpf_program *sched_wakeup_new;
                struct bpf_program *sched_switch;
                struct bpf_program *handle_sched_wakeup;
                struct bpf_program *handle_sched_wakeup_new;
                struct bpf_program *handle_sched_switch;
        } progs;
        struct {
                struct bpf_link *sched_wakeup;
                struct bpf_link *sched_wakeup_new;
                struct bpf_link *sched_switch;
                struct bpf_link *handle_sched_wakeup;
                struct bpf_link *handle_sched_wakeup_new;
                struct bpf_link *handle_sched_switch;
        } links;
        struct runqslower_bpf__rodata {
                __u64 min_us;
                pid_t targ_pid;
                pid_t targ_tgid;
        } *rodata;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int pid;
	long long min_us;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'P':
		env.previous = true;
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
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		min_us = strtoll(arg, NULL, 10);
		if (errno || min_us <= 0) {
			fprintf(stderr, "Invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
		env.min_us = min_us;
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
	char ts[32];
	time_t t;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (env.previous)
		printf("%-8s %-16s %-6d %14llu %-16s %-6d\n", ts, e.task, e.pid, e.delta_us, e.prev_task, e.prev_pid);
	else
		printf("%-8s %-16s %-6d %14llu\n", ts, e.task, e.pid, e.delta_us);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static inline int
bpf_object__create_skeleton(struct runqslower_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "runqslower_bpf";
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

        s->maps[2].name = "runqslow.rodata";
        s->maps[2].map = &obj->maps.rodata;
        s->maps[2].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 6;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "sched_wakeup";
        s->progs[0].prog = &obj->progs.sched_wakeup;
        s->progs[0].link = &obj->links.sched_wakeup;

        s->progs[1].name = "sched_wakeup_new";
        s->progs[1].prog = &obj->progs.sched_wakeup_new;
        s->progs[1].link = &obj->links.sched_wakeup_new;

        s->progs[2].name = "sched_switch";
        s->progs[2].prog = &obj->progs.sched_switch;
        s->progs[2].link = &obj->links.sched_switch;

        s->progs[3].name = "handle_sched_wakeup";
        s->progs[3].prog = &obj->progs.handle_sched_wakeup;
        s->progs[3].link = &obj->links.handle_sched_wakeup;

        s->progs[4].name = "handle_sched_wakeup_new";
        s->progs[4].prog = &obj->progs.handle_sched_wakeup_new;
        s->progs[4].link = &obj->links.handle_sched_wakeup_new;

        s->progs[5].name = "handle_sched_switch";
        s->progs[5].prog = &obj->progs.handle_sched_switch;
        s->progs[5].link = &obj->links.handle_sched_switch;

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
	struct runqslower_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

        obj = (struct runqslower_bpf *)calloc(1, sizeof(*obj));
        if (!obj) { 
                errno = ENOMEM; 
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, NULL);
	if (err) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->min_us = env.min_us;

	if (probe_tp_btf("sched_wakeup")) {
		bpf_program__set_autoload(obj->progs.handle_sched_wakeup, false);
		bpf_program__set_autoload(obj->progs.handle_sched_wakeup_new, false);
		bpf_program__set_autoload(obj->progs.handle_sched_switch, false);
	} else {
		bpf_program__set_autoload(obj->progs.sched_wakeup, false);
		bpf_program__set_autoload(obj->progs.sched_wakeup_new, false);
		bpf_program__set_autoload(obj->progs.sched_switch, false);
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

	printf("Tracing run queue latency higher than %llu us\n", env.min_us);
	if (env.previous)
		printf("%-8s %-16s %-6s %14s %-16s %-6s\n", "TIME", "COMM", "TID", "LAT(us)", "PREV COMM", "PREV TID");
	else
		printf("%-8s %-16s %-6s %14s\n", "TIME", "COMM", "TID", "LAT(us)");

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 64,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
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
