// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Hengqi Chen
//
// Based on statsnoop(8) from BCC by Brendan Gregg.
// 09-May-2021   Hengqi Chen   Created this.
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "statsnoop.h"
#include "statsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool trace_failed_only = false;
static bool emit_timestamp = false;
static bool verbose = false;

const char *argp_program_version = "statsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace stat syscalls.\n"
"\n"
"USAGE: statsnoop [-h] [-t] [-x] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    statsnoop             # trace all stat syscalls\n"
"    statsnoop -t          # include timestamps\n"
"    statsnoop -x          # only show failed stats\n"
"    statsnoop -p 1216     # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "failed", 'x', NULL, 0, "Only show failed stats", 0 },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

struct statsnoop_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *values;
                struct bpf_map *events;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *handle_statfs_entry;
                struct bpf_program *handle_statfs_return;
                struct bpf_program *handle_newstat_entry;
                struct bpf_program *handle_newstat_return;
                struct bpf_program *handle_statx_entry;
                struct bpf_program *handle_statx_return;
                struct bpf_program *handle_newfstatat_entry;
                struct bpf_program *handle_newfstatat_return;
                struct bpf_program *handle_newlstat_entry;
                struct bpf_program *handle_newlstat_return;
        } progs;
        struct {
                struct bpf_link *handle_statfs_entry;
                struct bpf_link *handle_statfs_return;
                struct bpf_link *handle_newstat_entry;
                struct bpf_link *handle_newstat_return;
                struct bpf_link *handle_statx_entry;
                struct bpf_link *handle_statx_return;
                struct bpf_link *handle_newfstatat_entry;
                struct bpf_link *handle_newfstatat_return;
                struct bpf_link *handle_newlstat_entry;
                struct bpf_link *handle_newlstat_return;
        } links;
        struct statsnoop_bpf__rodata {
                pid_t target_pid;
                bool trace_failed_only;
        } *rodata;
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
	case 'x':
		trace_failed_only = true;
		break;
	case 't':
		emit_timestamp = true;
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

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	static __u64 start_timestamp = 0;
	struct event e;
	int fd, err;
	double ts = 0.0;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (e.ret >= 0) {
		fd = e.ret;
		err = 0;
	} else {
		fd = -1;
		err = -e.ret;
	}
	if (!start_timestamp)
		start_timestamp = e.ts_ns;
	if (emit_timestamp) {
		ts = (double)(e.ts_ns - start_timestamp) / 1000000000;
		printf("%-14.9f ", ts);
	}
	printf("%-7d %-20s %-4d %-4d %-s\n", e.pid, e.comm, fd, err, e.pathname);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static inline int
bpf_object__create_skeleton(struct statsnoop_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "statsnoop_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 3;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "values";
        s->maps[0].map = &obj->maps.values;

        s->maps[1].name = "events";
        s->maps[1].map = &obj->maps.events;

        s->maps[2].name = "statsnoo.rodata";
        s->maps[2].map = &obj->maps.rodata;
        s->maps[2].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 10;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "handle_statfs_entry";
        s->progs[0].prog = &obj->progs.handle_statfs_entry;
        s->progs[0].link = &obj->links.handle_statfs_entry;

        s->progs[1].name = "handle_statfs_return";
        s->progs[1].prog = &obj->progs.handle_statfs_return;
        s->progs[1].link = &obj->links.handle_statfs_return;

        s->progs[2].name = "handle_newstat_entry";
        s->progs[2].prog = &obj->progs.handle_newstat_entry;
        s->progs[2].link = &obj->links.handle_newstat_entry;

        s->progs[3].name = "handle_newstat_return";
        s->progs[3].prog = &obj->progs.handle_newstat_return;
        s->progs[3].link = &obj->links.handle_newstat_return;

        s->progs[4].name = "handle_statx_entry";
        s->progs[4].prog = &obj->progs.handle_statx_entry;
        s->progs[4].link = &obj->links.handle_statx_entry;

        s->progs[5].name = "handle_statx_return";
        s->progs[5].prog = &obj->progs.handle_statx_return;
        s->progs[5].link = &obj->links.handle_statx_return;

        s->progs[6].name = "handle_newfstatat_entry";
        s->progs[6].prog = &obj->progs.handle_newfstatat_entry;
        s->progs[6].link = &obj->links.handle_newfstatat_entry;

        s->progs[7].name = "handle_newfstatat_return";
        s->progs[7].prog = &obj->progs.handle_newfstatat_return;
        s->progs[7].link = &obj->links.handle_newfstatat_return;

        s->progs[8].name = "handle_newlstat_entry";
        s->progs[8].prog = &obj->progs.handle_newlstat_entry;
        s->progs[8].link = &obj->links.handle_newlstat_entry;

        s->progs[9].name = "handle_newlstat_return";
        s->progs[9].prog = &obj->progs.handle_newlstat_return;
        s->progs[9].link = &obj->links.handle_newlstat_return;

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
	struct statsnoop_bpf *obj;
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

        obj = (struct statsnoop_bpf *)calloc(1, sizeof(*obj));
        if (!obj) {
                errno = ENOMEM;
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, &open_opts);
	if (err) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->trace_failed_only = trace_failed_only;

	if (!tracepoint_exists("syscalls", "sys_enter_statfs")) {
		bpf_program__set_autoload(obj->progs.handle_statfs_entry, false);
		bpf_program__set_autoload(obj->progs.handle_statfs_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_statx")) {
		bpf_program__set_autoload(obj->progs.handle_statx_entry, false);
		bpf_program__set_autoload(obj->progs.handle_statx_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newstat")) {
		bpf_program__set_autoload(obj->progs.handle_newstat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newstat_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newfstatat")) {
		bpf_program__set_autoload(obj->progs.handle_newfstatat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newfstatat_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newlstat")) {
		bpf_program__set_autoload(obj->progs.handle_newlstat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newlstat_return, false);
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
		err = 1;
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-14s ", "TIME(s)");
	printf("%-7s %-20s %-4s %-4s %-s\n",
	       "PID", "COMM", "RET", "ERR", "PATH");

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

	return err != 0;
}
