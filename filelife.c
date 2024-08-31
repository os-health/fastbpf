// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on filelife(8) from BCC by Brendan Gregg & Allan McAleavy.
// 20-Mar-2020   Wenbo Zhang   Created this.
// 13-Nov-2022   Rong Tao      Check btf struct field for CO-RE and add vfs_open()
// 23-Aug-2023   Rong Tao      Add vfs_* 'struct mnt_idmap' support.(CO-RE)
// 08-Nov-2023   Rong Tao      Support unlink failed
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "filelife.h"
#include "filelife.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static struct env {
	pid_t pid;
	bool verbose;
} env = { };

struct filelife_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *start;
                struct bpf_map *events;
                struct bpf_map *currevent;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *vfs_create;
                struct bpf_program *vfs_open;
                struct bpf_program *security_inode_create;
                struct bpf_program *vfs_unlink;
                struct bpf_program *vfs_unlink_ret;
        } progs;
        struct {
                struct bpf_link *vfs_create;
                struct bpf_link *vfs_open;
                struct bpf_link *security_inode_create;
                struct bpf_link *vfs_unlink;
                struct bpf_link *vfs_unlink_ret;
        } links;
        struct filelife_bpf__rodata {
                pid_t targ_tgid;
        } *rodata;
};

const char *argp_program_version = "filelife 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace the lifespan of short-lived files.\n"
"\n"
"USAGE: filelife  [--help] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    filelife         # trace all events\n"
"    filelife -p 123  # trace pid 123\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
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
	printf("%-8s %-6d %-16s %-7.2f %s\n",
	       ts, e.tgid, e.task, (double)e.delta_ns / 1000000000,
	       e.file);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static inline int
bpf_object__create_skeleton(struct filelife_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "filelife_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 4;
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

        s->maps[2].name = "currevent";
        s->maps[2].map = &obj->maps.currevent;

        s->maps[3].name = "filelife.rodata";
        s->maps[3].map = &obj->maps.rodata;
        s->maps[3].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 5;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "vfs_create";
        s->progs[0].prog = &obj->progs.vfs_create;
        s->progs[0].link = &obj->links.vfs_create;

        s->progs[1].name = "vfs_open";
        s->progs[1].prog = &obj->progs.vfs_open;
        s->progs[1].link = &obj->links.vfs_open;

        s->progs[2].name = "security_inode_create";
        s->progs[2].prog = &obj->progs.security_inode_create;
        s->progs[2].link = &obj->links.security_inode_create;

        s->progs[3].name = "vfs_unlink";
        s->progs[3].prog = &obj->progs.vfs_unlink;
        s->progs[3].link = &obj->links.vfs_unlink;

        s->progs[4].name = "vfs_unlink_ret";
        s->progs[4].prog = &obj->progs.vfs_unlink_ret;
        s->progs[4].link = &obj->links.vfs_unlink_ret;

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
	struct filelife_bpf *obj;
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

        obj = (struct filelife_bpf *)calloc(1, sizeof(*obj));
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

	if (!kprobe_exists("security_inode_create"))
		bpf_program__set_autoload(obj->progs.security_inode_create, false);

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

	printf("Tracing the lifespan of short-lived files ... Hit Ctrl-C to end.\n");
	printf("%-8s %-6s %-16s %-7s %s\n", "TIME", "PID", "COMM", "AGE(s)", "FILE");

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
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
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
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
	cleanup_core_btf(&open_opts);

	return err != 0;
}
