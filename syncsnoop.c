// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Tiago Ilieve
//
// Based on syncsnoop(8) from BCC by Brendan Gregg.
// 08-Feb-2024   Tiago Ilieve   Created this.
// 19-Jul-2024   Rong Tao       Support more sync syscalls
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include "syncsnoop.h"
#include "syncsnoop.skel.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100

static volatile sig_atomic_t exiting = 0;

struct env {
	bool verbose;
} env = {};

const char *argp_program_version = "syncsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace sync syscalls.\n"
"\n"
"USAGE: syncsnoop [--help]\n"
"\n"
"EXAMPLES:\n"
"    syncsnoop  # trace sync syscalls\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

struct syncsnoop_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *events;
        } maps;
        struct {
                struct bpf_program *tracepoint__syscalls__sys_enter_sync;
                struct bpf_program *tracepoint__syscalls__sys_enter_fsync;
                struct bpf_program *tracepoint__syscalls__sys_enter_fdatasync;
                struct bpf_program *tracepoint__syscalls__sys_enter_msync;
                struct bpf_program *tracepoint__syscalls__sys_enter_sync_file_range;
                struct bpf_program *tracepoint__syscalls__sys_enter_syncfs;
        } progs;
        struct {
                struct bpf_link *tracepoint__syscalls__sys_enter_sync;
                struct bpf_link *tracepoint__syscalls__sys_enter_fsync;
                struct bpf_link *tracepoint__syscalls__sys_enter_fdatasync;
                struct bpf_link *tracepoint__syscalls__sys_enter_msync;
                struct bpf_link *tracepoint__syscalls__sys_enter_sync_file_range;
                struct bpf_link *tracepoint__syscalls__sys_enter_syncfs;
        } links;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
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
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	printf("%-18.9f %-16s %-16s\n", (float) e.ts_us  / 1000000, e.comm,
	       sys_names[e.sys]);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static inline int
bpf_object__create_skeleton(struct syncsnoop_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "syncsnoop_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 1;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "events";
        s->maps[0].map = &obj->maps.events;

        /* programs */
        s->prog_cnt = 6;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "tracepoint__syscalls__sys_enter_sync";
        s->progs[0].prog = &obj->progs.tracepoint__syscalls__sys_enter_sync;
        s->progs[0].link = &obj->links.tracepoint__syscalls__sys_enter_sync;

        s->progs[1].name = "tracepoint__syscalls__sys_enter_fsync";
        s->progs[1].prog = &obj->progs.tracepoint__syscalls__sys_enter_fsync;
        s->progs[1].link = &obj->links.tracepoint__syscalls__sys_enter_fsync;

        s->progs[2].name = "tracepoint__syscalls__sys_enter_fdatasync";
        s->progs[2].prog = &obj->progs.tracepoint__syscalls__sys_enter_fdatasync;
        s->progs[2].link = &obj->links.tracepoint__syscalls__sys_enter_fdatasync;

        s->progs[3].name = "tracepoint__syscalls__sys_enter_msync";
        s->progs[3].prog = &obj->progs.tracepoint__syscalls__sys_enter_msync;
        s->progs[3].link = &obj->links.tracepoint__syscalls__sys_enter_msync;

        s->progs[4].name = "tracepoint__syscalls__sys_enter_sync_file_range";
        s->progs[4].prog = &obj->progs.tracepoint__syscalls__sys_enter_sync_file_range;
        s->progs[4].link = &obj->links.tracepoint__syscalls__sys_enter_sync_file_range;

        s->progs[5].name = "tracepoint__syscalls__sys_enter_syncfs";
        s->progs[5].prog = &obj->progs.tracepoint__syscalls__sys_enter_syncfs;
        s->progs[5].link = &obj->links.tracepoint__syscalls__sys_enter_syncfs;

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
	struct syncsnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

        obj = (struct syncsnoop_bpf *)calloc(1, sizeof(*obj));
        if (!obj) {
                errno = ENOMEM;
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, NULL);
	if (err) {
		fprintf(stderr, "failed to open and load BPF object\n");
		return 1;
	}

	err = bpf_object__load_skeleton(obj->skeleton);

	err = bpf_object__attach_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to attach BPF object\n");
		return 1;
	}

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

	/* print header */
	printf("%-18s %-16s %s\n", "TIME(s)", "COMM", "CALL");

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

	return err != 0;
}