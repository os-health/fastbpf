// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on vfsstat(8) from BCC by Brendan Gregg
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include "vfsstat.h"
#include "vfsstat.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

const char *argp_program_version = "vfsstat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
	"\nvfsstat: Count some VFS calls\n"
	"\n"
	"EXAMPLES:\n"
	"    vfsstat      # interval one second\n"
	"    vfsstat 5 3  # interval five seconds, three output lines\n";
static char args_doc[] = "[interval [count]]";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static struct env {
	bool verbose;
	int count;
	int interval;
} env = {
	.interval = 1,	/* once a second */
};

struct vfsstat_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *bss;
        } maps;
        struct {
                struct bpf_program *kprobe_vfs_read;
                struct bpf_program *kprobe_vfs_write;
                struct bpf_program *kprobe_vfs_fsync;
                struct bpf_program *kprobe_vfs_open;
                struct bpf_program *kprobe_vfs_create;
                struct bpf_program *kprobe_vfs_unlink;
                struct bpf_program *kprobe_vfs_mkdir;
                struct bpf_program *kprobe_vfs_rmdir;
                struct bpf_program *fentry_vfs_read;
                struct bpf_program *fentry_vfs_write;
                struct bpf_program *fentry_vfs_fsync;
                struct bpf_program *fentry_vfs_open;
                struct bpf_program *fentry_vfs_create;
                struct bpf_program *fentry_vfs_unlink;
                struct bpf_program *fentry_vfs_mkdir;
                struct bpf_program *fentry_vfs_rmdir;
        } progs;
        struct {
                struct bpf_link *kprobe_vfs_read;
                struct bpf_link *kprobe_vfs_write;
                struct bpf_link *kprobe_vfs_fsync;
                struct bpf_link *kprobe_vfs_open;
                struct bpf_link *kprobe_vfs_create;
                struct bpf_link *kprobe_vfs_unlink;
                struct bpf_link *kprobe_vfs_mkdir;
                struct bpf_link *kprobe_vfs_rmdir;
                struct bpf_link *fentry_vfs_read;
                struct bpf_link *fentry_vfs_write;
                struct bpf_link *fentry_vfs_fsync;
                struct bpf_link *fentry_vfs_open;
                struct bpf_link *fentry_vfs_create;
                struct bpf_link *fentry_vfs_unlink;
                struct bpf_link *fentry_vfs_mkdir;
                struct bpf_link *fentry_vfs_rmdir;
        } links;
        struct vfsstat_bpf__bss {
                __u64 stats[8];
        } *bss;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long interval;
	long count;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case 0:
			errno = 0;
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0 || interval > INT_MAX) {
				fprintf(stderr, "invalid interval: %s\n", arg);
				argp_usage(state);
			}
			env.interval = interval;
			break;
		case 1:
			errno = 0;
			count = strtol(arg, NULL, 10);
			if (errno || count < 0 || count > INT_MAX) {
				fprintf(stderr, "invalid count: %s\n", arg);
				argp_usage(state);
			}
			env.count = count;
			break;
		default:
			argp_usage(state);
			break;
		}
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

static const char *strftime_now(char *s, size_t max, const char *format)
{
	struct tm *tm;
	time_t t;

	t = time(NULL);
	tm = localtime(&t);
	if (tm == NULL) {
		fprintf(stderr, "localtime: %s\n", strerror(errno));
		return "<failed>";
	}
	if (strftime(s, max, format, tm) == 0) {
		fprintf(stderr, "strftime error\n");
		return "<failed>";
	}
	return s;
}

static const char *stat_types_names[] = {
	[S_READ] = "READ",
	[S_WRITE] = "WRITE",
	[S_FSYNC] = "FSYNC",
	[S_OPEN] = "OPEN",
	[S_CREATE] = "CREATE",
	[S_UNLINK] = "UNLINK",
	[S_MKDIR] = "MKDIR",
	[S_RMDIR] = "RMDIR",
};

static void print_header(void)
{
	int i;

	printf("%-8s  ", "TIME");
	for (i = 0; i < S_MAXSTAT; i++)
		printf(" %6s/s", stat_types_names[i]);
	printf("\n");
}

static void print_and_reset_stats(__u64 stats[S_MAXSTAT])
{
	char s[16];
	__u64 val;
	int i;

	printf("%-8s: ", strftime_now(s, sizeof(s), "%H:%M:%S"));
	for (i = 0; i < S_MAXSTAT; i++) {
		val = __atomic_exchange_n(&stats[i], 0, __ATOMIC_RELAXED);
		printf(" %8llu", val / env.interval);
	}
	printf("\n");
}

static inline int
bpf_object__create_skeleton(struct vfsstat_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "vfsstat_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 1;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "vfsstat_.bss";
        s->maps[0].map = &obj->maps.bss;
        s->maps[0].mmaped = (void **)&obj->bss;

        /* programs */
        s->prog_cnt = 16;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "kprobe_vfs_read";
        s->progs[0].prog = &obj->progs.kprobe_vfs_read;
        s->progs[0].link = &obj->links.kprobe_vfs_read;

        s->progs[1].name = "kprobe_vfs_write";
        s->progs[1].prog = &obj->progs.kprobe_vfs_write;
        s->progs[1].link = &obj->links.kprobe_vfs_write;

        s->progs[2].name = "kprobe_vfs_fsync";
        s->progs[2].prog = &obj->progs.kprobe_vfs_fsync;
        s->progs[2].link = &obj->links.kprobe_vfs_fsync;

        s->progs[3].name = "kprobe_vfs_open";
        s->progs[3].prog = &obj->progs.kprobe_vfs_open;
        s->progs[3].link = &obj->links.kprobe_vfs_open;

        s->progs[4].name = "kprobe_vfs_create";
        s->progs[4].prog = &obj->progs.kprobe_vfs_create;
        s->progs[4].link = &obj->links.kprobe_vfs_create;

        s->progs[5].name = "kprobe_vfs_unlink";
        s->progs[5].prog = &obj->progs.kprobe_vfs_unlink;
        s->progs[5].link = &obj->links.kprobe_vfs_unlink;

        s->progs[6].name = "kprobe_vfs_mkdir";
        s->progs[6].prog = &obj->progs.kprobe_vfs_mkdir;
        s->progs[6].link = &obj->links.kprobe_vfs_mkdir;

        s->progs[7].name = "kprobe_vfs_rmdir";
        s->progs[7].prog = &obj->progs.kprobe_vfs_rmdir;
        s->progs[7].link = &obj->links.kprobe_vfs_rmdir;

        s->progs[8].name = "fentry_vfs_read";
        s->progs[8].prog = &obj->progs.fentry_vfs_read;
        s->progs[8].link = &obj->links.fentry_vfs_read;

        s->progs[9].name = "fentry_vfs_write";
        s->progs[9].prog = &obj->progs.fentry_vfs_write;
        s->progs[9].link = &obj->links.fentry_vfs_write;

        s->progs[10].name = "fentry_vfs_fsync";
        s->progs[10].prog = &obj->progs.fentry_vfs_fsync;
        s->progs[10].link = &obj->links.fentry_vfs_fsync;

        s->progs[11].name = "fentry_vfs_open";
        s->progs[11].prog = &obj->progs.fentry_vfs_open;
        s->progs[11].link = &obj->links.fentry_vfs_open;

        s->progs[12].name = "fentry_vfs_create";
        s->progs[12].prog = &obj->progs.fentry_vfs_create;
        s->progs[12].link = &obj->links.fentry_vfs_create;

        s->progs[13].name = "fentry_vfs_unlink";
        s->progs[13].prog = &obj->progs.fentry_vfs_unlink;
        s->progs[13].link = &obj->links.fentry_vfs_unlink;

        s->progs[14].name = "fentry_vfs_mkdir";
        s->progs[14].prog = &obj->progs.fentry_vfs_mkdir;
        s->progs[14].link = &obj->links.fentry_vfs_mkdir;

        s->progs[15].name = "fentry_vfs_rmdir";
        s->progs[15].prog = &obj->progs.fentry_vfs_rmdir;
        s->progs[15].link = &obj->links.fentry_vfs_rmdir;

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
		.args_doc = args_doc,
	};
	struct vfsstat_bpf *skel;
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

        skel = (struct vfsstat_bpf *)calloc(1, sizeof(*skel));
        if (!skel) {
                errno = ENOMEM;
                goto cleanup;
        }

        err = bpf_object__create_skeleton(skel, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(skel->skeleton, NULL);
	if (err) {
		fprintf(stderr, "failed to open BPF skelect\n");
		return 1;
	}

	/* It fallbacks to kprobes when kernel does not support fentry. */
	if (fentry_can_attach("vfs_read", NULL)) {
		bpf_program__set_autoload(skel->progs.kprobe_vfs_read, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_write, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_fsync, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_open, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_create, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_unlink, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_mkdir, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_rmdir, false);
	} else {
		bpf_program__set_autoload(skel->progs.fentry_vfs_read, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_write, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_fsync, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_open, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_create, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_unlink, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_mkdir, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_rmdir, false);
	}

	err = bpf_object__load_skeleton(skel->skeleton);
	if (err) {
		fprintf(stderr, "failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	if (!skel->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = bpf_object__attach_skeleton(skel->skeleton);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n",
				strerror(-err));
		goto cleanup;
	}

	print_header();
	do {
		sleep(env.interval);
		print_and_reset_stats(skel->bss->stats);
	} while (!env.count || --env.count);

cleanup:
	bpf_object__destroy_skeleton(skel->skeleton);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
