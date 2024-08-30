// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on hardirq(8) from BCC by Brendan Gregg.
// 31-Aug-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "hardirqs.h"
#include "hardirqs.skel.h"
#include "trace_helpers.h"

struct env {
	bool count;
	bool distributed;
	bool nanoseconds;
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

struct object_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *cgroup_map;
                struct bpf_map *start;
                struct bpf_map *infos;
                struct bpf_map *rodata;
                struct bpf_map *bss;
        } maps;
        struct {
                struct bpf_program *irq_handler_entry_btf;
                struct bpf_program *irq_handler_exit_btf;
                struct bpf_program *irq_handler_entry;
                struct bpf_program *irq_handler_exit;
        } progs;
        struct {
                struct bpf_link *irq_handler_entry_btf;
                struct bpf_link *irq_handler_exit_btf;
                struct bpf_link *irq_handler_entry;
                struct bpf_link *irq_handler_exit;
        } links;
        struct hardirqs_bpf__rodata {
                bool filter_cg;
                bool targ_dist;
                bool targ_ns;
                bool do_count;
        } *rodata;
        struct hardirqs_bpf__bss {
        } *bss;
}; 

static volatile bool exiting;

const char *argp_program_version = "hardirqs 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize hard irq event time as histograms.\n"
"\n"
"USAGE: hardirqs [--help] [-T] [-N] [-d] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    hardirqs            # sum hard irq event time\n"
"    hardirqs -d         # show hard irq event time as histograms\n"
"    hardirqs 1 10       # print 1 second summaries, 10 times\n"
"    hardirqs -c CG      # Trace process under cgroupsPath CG\n"
"    hardirqs -NT 1      # 1s summaries, nanoseconds, and timestamps\n";

static const struct argp_option opts[] = {
	{ "count", 'C', NULL, 0, "Show event counts instead of timing", 0 },
	{ "distributed", 'd', NULL, 0, "Show distributions as histograms", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "nanoseconds", 'N', NULL, 0, "Output in nanoseconds", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.distributed = true;
		break;
	case 'C':
		env.count = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'N':
		env.nanoseconds = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
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

static void sig_handler(int sig)
{
	exiting = true;
}

static int print_map(struct bpf_map *map)
{
	struct irq_key lookup_key = {}, next_key;
	struct info info;
	int fd, err;

	if (env.count) {
		printf("%-26s %11s\n", "HARDIRQ", "TOTAL_count");
	} else if (!env.distributed) {
		const char *units = env.nanoseconds ? "nsecs" : "usecs";

		printf("%-26s %6s%5s\n", "HARDIRQ", "TOTAL_", units);
	}

	fd = bpf_map__fd(map);
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}
		if (!env.distributed)
			printf("%-26s %11llu\n", next_key.name, info.count);
		else {
			const char *units = env.nanoseconds ? "nsecs" : "usecs";

			printf("hardirq = %s\n", next_key.name);
			print_log2_hist(info.slots, MAX_SLOTS, units);
		}
		lookup_key = next_key;
	}

	memset(&lookup_key, 0, sizeof(lookup_key));

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup infos: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
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
        s->name = "hardirqs_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 5;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "cgroup_map";
        s->maps[0].map = &obj->maps.cgroup_map;

        s->maps[1].name = "start";
        s->maps[1].map = &obj->maps.start;

        s->maps[2].name = "infos";
        s->maps[2].map = &obj->maps.infos;

        s->maps[3].name = "hardirqs.rodata";
        s->maps[3].map = &obj->maps.rodata;
        s->maps[3].mmaped = (void **)&obj->rodata;

        s->maps[4].name = "hardirqs.bss";
        s->maps[4].map = &obj->maps.bss;
        s->maps[4].mmaped = (void **)&obj->bss;

        /* programs */
        s->prog_cnt = 4;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "irq_handler_entry_btf";
        s->progs[0].prog = &obj->progs.irq_handler_entry_btf;
        s->progs[0].link = &obj->links.irq_handler_entry_btf;

        s->progs[1].name = "irq_handler_exit_btf";
        s->progs[1].prog = &obj->progs.irq_handler_exit_btf;
        s->progs[1].link = &obj->links.irq_handler_exit_btf;

        s->progs[2].name = "irq_handler_entry";
        s->progs[2].prog = &obj->progs.irq_handler_entry;
        s->progs[2].link = &obj->links.irq_handler_entry;

        s->progs[3].name = "irq_handler_exit";
        s->progs[3].prog = &obj->progs.irq_handler_exit;
        s->progs[3].link = &obj->links.irq_handler_exit;

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
	struct object_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.count && env.distributed) {
		fprintf(stderr, "count, distributed cann't be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

        obj = (struct object_bpf *)calloc(1, sizeof(*obj));
        if (!obj) {
                errno = ENOMEM;
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, NULL);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("irq_handler_entry")) {
		bpf_program__set_autoload(obj->progs.irq_handler_entry, false);
		bpf_program__set_autoload(obj->progs.irq_handler_exit, false);
		if (env.count)
			bpf_program__set_autoload(obj->progs.irq_handler_exit_btf, false);
	} else {
		bpf_program__set_autoload(obj->progs.irq_handler_entry_btf, false);
		bpf_program__set_autoload(obj->progs.irq_handler_exit_btf, false);
		if (env.count)
			bpf_program__set_autoload(obj->progs.irq_handler_exit, false);
	}

	obj->rodata->filter_cg = env.cg;
	obj->rodata->do_count = env.count;

	/* initialize global data (filtering options) */
	if (!env.count) {
		obj->rodata->targ_dist = env.distributed;
		obj->rodata->targ_ns = env.nanoseconds;
	}

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
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
		fprintf(stderr, "failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	if (env.count)
		printf("Tracing hard irq events... Hit Ctrl-C to end.\n");
	else
		printf("Tracing hard irq event time... Hit Ctrl-C to end.\n");

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_map(obj->maps.infos);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	bpf_object__destroy_skeleton(obj->skeleton);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
