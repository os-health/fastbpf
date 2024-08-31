// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on softirq(8) from BCC by Brendan Gregg & Sasha Goldshtein.
// 15-Aug-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "softirqs.h"
#include "softirqs.skel.h"
#include "trace_helpers.h"

struct env {
	bool distributed;
	bool nanoseconds;
	bool count;
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
	.count = false,
};

static volatile bool exiting;

const char *argp_program_version = "softirqs 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize soft irq event time as histograms.\n"
"\n"
"USAGE: softirqs [--help] [-T] [-N] [-d] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    softirqs            # sum soft irq event time\n"
"    softirqs -d         # show soft irq event time as histograms\n"
"    softirqs 1 10       # print 1 second summaries, 10 times\n"
"    softirqs -NT 1      # 1s summaries, nanoseconds, and timestamps\n";

static const struct argp_option opts[] = {
	{ "distributed", 'd', NULL, 0, "Show distributions as histograms", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "nanoseconds", 'N', NULL, 0, "Output in nanoseconds", 0 },
	{ "count", 'C', NULL, 0, "Show event counts with timing", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

struct softirqs_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *start;
                struct bpf_map *rodata;
                struct bpf_map *bss;
        } maps;
        struct {
                struct bpf_program *softirq_entry_btf;
                struct bpf_program *softirq_exit_btf;
                struct bpf_program *softirq_entry;
                struct bpf_program *softirq_exit;
        } progs;
        struct {
                struct bpf_link *softirq_entry_btf;
                struct bpf_link *softirq_exit_btf;
                struct bpf_link *softirq_entry;
                struct bpf_link *softirq_exit;
        } links;
        struct softirqs_bpf__rodata {
                bool targ_dist;
                bool targ_ns;
        } *rodata;
        struct softirqs_bpf__bss {
                __u64 counts[10];
                __u64 time[10];
                struct hist hists[10];
        } *bss;
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
	case 'N':
		env.nanoseconds = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'C':
		env.count = true;
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

enum {
	HI_SOFTIRQ = 0,
	TIMER_SOFTIRQ = 1,
	NET_TX_SOFTIRQ = 2,
	NET_RX_SOFTIRQ = 3,
	BLOCK_SOFTIRQ = 4,
	IRQ_POLL_SOFTIRQ = 5,
	TASKLET_SOFTIRQ = 6,
	SCHED_SOFTIRQ = 7,
	HRTIMER_SOFTIRQ = 8,
	RCU_SOFTIRQ = 9,
	NR_SOFTIRQS = 10,
};

static char *vec_names[] = {
	[HI_SOFTIRQ] = "hi",
	[TIMER_SOFTIRQ] = "timer",
	[NET_TX_SOFTIRQ] = "net_tx",
	[NET_RX_SOFTIRQ] = "net_rx",
	[BLOCK_SOFTIRQ] = "block",
	[IRQ_POLL_SOFTIRQ] = "irq_poll",
	[TASKLET_SOFTIRQ] = "tasklet",
	[SCHED_SOFTIRQ] = "sched",
	[HRTIMER_SOFTIRQ] = "hrtimer",
	[RCU_SOFTIRQ] = "rcu",
};

static int print_count(struct softirqs_bpf__bss *bss)
{
	const char *units = env.nanoseconds ? "nsecs" : "usecs";
	__u64 count, time;
	__u32 vec;

	printf("%-16s %-6s%-5s  %-11s\n", "SOFTIRQ", "TOTAL_",
			units, env.count?"TOTAL_count":"");

	for (vec = 0; vec < NR_SOFTIRQS; vec++) {
		time = __atomic_exchange_n(&bss->time[vec], 0,
					__ATOMIC_RELAXED);
		count = __atomic_exchange_n(&bss->counts[vec], 0,
					__ATOMIC_RELAXED);
		if (count > 0) {
			printf("%-16s %11llu", vec_names[vec], time);
			if (env.count) {
				printf("  %11llu", count);
			}
			printf("\n");
		}
	}

	return 0;
}

static struct hist zero;

static int print_hist(struct softirqs_bpf__bss *bss)
{
	const char *units = env.nanoseconds ? "nsecs" : "usecs";
	__u32 vec;

	for (vec = 0; vec < NR_SOFTIRQS; vec++) {
		struct hist hist = bss->hists[vec];

		bss->hists[vec] = zero;
		if (!memcmp(&zero, &hist, sizeof(hist)))
			continue;
		printf("softirq = %s\n", vec_names[vec]);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		printf("\n");
	}

	return 0;
}

static inline int
bpf_object__create_skeleton(struct softirqs_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "softirqs_bpf";
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

        s->maps[1].name = "softirqs.rodata";
        s->maps[1].map = &obj->maps.rodata;
        s->maps[1].mmaped = (void **)&obj->rodata;

        s->maps[2].name = "softirqs.bss";
        s->maps[2].map = &obj->maps.bss;
        s->maps[2].mmaped = (void **)&obj->bss;

        /* programs */
        s->prog_cnt = 4;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "softirq_entry_btf";
        s->progs[0].prog = &obj->progs.softirq_entry_btf;
        s->progs[0].link = &obj->links.softirq_entry_btf;

        s->progs[1].name = "softirq_exit_btf";
        s->progs[1].prog = &obj->progs.softirq_exit_btf;
        s->progs[1].link = &obj->links.softirq_exit_btf;

        s->progs[2].name = "softirq_entry";
        s->progs[2].prog = &obj->progs.softirq_entry;
        s->progs[2].link = &obj->links.softirq_entry;

        s->progs[3].name = "softirq_exit";
        s->progs[3].prog = &obj->progs.softirq_exit;
        s->progs[3].link = &obj->links.softirq_exit;

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
	struct softirqs_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

        obj = (struct softirqs_bpf *)calloc(1, sizeof(*obj));
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

	if (probe_tp_btf("softirq_entry")) {
		bpf_program__set_autoload(obj->progs.softirq_entry, false);
		bpf_program__set_autoload(obj->progs.softirq_exit, false);
	} else {
		bpf_program__set_autoload(obj->progs.softirq_entry_btf, false);
		bpf_program__set_autoload(obj->progs.softirq_exit_btf, false);
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_dist = env.distributed;
	obj->rodata->targ_ns = env.nanoseconds;

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (!obj->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = bpf_object__attach_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing soft irq event time... Hit Ctrl-C to end.\n");

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

		if (!env.distributed)
			err = print_count(obj->bss);
		else
			err = print_hist(obj->bss);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	bpf_object__destroy_skeleton(obj->skeleton);

	return err != 0;
}
