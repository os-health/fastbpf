// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Wenbo Zhang
//
// Based on cachestat(8) from BCC by Brendan Gregg and Allan McAleavy.
//  8-Mar-2021   Wenbo Zhang   Created this.
// 30-Jan-2023   Rong Tao      Add kprobe and use fentry_can_attach() decide
//                             use fentry/kprobe
// 15-Feb-2023   Rong Tao      Add tracepoint writeback_dirty_{page,folio}
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cachestat.skel.h"
#include "trace_helpers.h"

static struct env {
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 1,
	.times = 99999999,
};

struct cachestat_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *bss;
        } maps;
        struct {
                struct bpf_program *fentry_add_to_page_cache_lru;
                struct bpf_program *fentry_mark_page_accessed;
                struct bpf_program *fentry_account_page_dirtied;
                struct bpf_program *fentry_mark_buffer_dirty;
                struct bpf_program *kprobe_add_to_page_cache_lru;
                struct bpf_program *kprobe_mark_page_accessed;
                struct bpf_program *kprobe_account_page_dirtied;
                struct bpf_program *kprobe_folio_account_dirtied;
                struct bpf_program *kprobe_mark_buffer_dirty;
                struct bpf_program *tracepoint__writeback_dirty_folio;
                struct bpf_program *tracepoint__writeback_dirty_page;
        } progs;
        struct {
                struct bpf_link *fentry_add_to_page_cache_lru;
                struct bpf_link *fentry_mark_page_accessed;
                struct bpf_link *fentry_account_page_dirtied;
                struct bpf_link *fentry_mark_buffer_dirty;
                struct bpf_link *kprobe_add_to_page_cache_lru;
                struct bpf_link *kprobe_mark_page_accessed;
                struct bpf_link *kprobe_account_page_dirtied;
                struct bpf_link *kprobe_folio_account_dirtied;
                struct bpf_link *kprobe_mark_buffer_dirty;
                struct bpf_link *tracepoint__writeback_dirty_folio;
                struct bpf_link *tracepoint__writeback_dirty_page;
        } links;
        struct cachestat_bpf__bss {
                __s64 total;
                __s64 misses;
                __u64 mbd;
        } *bss;
};

static volatile bool exiting;

const char *argp_program_version = "cachestat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Count cache kernel function calls.\n"
"\n"
"USAGE: cachestat [--help] [-T] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    cachestat          # shows hits and misses to the file system page cache\n"
"    cachestat -T       # include timestamps\n"
"    cachestat 1 10     # print 1 second summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
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

static int get_meminfo(__u64 *buffers, __u64 *cached)
{
	FILE *f;

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return -1;
	if (fscanf(f,
		   "MemTotal: %*u kB\n"
		   "MemFree: %*u kB\n"
		   "MemAvailable: %*u kB\n"
		   "Buffers: %llu kB\n"
		   "Cached: %llu kB\n",
		   buffers, cached) != 2) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

static inline int
bpf_object__create_skeleton(struct cachestat_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "cachestat_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 1;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "cachesta.bss";
        s->maps[0].map = &obj->maps.bss;
        s->maps[0].mmaped = (void **)&obj->bss;

        /* programs */
        s->prog_cnt = 11;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "fentry_add_to_page_cache_lru";
        s->progs[0].prog = &obj->progs.fentry_add_to_page_cache_lru;
        s->progs[0].link = &obj->links.fentry_add_to_page_cache_lru;

        s->progs[1].name = "fentry_mark_page_accessed";
        s->progs[1].prog = &obj->progs.fentry_mark_page_accessed;
        s->progs[1].link = &obj->links.fentry_mark_page_accessed;

        s->progs[2].name = "fentry_account_page_dirtied";
        s->progs[2].prog = &obj->progs.fentry_account_page_dirtied;
        s->progs[2].link = &obj->links.fentry_account_page_dirtied;

        s->progs[3].name = "fentry_mark_buffer_dirty";
        s->progs[3].prog = &obj->progs.fentry_mark_buffer_dirty;
        s->progs[3].link = &obj->links.fentry_mark_buffer_dirty;

        s->progs[4].name = "kprobe_add_to_page_cache_lru";
        s->progs[4].prog = &obj->progs.kprobe_add_to_page_cache_lru;
        s->progs[4].link = &obj->links.kprobe_add_to_page_cache_lru;

        s->progs[5].name = "kprobe_mark_page_accessed";
        s->progs[5].prog = &obj->progs.kprobe_mark_page_accessed;
        s->progs[5].link = &obj->links.kprobe_mark_page_accessed;

        s->progs[6].name = "kprobe_account_page_dirtied";
        s->progs[6].prog = &obj->progs.kprobe_account_page_dirtied;
        s->progs[6].link = &obj->links.kprobe_account_page_dirtied;

        s->progs[7].name = "kprobe_folio_account_dirtied";
        s->progs[7].prog = &obj->progs.kprobe_folio_account_dirtied;
        s->progs[7].link = &obj->links.kprobe_folio_account_dirtied;

        s->progs[8].name = "kprobe_mark_buffer_dirty";
        s->progs[8].prog = &obj->progs.kprobe_mark_buffer_dirty;
        s->progs[8].link = &obj->links.kprobe_mark_buffer_dirty;

        s->progs[9].name = "tracepoint__writeback_dirty_folio";
        s->progs[9].prog = &obj->progs.tracepoint__writeback_dirty_folio;
        s->progs[9].link = &obj->links.tracepoint__writeback_dirty_folio;

        s->progs[10].name = "tracepoint__writeback_dirty_page";
        s->progs[10].prog = &obj->progs.tracepoint__writeback_dirty_page;
        s->progs[10].link = &obj->links.tracepoint__writeback_dirty_page;

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
	__u64 buffers, cached, mbd;
	struct cachestat_bpf *obj;
	__s64 total, misses, hits;
	struct tm *tm;
	float ratio;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

        obj = (struct cachestat_bpf *)calloc(1, sizeof(*obj));
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

	/**
	 * account_page_dirtied was renamed to folio_account_dirtied
	 * in kernel commit 203a31516616 ("mm/writeback: Add __folio_mark_dirty()")
	 */
	if (fentry_can_attach("folio_account_dirtied", NULL)) {
		err = bpf_program__set_attach_target(obj->progs.fentry_account_page_dirtied, 0,
						     "folio_account_dirtied");
		if (err) {
			fprintf(stderr, "failed to set attach target\n");
			goto cleanup;
		}
	}
	if (kprobe_exists("folio_account_dirtied")) {
		bpf_program__set_autoload(obj->progs.kprobe_account_page_dirtied, false);
		bpf_program__set_autoload(obj->progs.tracepoint__writeback_dirty_folio, false);
		bpf_program__set_autoload(obj->progs.tracepoint__writeback_dirty_page, false);
	} else if (kprobe_exists("account_page_dirtied")) {
		bpf_program__set_autoload(obj->progs.kprobe_folio_account_dirtied, false);
		bpf_program__set_autoload(obj->progs.tracepoint__writeback_dirty_folio, false);
		bpf_program__set_autoload(obj->progs.tracepoint__writeback_dirty_page, false);
	} else if (tracepoint_exists("writeback", "writeback_dirty_folio")) {
		bpf_program__set_autoload(obj->progs.kprobe_account_page_dirtied, false);
		bpf_program__set_autoload(obj->progs.kprobe_folio_account_dirtied, false);
		bpf_program__set_autoload(obj->progs.tracepoint__writeback_dirty_page, false);
	} else if (tracepoint_exists("writeback", "writeback_dirty_page")) {
		bpf_program__set_autoload(obj->progs.kprobe_account_page_dirtied, false);
		bpf_program__set_autoload(obj->progs.kprobe_folio_account_dirtied, false);
		bpf_program__set_autoload(obj->progs.tracepoint__writeback_dirty_folio, false);
	}

	/* It fallbacks to kprobes when kernel does not support fentry. */
	if (fentry_can_attach("folio_account_dirtied", NULL)
		|| fentry_can_attach("account_page_dirtied", NULL)) {
		bpf_program__set_autoload(obj->progs.kprobe_account_page_dirtied, false);
	} else {
		bpf_program__set_autoload(obj->progs.fentry_account_page_dirtied, false);
	}

	if (fentry_can_attach("add_to_page_cache_lru", NULL)) {
		bpf_program__set_autoload(obj->progs.kprobe_add_to_page_cache_lru, false);
	} else {
		bpf_program__set_autoload(obj->progs.fentry_add_to_page_cache_lru, false);
	}

	if (fentry_can_attach("mark_page_accessed", NULL)) {
		bpf_program__set_autoload(obj->progs.kprobe_mark_page_accessed, false);
	} else {
		bpf_program__set_autoload(obj->progs.fentry_mark_page_accessed, false);
	}

	if (fentry_can_attach("mark_buffer_dirty", NULL)) {
		bpf_program__set_autoload(obj->progs.kprobe_mark_buffer_dirty, false);
	} else {
		bpf_program__set_autoload(obj->progs.fentry_mark_buffer_dirty, false);
	}

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to load BPF object\n");
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

	if (env.timestamp)
		printf("%-8s ", "TIME");
	printf("%8s %8s %8s %8s %12s %10s\n", "HITS", "MISSES", "DIRTIES",
		"HITRATIO", "BUFFERS_MB", "CACHED_MB");

	while (1) {
		sleep(env.interval);

		/* total = total cache accesses without counting dirties */
		total = __atomic_exchange_n(&obj->bss->total, 0, __ATOMIC_RELAXED);
		/* misses = total of add to lru because of read misses */
		misses = __atomic_exchange_n(&obj->bss->misses, 0, __ATOMIC_RELAXED);
		/* mbd = total of mark_buffer_dirty events */
		mbd = __atomic_exchange_n(&obj->bss->mbd, 0, __ATOMIC_RELAXED);

		if (total < 0)
			total = 0;
		if (misses < 0)
			misses = 0;
		hits = total - misses;
		/*
		 * If hits are < 0, then its possible misses are overestimated
		 * due to possibly page cache read ahead adding more pages than
		 * needed. In this case just assume misses as total and reset
		 * hits.
		 */
		if (hits < 0) {
			misses = total;
			hits = 0;
		}
		ratio = total > 0 ? hits * 1.0 / total : 0.0;
		err = get_meminfo(&buffers, &cached);
		if (err) {
			fprintf(stderr, "failed to get meminfo: %d\n", err);
			goto cleanup;
		}
		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s ", ts);
		}
		printf("%8lld %8lld %8llu %7.2f%% %12llu %10llu\n",
			hits, misses, mbd, 100 * ratio,
			buffers / 1024, cached / 1024);

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	bpf_object__destroy_skeleton(obj->skeleton);
	return err != 0;
}
