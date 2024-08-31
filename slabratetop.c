/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * slabratetop Trace slab kmem_cache_alloc by process.
 * Copyright (c) 2022 Rong Tao
 *
 * Based on slabratetop(8) from BCC by Brendan Gregg.
 * 07-Jan-2022   Rong Tao   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "slabratetop.h"
#include "slabratetop.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

enum SORT_BY {
	SORT_BY_CACHE_NAME,
	SORT_BY_CACHE_COUNT,
	SORT_BY_CACHE_SIZE,
};

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool clear_screen = true;
static int output_rows = 20;
static int sort_by = SORT_BY_CACHE_SIZE;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "slabratetop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace slab kmem cache alloc by process.\n"
"\n"
"USAGE: slabratetop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    slabratetop            # slab rate top, refresh every 1s\n"
"    slabratetop -p 181     # only trace PID 181\n"
"    slabratetop -s count   # sort columns by count\n"
"    slabratetop -r 100     # print 100 rows\n"
"    slabratetop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen", 0 },
	{ "sort", 's', "SORT", 0, "Sort columns, default size [name, count, size]", 0 },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

struct slabratetop_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *slab_entries;
                struct bpf_map *rodata;
                struct bpf_map *bss;
        } maps;
        struct {
                struct bpf_program *kmem_cache_alloc;
        } progs;
        struct {
                struct bpf_link *kmem_cache_alloc;
        } links;
        struct slabratetop_bpf__rodata {
                pid_t target_pid;
        } *rodata;
        struct slabratetop_bpf__bss {
        } *bss;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, rows;
	static int pos_args;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'C':
		clear_screen = false;
		break;
	case 's':
		if (!strcmp(arg, "name")) {
			sort_by = SORT_BY_CACHE_NAME;
		} else if (!strcmp(arg, "count")) {
			sort_by = SORT_BY_CACHE_COUNT;
		} else if (!strcmp(arg, "size")) {
			sort_by = SORT_BY_CACHE_SIZE;
		} else {
			warn("invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		rows = strtol(arg, NULL, 10);
		if (errno || rows <= 0) {
			warn("invalid rows: %s\n", arg);
			argp_usage(state);
		}
		output_rows = rows;
		if (output_rows > OUTPUT_ROWS_LIMIT)
			output_rows = OUTPUT_ROWS_LIMIT;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0) {
				warn("invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			count = strtol(arg, NULL, 10);
			if (errno || count <= 0) {
				warn("invalid count\n");
				argp_usage(state);
			}
		} else {
			warn("unrecognized positional argument: %s\n", arg);
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
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int sort_column(const void *obj1, const void *obj2)
{
	struct slabrate_info *s1 = (struct slabrate_info *)obj1;
	struct slabrate_info *s2 = (struct slabrate_info *)obj2;

	if (sort_by == SORT_BY_CACHE_NAME) {
		return strcasecmp(s1->name, s2->name);
	} else if (sort_by == SORT_BY_CACHE_COUNT) {
		return s2->count - s1->count;
	} else if (sort_by == SORT_BY_CACHE_SIZE) {
		return s2->size - s1->size;
	} else {
		return s2->size - s1->size;
	}
}

static int print_stat(struct slabratetop_bpf *obj)
{
	FILE *f;
	time_t t;
	struct tm *tm;
	char ts[16], buf[256];
	char *key, **prev_key = NULL;
	static struct slabrate_info values[OUTPUT_ROWS_LIMIT];
	int n, i, err = 0, rows = 0;
	int fd = bpf_map__fd(obj->maps.slab_entries);

	f = fopen("/proc/loadavg", "r");
	if (f) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		memset(buf, 0 , sizeof(buf));
		n = fread(buf, 1, sizeof(buf), f);
		if (n)
			printf("%8s loadavg: %s\n", ts, buf);
		fclose(f);
	}

	printf("%-32s %6s %10s\n", "CACHE", "ALLOCS", "BYTES");

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}

	qsort(values, rows, sizeof(struct slabrate_info), sort_column);
	rows = rows < output_rows ? rows : output_rows;
	for (i = 0; i < rows; i++)
		printf("%-32s %6lld %10lld\n",
		       values[i].name, values[i].count, values[i].size);

	printf("\n");
	prev_key = NULL;

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_delete_elem(fd, &key);
		if (err) {
			warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}
	return err;
}

static inline int
bpf_object__create_skeleton(struct slabratetop_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "slabratetop_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 3;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "slab_entries";
        s->maps[0].map = &obj->maps.slab_entries;

        s->maps[1].name = "slabrate.rodata";
        s->maps[1].map = &obj->maps.rodata;
        s->maps[1].mmaped = (void **)&obj->rodata;

        s->maps[2].name = "slabrate.bss";
        s->maps[2].map = &obj->maps.bss;
        s->maps[2].mmaped = (void **)&obj->bss;

        /* programs */
        s->prog_cnt = 1;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "kmem_cache_alloc";
        s->progs[0].prog = &obj->progs.kmem_cache_alloc;
        s->progs[0].link = &obj->links.kmem_cache_alloc;

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
	struct slabratetop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

        obj = (struct slabratetop_bpf *)calloc(1, sizeof(*obj));
        if (!obj) { 
                errno = ENOMEM; 
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, NULL);
	if (err) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;

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

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj);
		if (err)
			goto cleanup;

		count--;
		if (exiting || !count)
			goto cleanup;
	}

cleanup:
	bpf_object__destroy_skeleton(obj->skeleton);

	return err != 0;
}
