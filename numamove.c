// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on numamove(8) from BPF-Perf-Tools-Book by Brendan Gregg.
//  8-Jun-2020   Wenbo Zhang   Created this.
// 30-Jan-2023   Rong Tao      Use fentry_can_attach() to decide use fentry/kprobe.
// 06-Apr-2024   Rong Tao      Support migrate_misplaced_folio()
#include <argp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "numamove.skel.h"
#include "trace_helpers.h"

static struct env {
	bool verbose;
} env;

struct numamove_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *start;
                struct bpf_map *bss;
        } maps;
        struct {
                struct bpf_program *fentry_migrate_misplaced_page;
                struct bpf_program *fentry_migrate_misplaced_folio;
                struct bpf_program *kprobe_migrate_misplaced_page;
                struct bpf_program *kprobe_migrate_misplaced_folio;
                struct bpf_program *fexit_migrate_misplaced_page_exit;
                struct bpf_program *fexit_migrate_misplaced_folio_exit;
                struct bpf_program *kretprobe_migrate_misplaced_page_exit;
                struct bpf_program *kretprobe_migrate_misplaced_folio_exit;
        } progs;
        struct {
                struct bpf_link *fentry_migrate_misplaced_page;
                struct bpf_link *fentry_migrate_misplaced_folio;
                struct bpf_link *kprobe_migrate_misplaced_page;
                struct bpf_link *kprobe_migrate_misplaced_folio;
                struct bpf_link *fexit_migrate_misplaced_page_exit;
                struct bpf_link *fexit_migrate_misplaced_folio_exit;
                struct bpf_link *kretprobe_migrate_misplaced_page_exit;
                struct bpf_link *kretprobe_migrate_misplaced_folio_exit;
        } links;
        struct numamove_bpf__bss {
                __u64 latency;
                __u64 num;
        } *bss;
};

static volatile bool exiting;

const char *argp_program_version = "numamove 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show page migrations of type NUMA misplaced per second.\n"
"\n"
"USAGE: numamove [--help]\n"
"\n"
"EXAMPLES:\n"
"    numamove              # Show page migrations' count and latency";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
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

static inline int
bpf_object__create_skeleton(struct numamove_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "numamove_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 2;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "start";
        s->maps[0].map = &obj->maps.start;

        s->maps[1].name = "numamove.bss";
        s->maps[1].map = &obj->maps.bss;
        s->maps[1].mmaped = (void **)&obj->bss;

        /* programs */
        s->prog_cnt = 8;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "fentry_migrate_misplaced_page";
        s->progs[0].prog = &obj->progs.fentry_migrate_misplaced_page;
        s->progs[0].link = &obj->links.fentry_migrate_misplaced_page;

        s->progs[1].name = "fentry_migrate_misplaced_folio";
        s->progs[1].prog = &obj->progs.fentry_migrate_misplaced_folio;
        s->progs[1].link = &obj->links.fentry_migrate_misplaced_folio;

        s->progs[2].name = "kprobe_migrate_misplaced_page";
        s->progs[2].prog = &obj->progs.kprobe_migrate_misplaced_page;
        s->progs[2].link = &obj->links.kprobe_migrate_misplaced_page;

        s->progs[3].name = "kprobe_migrate_misplaced_folio";
        s->progs[3].prog = &obj->progs.kprobe_migrate_misplaced_folio;
        s->progs[3].link = &obj->links.kprobe_migrate_misplaced_folio;

        s->progs[4].name = "fexit_migrate_misplaced_page_exit";
        s->progs[4].prog = &obj->progs.fexit_migrate_misplaced_page_exit;
        s->progs[4].link = &obj->links.fexit_migrate_misplaced_page_exit;

        s->progs[5].name = "fexit_migrate_misplaced_folio_exit";
        s->progs[5].prog = &obj->progs.fexit_migrate_misplaced_folio_exit;
        s->progs[5].link = &obj->links.fexit_migrate_misplaced_folio_exit;

        s->progs[6].name = "kretprobe_migrate_misplaced_page_exit";
        s->progs[6].prog = &obj->progs.kretprobe_migrate_misplaced_page_exit;
        s->progs[6].link = &obj->links.kretprobe_migrate_misplaced_page_exit;

        s->progs[7].name = "kretprobe_migrate_misplaced_folio_exit";
        s->progs[7].prog = &obj->progs.kretprobe_migrate_misplaced_folio_exit;
        s->progs[7].link = &obj->links.kretprobe_migrate_misplaced_folio_exit;

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
	struct numamove_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;
	bool use_folio, use_fentry;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

        obj = (struct numamove_bpf *)calloc(1, sizeof(*obj));
        if (!obj) { 
                errno = ENOMEM; 
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, NULL);
	if (err) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	if (!obj->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	/* It fallbacks to kprobes when kernel does not support fentry. */
	if (fentry_can_attach("migrate_misplaced_folio", NULL)) {
		use_fentry = true;
		use_folio = true;
	} else if (kprobe_exists("migrate_misplaced_folio")) {
		use_fentry = false;
		use_folio = true;
	} else if (fentry_can_attach("migrate_misplaced_page", NULL)) {
		use_fentry = true;
		use_folio = false;
	} else if (kprobe_exists("migrate_misplaced_page")) {
		use_fentry = false;
		use_folio = false;
	} else {
		fprintf(stderr, "can't found any fentry/kprobe of migrate misplaced folio/page\n");
		return 1;
	}

	bpf_program__set_autoload(obj->progs.fentry_migrate_misplaced_folio, (use_fentry && use_folio));
	bpf_program__set_autoload(obj->progs.fexit_migrate_misplaced_folio_exit, (use_fentry && use_folio));
	bpf_program__set_autoload(obj->progs.kprobe_migrate_misplaced_folio, (!use_fentry && use_folio));
	bpf_program__set_autoload(obj->progs.kretprobe_migrate_misplaced_folio_exit, (!use_fentry && use_folio));

	bpf_program__set_autoload(obj->progs.fentry_migrate_misplaced_page, (use_fentry && !use_folio));
	bpf_program__set_autoload(obj->progs.fexit_migrate_misplaced_page_exit, (use_fentry && !use_folio));
	bpf_program__set_autoload(obj->progs.kprobe_migrate_misplaced_page, (!use_fentry && !use_folio));
	bpf_program__set_autoload(obj->progs.kretprobe_migrate_misplaced_page_exit, (!use_fentry && !use_folio));

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	err = bpf_object__attach_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("%-10s %18s %18s\n", "TIME", "NUMA_migrations", "NUMA_migrations_ms");
	while (!exiting) {
		sleep(1);
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-10s %18lld %18lld\n", ts,
			__atomic_exchange_n(&obj->bss->num, 0, __ATOMIC_RELAXED),
			__atomic_exchange_n(&obj->bss->latency, 0, __ATOMIC_RELAXED));
	}

cleanup:
	bpf_object__destroy_skeleton(obj->skeleton);
	return err != 0;
}
