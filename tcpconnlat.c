// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on tcpconnlat(8) from BCC by Brendan Gregg.
// 11-Jul-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcpconnlat.h"
#include "tcpconnlat.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static struct env {
	__u64 min_us;
	pid_t pid;
	bool timestamp;
	bool lport;
	bool verbose;
} env;

struct object_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *start;
                struct bpf_map *events;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *tcp_v4_connect;
                struct bpf_program *tcp_v6_connect;
                struct bpf_program *tcp_rcv_state_process;
                struct bpf_program *tcp_destroy_sock;
                struct bpf_program *fentry_tcp_v4_connect;
                struct bpf_program *fentry_tcp_v6_connect;
                struct bpf_program *fentry_tcp_rcv_state_process;
        } progs;
        struct {
                struct bpf_link *tcp_v4_connect;
                struct bpf_link *tcp_v6_connect;
                struct bpf_link *tcp_rcv_state_process;
                struct bpf_link *tcp_destroy_sock;
                struct bpf_link *fentry_tcp_v4_connect;
                struct bpf_link *fentry_tcp_v6_connect;
                struct bpf_link *fentry_tcp_rcv_state_process;
        } links;
        struct tcpconnlat_bpf__rodata {
                __u64 targ_min_us;
                pid_t targ_tgid;
        } *rodata;
}; 

const char *argp_program_version = "tcpconnlat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"\nTrace TCP connects and show connection latency.\n"
"\n"
"USAGE: tcpconnlat [--help] [-t] [-p PID] [-L]\n"
"\n"
"EXAMPLES:\n"
"    tcpconnlat              # summarize on-CPU time as a histogram\n"
"    tcpconnlat 1            # trace connection latency slower than 1 ms\n"
"    tcpconnlat 0.1          # trace connection latency slower than 100 us\n"
"    tcpconnlat -t           # 1s summaries, milliseconds, and timestamps\n"
"    tcpconnlat -p 185       # trace PID 185 only\n"
"    tcpconnlat -L           # include LPORT while printing outputs\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "lport", 'L', NULL, 0, "Include LPORT on output", 0 },
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
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'L':
		env.lport = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.min_us = strtod(arg, NULL) * 1000;
		if (errno || env.min_us <= 0) {
			fprintf(stderr, "Invalid delay (in us): %s\n", arg);
			argp_usage(state);
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

static void sig_int(int signo)
{
	exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;
	static __u64 start_ts;

	if (env.timestamp) {
		if (start_ts == 0)
			start_ts = e->ts_us;
		printf("%-9.3f ", (e->ts_us - start_ts) / 1000000.0);
	}
	if (e->af == AF_INET) {
		s.x4.s_addr = e->saddr_v4;
		d.x4.s_addr = e->daddr_v4;
	} else if (e->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		fprintf(stderr, "broken event: event->af=%d", e->af);
		return;
	}

	if (env.lport) {
		printf("%-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %.2f\n", e->tgid, e->comm,
			e->af == AF_INET ? 4 : 6, inet_ntop(e->af, &s, src, sizeof(src)), e->lport,
			inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
			e->delta_us / 1000.0);
	} else {
		printf("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f\n", e->tgid, e->comm,
			e->af == AF_INET ? 4 : 6, inet_ntop(e->af, &s, src, sizeof(src)),
			inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
			e->delta_us / 1000.0);
	}
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
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
        s->name = "tcpconnlat_bpf";
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

        s->maps[2].name = "tcpconnl.rodata";
        s->maps[2].map = &obj->maps.rodata;
        s->maps[2].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 7;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }
        s->progs[0].name = "tcp_v4_connect";
        s->progs[0].prog = &obj->progs.tcp_v4_connect;
        s->progs[0].link = &obj->links.tcp_v4_connect;

        s->progs[1].name = "tcp_v6_connect";
        s->progs[1].prog = &obj->progs.tcp_v6_connect;
        s->progs[1].link = &obj->links.tcp_v6_connect;

        s->progs[2].name = "tcp_rcv_state_process";
        s->progs[2].prog = &obj->progs.tcp_rcv_state_process;
        s->progs[2].link = &obj->links.tcp_rcv_state_process;

        s->progs[3].name = "tcp_destroy_sock";
        s->progs[3].prog = &obj->progs.tcp_destroy_sock;
        s->progs[3].link = &obj->links.tcp_destroy_sock;

        s->progs[4].name = "fentry_tcp_v4_connect";
        s->progs[4].prog = &obj->progs.fentry_tcp_v4_connect;
        s->progs[4].link = &obj->links.fentry_tcp_v4_connect;

        s->progs[5].name = "fentry_tcp_v6_connect";
        s->progs[5].prog = &obj->progs.fentry_tcp_v6_connect;
        s->progs[5].link = &obj->links.fentry_tcp_v6_connect;

        s->progs[6].name = "fentry_tcp_rcv_state_process";
        s->progs[6].prog = &obj->progs.fentry_tcp_rcv_state_process;
        s->progs[6].link = &obj->links.fentry_tcp_rcv_state_process;

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
	struct object_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

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

	/* initialize global data (filtering options) */
	obj->rodata->targ_min_us = env.min_us;
	obj->rodata->targ_tgid = env.pid;

	if (fentry_can_attach("tcp_v4_connect", NULL)) {
		bpf_program__set_attach_target(obj->progs.fentry_tcp_v4_connect, 0, "tcp_v4_connect");
		bpf_program__set_attach_target(obj->progs.fentry_tcp_v6_connect, 0, "tcp_v6_connect");
		bpf_program__set_attach_target(obj->progs.fentry_tcp_rcv_state_process, 0, "tcp_rcv_state_process");
		bpf_program__set_autoload(obj->progs.tcp_v4_connect, false);
		bpf_program__set_autoload(obj->progs.tcp_v6_connect, false);
		bpf_program__set_autoload(obj->progs.tcp_rcv_state_process, false);
	} else {
		bpf_program__set_autoload(obj->progs.fentry_tcp_v4_connect, false);
		bpf_program__set_autoload(obj->progs.fentry_tcp_v6_connect, false);
		bpf_program__set_autoload(obj->progs.fentry_tcp_rcv_state_process, false);
	}

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_object__attach_skeleton(obj->skeleton);
	if (err) {
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		fprintf(stderr, "failed to open perf buffer: %d\n", errno);
		goto cleanup;
	}

	/* print header */
	if (env.timestamp)
		printf("%-9s ", ("TIME(s)"));
	if (env.lport) {
		printf("%-6s %-12s %-2s %-16s %-6s %-16s %-5s %s\n",
			"PID", "COMM", "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)");
	} else {
		printf("%-6s %-12s %-2s %-16s %-16s %-5s %s\n",
			"PID", "COMM", "IP", "SADDR", "DADDR", "DPORT", "LAT(ms)");
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
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
