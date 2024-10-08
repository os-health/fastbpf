// SPDX-License-Identifier: GPL-2.0

/*
 * tcplife      Trace the lifespan of TCP sessions and summarize.
 *
 * Copyright (c) 2022 Hengqi Chen
 *
 * Based on tcplife(8) from BCC by Brendan Gregg.
 * 02-Jun-2022   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>

#include "btf_helpers.h"
#include "tcplife.h"
#include "tcplife.skel.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

struct tcplife_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *birth;
                struct bpf_map *idents;
                struct bpf_map *events;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *inet_sock_set_state;
        } progs;
        struct {
                struct bpf_link *inet_sock_set_state;
        } links;
        struct tcplife_bpf__rodata {
                bool filter_sport;
                bool filter_dport;
                __u16 target_sports[1024];
                __u16 target_dports[1024];
                pid_t target_pid;
                __u16 target_family;
        } *rodata;
};

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static short target_family = 0;
static char *target_sports = NULL;
static char *target_dports = NULL;
static int column_width = 15;
static bool emit_timestamp = false;
static bool verbose = false;

const char *argp_program_version = "tcplife 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace the lifespan of TCP sessions and summarize.\n"
"\n"
"USAGE: tcplife [-h] [-p PID] [-4] [-6] [-L] [-D] [-T] [-w]\n"
"\n"
"EXAMPLES:\n"
"    tcplife -p 1215             # only trace PID 1215\n"
"    tcplife -p 1215 -4          # trace IPv4 only\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 only", 0 },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 only", 0 },
	{ "wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)", 0 },
	{ "time", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "localport", 'L', "LOCALPORT", 0, "Comma-separated list of local ports to trace.", 0 },
	{ "remoteport", 'D', "REMOTEPORT", 0, "Comma-separated list of remote ports to trace.", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long n;

	switch (key) {
	case 'p':
		errno = 0;
		n = strtol(arg, NULL, 10);
		if (errno || n <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = n;
		break;
	case '4':
		target_family = AF_INET;
		break;
	case '6':
		target_family = AF_INET6;
		break;
	case 'w':
		column_width = 39;
		break;
	case 'L':
		target_sports = strdup(arg);
		break;
	case 'D':
		target_dports = strdup(arg);
		break;
	case 'T':
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
	char ts[32], saddr[48], daddr[48];
	struct event e;
	struct tm *tm;
	time_t t;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%8s ", ts);
	}

	inet_ntop(e.family, &e.saddr, saddr, sizeof(saddr));
	inet_ntop(e.family, &e.daddr, daddr, sizeof(daddr));

	printf("%-7d %-16s %-*s %-5d %-*s %-5d %-6.2f %-6.2f %-.2f\n",
	       e.pid, e.comm, column_width, saddr, e.sport, column_width, daddr, e.dport,
	       (double)e.tx_b / 1024, (double)e.rx_b / 1024, (double)e.span_us / 1000);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static inline int
bpf_object__create_skeleton(struct tcplife_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "tcplife_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 4;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "birth";
        s->maps[0].map = &obj->maps.birth;

        s->maps[1].name = "idents";
        s->maps[1].map = &obj->maps.idents;

        s->maps[2].name = "events";
        s->maps[2].map = &obj->maps.events;

        s->maps[3].name = "tcplife_.rodata";
        s->maps[3].map = &obj->maps.rodata;
        s->maps[3].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 1;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "inet_sock_set_state";
        s->progs[0].prog = &obj->progs.inet_sock_set_state;
        s->progs[0].link = &obj->links.inet_sock_set_state;

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
	struct tcplife_bpf *obj;
	struct perf_buffer *pb = NULL;
	short port_num;
	char *port;
	int err, i;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

        obj = (struct tcplife_bpf *)calloc(1, sizeof(*obj));
        if (!obj) {
                errno = ENOMEM;
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, &open_opts);
	if (err) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->target_family = target_family;

	if (target_sports) {
		i = 0;
		port = strtok(target_sports, ",");
		while (port && i < MAX_PORTS) {
			port_num = strtol(port, NULL, 10);
			obj->rodata->target_sports[i++] = port_num;
			port = strtok(NULL, ",");
		}
		obj->rodata->filter_sport = true;
	}

	if (target_dports) {
		i = 0;
		port = strtok(target_dports, ",");
		while (port && i < MAX_PORTS) {
			port_num = strtol(port, NULL, 10);
			obj->rodata->target_dports[i++] = port_num;
			port = strtok(NULL, ",");
		}
		obj->rodata->filter_dport = true;
	}

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_object__attach_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to attach BPF object: %d\n", err);
		goto cleanup;
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

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-16s %-*s %-5s %-*s %-5s %-6s %-6s %-s\n",
	       "PID", "COMM", column_width, "LADDR", "LPORT", column_width, "RADDR", "RPORT",
	       "TX_KB", "RX_KB", "MS");

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
