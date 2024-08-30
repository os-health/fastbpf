// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * tcpstates    Trace TCP session state changes with durations.
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on tcpstates(8) from BCC by Brendan Gregg.
 * 18-Dec-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "btf_helpers.h"
#include "tcpstates.h"
#include "tcpstates.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static short target_family = 0;
static char *target_sports = NULL;
static char *target_dports = NULL;
static bool wide_output = false;
static bool verbose = false;
static const char *tcp_states[] = {
	[1] = "ESTABLISHED",
	[2] = "SYN_SENT",
	[3] = "SYN_RECV",
	[4] = "FIN_WAIT1",
	[5] = "FIN_WAIT2",
	[6] = "TIME_WAIT",
	[7] = "CLOSE",
	[8] = "CLOSE_WAIT",
	[9] = "LAST_ACK",
	[10] = "LISTEN",
	[11] = "CLOSING",
	[12] = "NEW_SYN_RECV",
	[13] = "UNKNOWN",
};

struct object_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *sports;
                struct bpf_map *dports;
                struct bpf_map *timestamps;
                struct bpf_map *events;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *handle_set_state;
        } progs;
        struct {
                struct bpf_link *handle_set_state;
        } links;
        struct tcpstates_bpf__rodata {
                bool filter_by_sport;
                bool filter_by_dport;
                short target_family;
        } *rodata;
};

const char *argp_program_version = "tcpstates 1.0";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace TCP session state changes and durations.\n"
"\n"
"USAGE: tcpstates [-4] [-6] [-T] [-L lport] [-D dport]\n"
"\n"
"EXAMPLES:\n"
"    tcpstates                  # trace all TCP state changes\n"
"    tcpstates -T               # include timestamps\n"
"    tcpstates -L 80            # only trace local port 80\n"
"    tcpstates -D 80            # only trace remote port 80\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 family only", 0 },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 family only", 0 },
	{ "wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)", 0 },
	{ "localport", 'L', "LPORT", 0, "Comma-separated list of local ports to trace.", 0 },
	{ "remoteport", 'D', "DPORT", 0, "Comma-separated list of remote ports to trace.", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long port_num;
	char *port;

	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'T':
		emit_timestamp = true;
		break;
	case '4':
		target_family = AF_INET;
		break;
	case '6':
		target_family = AF_INET6;
		break;
	case 'w':
		wide_output = true;
		break;
	case 'L':
		if (!arg) {
			warn("No ports specified\n");
			argp_usage(state);
		}
		target_sports = strdup(arg);
		port = strtok(arg, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			if (errno || port_num <= 0 || port_num > 65536) {
				warn("Invalid ports: %s\n", arg);
				argp_usage(state);
			}
			port = strtok(NULL, ",");
		}
		break;
	case 'D':
		if (!arg) {
			warn("No ports specified\n");
			argp_usage(state);
		}
		target_dports = strdup(arg);
		port = strtok(arg, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			if (errno || port_num <= 0 || port_num > 65536) {
				warn("Invalid ports: %s\n", arg);
				argp_usage(state);
			}
			port = strtok(NULL, ",");
		}
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
	char ts[32], saddr[39], daddr[39];
	struct event e;
	struct tm *tm;
	int family;
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
	if (wide_output) {
		family = e.family == AF_INET ? 4 : 6;
		printf("%-16llx %-7d %-16s %-2d %-39s %-5d %-39s %-5d %-11s -> %-11s %.3f\n",
		       e.skaddr, e.pid, e.task, family, saddr, e.sport, daddr, e.dport,
		       tcp_states[e.oldstate], tcp_states[e.newstate], (double)e.delta_us / 1000);
	} else {
		printf("%-16llx %-7d %-10.10s %-15s %-5d %-15s %-5d %-11s -> %-11s %.3f\n",
		       e.skaddr, e.pid, e.task, saddr, e.sport, daddr, e.dport,
		       tcp_states[e.oldstate], tcp_states[e.newstate], (double)e.delta_us / 1000);
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
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
        s->name = "tcpstates_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 5;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "sports";
        s->maps[0].map = &obj->maps.sports;

        s->maps[1].name = "dports";
        s->maps[1].map = &obj->maps.dports;

        s->maps[2].name = "timestamps";
        s->maps[2].map = &obj->maps.timestamps;

        s->maps[3].name = "events";
        s->maps[3].map = &obj->maps.events;

        s->maps[4].name = "tcpstate.rodata";
        s->maps[4].map = &obj->maps.rodata;
        s->maps[4].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 1;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "handle_set_state";
        s->progs[0].prog = &obj->progs.handle_set_state;
        s->progs[0].link = &obj->links.handle_set_state;

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
	struct object_bpf *obj;
	int err, port_map_fd;
	short port_num;
	char *port;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

        obj = (struct object_bpf *)calloc(1, sizeof(*obj));
        if (!obj) {
                errno = ENOMEM;
                goto cleanup;
        }

        err = bpf_object__create_skeleton(obj, obj_buf, obj_buf_sz);
        if (err)
                goto cleanup;

        err = bpf_object__open_skeleton(obj->skeleton, &open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->filter_by_sport = target_sports != NULL;
	obj->rodata->filter_by_dport = target_dports != NULL;
	obj->rodata->target_family = target_family;

	err = bpf_object__load_skeleton(obj->skeleton);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (target_sports) {
		port_map_fd = bpf_map__fd(obj->maps.sports);
		port = strtok(target_sports, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}
	if (target_dports) {
		port_map_fd = bpf_map__fd(obj->maps.dports);
		port = strtok(target_dports, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}

	err = bpf_object__attach_skeleton(obj->skeleton);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = - errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	if (wide_output)
		printf("%-16s %-7s %-16s %-2s %-39s %-5s %-39s %-5s %-11s -> %-11s %s\n",
		       "SKADDR", "PID", "COMM", "IP", "LADDR", "LPORT",
		       "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS");
	else
		printf("%-16s %-7s %-10s %-15s %-5s %-15s %-5s %-11s -> %-11s %s\n",
		       "SKADDR", "PID", "COMM", "LADDR", "LPORT",
		       "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
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
