/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * solisten  Trace IPv4 and IPv6 listen syscalls
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on solisten(8) from BCC by Jean-Tiare Le Bigot
 * 31-May-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "solisten.h"
#include "solisten.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool emit_timestamp = false;
static bool verbose = false;

const char *argp_program_version = "solisten 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace IPv4 and IPv6 listen syscalls.\n"
"\n"
"USAGE: solisten [-h] [-t] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    solisten           # trace listen syscalls\n"
"    solisten -t        # output with timestamp\n"
"    solisten -p 1216   # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

struct solisten_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *values;
                struct bpf_map *events;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *inet_listen_entry;
                struct bpf_program *inet_listen_exit;
                struct bpf_program *inet_listen_fexit;
        } progs;
        struct {
                struct bpf_link *inet_listen_entry;
                struct bpf_link *inet_listen_exit;
                struct bpf_link *inet_listen_fexit;
        } links;
        struct solisten_bpf__rodata {
                pid_t target_pid;
        } *rodata;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 't':
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
	const struct event *e = data;
	time_t t;
	struct tm *tm;
	char ts[32], proto[16], addr[48] = {};
	__u16 family = e->proto >> 16;
	__u16 type = (__u16)e->proto;
	const char *prot;

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%8s ", ts);
	}

	if (type == SOCK_STREAM)
		prot = "TCP";
	else if (type == SOCK_DGRAM)
		prot = "UDP";
	else
		prot = "UNK";
	if (family == AF_INET)
		snprintf(proto, sizeof(proto), "%sv4", prot);
	else /* family == AF_INET6 */
		snprintf(proto, sizeof(proto), "%sv6", prot);
	inet_ntop(family, e->addr, addr, sizeof(addr));
	printf("%-7d %-16s %-3d %-7d %-5s %-5d %-32s\n",
	       e->pid, e->task, e->ret, e->backlog, proto, e->port, addr);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static inline int
bpf_object__create_skeleton(struct solisten_bpf *obj, char * obj_buf, size_t obj_buf_sz)
{
        struct bpf_object_skeleton *s;
        int err;

        s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
        if (!s) {
                err = -ENOMEM;
                goto err;
        }

        s->sz = sizeof(*s);
        s->name = "solisten_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 3;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "values";
        s->maps[0].map = &obj->maps.values;

        s->maps[1].name = "events";
        s->maps[1].map = &obj->maps.events;

        s->maps[2].name = "solisten.rodata";
        s->maps[2].map = &obj->maps.rodata;
        s->maps[2].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 3;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "inet_listen_entry";
        s->progs[0].prog = &obj->progs.inet_listen_entry;
        s->progs[0].link = &obj->links.inet_listen_entry;

        s->progs[1].name = "inet_listen_exit";
        s->progs[1].prog = &obj->progs.inet_listen_exit;
        s->progs[1].link = &obj->links.inet_listen_exit;

        s->progs[2].name = "inet_listen_fexit";
        s->progs[2].prog = &obj->progs.inet_listen_fexit;
        s->progs[2].link = &obj->links.inet_listen_fexit;

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
	struct solisten_bpf *obj;
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

        obj = (struct solisten_bpf *)calloc(1, sizeof(*obj));
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

	if (fentry_can_attach("inet_listen", NULL)) {
		bpf_program__set_autoload(obj->progs.inet_listen_entry, false);
		bpf_program__set_autoload(obj->progs.inet_listen_exit, false);
	} else {
		bpf_program__set_autoload(obj->progs.inet_listen_fexit, false);
	}

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

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
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
	printf("%-7s %-16s %-3s %-7s %-5s %-5s %-32s\n",
	       "PID", "COMM", "RET", "BACKLOG", "PROTO", "PORT", "ADDR");

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
