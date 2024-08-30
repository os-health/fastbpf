// Based on execsnoop(8) from BCC by Brendan Gregg and others.
//
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "execsnoop.h"
#include "execsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES   64
#define PERF_POLL_TIMEOUT_MS	100
#define MAX_ARGS_KEY 259

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool time;
	bool timestamp;
	bool fails;
	uid_t uid;
	bool quote;
	const char *name;
	const char *line;
	bool print_uid;
	bool verbose;
	int max_args;
	char *cgroupspath;
	bool cg;
} env = {
	.max_args = DEFAULT_MAXARGS,
	.uid = INVALID_UID
};

struct object_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
                struct bpf_map *cgroup_map;
                struct bpf_map *execs;
                struct bpf_map *events;
                struct bpf_map *rodata;
        } maps;
        struct {
                struct bpf_program *tracepoint__syscalls__sys_enter_execve;
                struct bpf_program *tracepoint__syscalls__sys_exit_execve;
        } progs;
        struct {
                struct bpf_link *tracepoint__syscalls__sys_enter_execve;
                struct bpf_link *tracepoint__syscalls__sys_exit_execve;
        } links;
        struct execsnoop_bpf__rodata {
                bool filter_cg;
                bool ignore_failed;
                uid_t targ_uid;
                int max_args;
        } *rodata;
};

static struct timespec start_time;

const char *argp_program_version = "execsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace exec syscalls\n"
"\n"
"USAGE: execsnoop [-h] [-T] [-t] [-x] [-u UID] [-q] [-n NAME] [-l LINE] [-U] [-c CG]\n"
"                 [--max-args MAX_ARGS]\n"
"\n"
"EXAMPLES:\n"
"   ./execsnoop           # trace all exec() syscalls\n"
"   ./execsnoop -x        # include failed exec()s\n"
"   ./execsnoop -T        # include time (HH:MM:SS)\n"
"   ./execsnoop -U        # include UID\n"
"   ./execsnoop -u 1000   # only trace UID 1000\n"
"   ./execsnoop -t        # include timestamps\n"
"   ./execsnoop -q        # add \"quotemarks\" around arguments\n"
"   ./execsnoop -n main   # only print command lines containing \"main\"\n"
"   ./execsnoop -l tpkg   # only print command where arguments contains \"tpkg\""
"   ./execsnoop -c CG     # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "time", 'T', NULL, 0, "include time column on output (HH:MM:SS)", 0 },
	{ "timestamp", 't', NULL, 0, "include timestamp on output", 0 },
	{ "fails", 'x', NULL, 0, "include failed exec()s", 0 },
	{ "uid", 'u', "UID", 0, "trace this UID only", 0 },
	{ "quote", 'q', NULL, 0, "Add quotemarks (\") around arguments", 0 },
	{ "name", 'n', "NAME", 0, "only print commands matching this name, any arg", 0 },
	{ "line", 'l', "LINE", 0, "only print commands where arg contains this line", 0 },
	{ "print-uid", 'U', NULL, 0, "print UID column", 0 },
	{ "max-args", MAX_ARGS_KEY, "MAX_ARGS", 0,
		"maximum number of arguments parsed and displayed, defaults to 20", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long int uid, max_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'T':
		env.time = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'x':
		env.fails = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'u':
		errno = 0;
		uid = strtol(arg, NULL, 10);
		if (errno || uid < 0 || uid >= INVALID_UID) {
			fprintf(stderr, "Invalid UID %s\n", arg);
			argp_usage(state);
		}
		env.uid = uid;
		break;
	case 'q':
		env.quote = true;
		break;
	case 'n':
		env.name = arg;
		break;
	case 'l':
		env.line = arg;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case MAX_ARGS_KEY:
		errno = 0;
		max_args = strtol(arg, NULL, 10);
		if (errno || max_args < 1 || max_args > TOTAL_MAX_ARGS) {
			fprintf(stderr, "Invalid MAX_ARGS %s, should be in [1, %d] range\n",
					arg, TOTAL_MAX_ARGS);

			argp_usage(state);
		}
		env.max_args = max_args;
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

static void time_since_start()
{
	long nsec, sec;
	static struct timespec cur_time;
	double time_diff;

	clock_gettime(CLOCK_MONOTONIC, &cur_time);
	nsec = cur_time.tv_nsec - start_time.tv_nsec;
	sec = cur_time.tv_sec - start_time.tv_sec;
	if (nsec < 0) {
		nsec += NSEC_PER_SEC;
		sec--;
	}
	time_diff = sec + (double)nsec / NSEC_PER_SEC;
	printf("%-8.3f", time_diff);
}

static void inline quoted_symbol(char c) {
	switch(c) {
		case '"':
			putchar('\\');
			putchar('"');
			break;
		case '\t':
			putchar('\\');
			putchar('t');
			break;
		case '\n':
			putchar('\\');
			putchar('n');
			break;
		default:
			putchar(c);
			break;
	}
}

static void print_args(const struct event *e, bool quote)
{
	int i, args_counter = 0;

	if (env.quote)
		putchar('"');

	for (i = 0; i < e->args_size && args_counter < e->args_count; i++) {
		char c = e->args[i];

		if (env.quote) {
			if (c == '\0') {
				args_counter++;
				putchar('"');
				putchar(' ');
				if (args_counter < e->args_count) {
					putchar('"');
				}
			} else {
				quoted_symbol(c);
			}
		} else {
			if (c == '\0') {
				args_counter++;
				putchar(' ');
			} else {
				putchar(c);
			}
		}
	}
	if (e->args_count == env.max_args + 1) {
		fputs(" ...", stdout);
	}
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	time_t t;
	struct tm *tm;
	char ts[32];

	/* TODO: use pcre lib */
	if (env.name && strstr(e->comm, env.name) == NULL)
		return;

	/* TODO: use pcre lib */
	if (env.line && strstr(e->comm, env.line) == NULL)
		return;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (env.time) {
		printf("%-8s ", ts);
	}
	if (env.timestamp) {
		time_since_start();
	}

	if (env.print_uid)
		printf("%-6d", e->uid);

	printf("%-16s %-6d %-6d %3d ", e->comm, e->pid, e->ppid, e->retval);
	print_args(e, env.quote);
	putchar('\n');
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
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
        s->name = "execsnoop_bpf";
        s->obj = &obj->obj;

        /* maps */
        s->map_cnt = 4;
        s->map_skel_sz = sizeof(*s->maps);
        s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
        if (!s->maps) {
                err = -ENOMEM;
                goto err;
        }

        s->maps[0].name = "cgroup_map";
        s->maps[0].map = &obj->maps.cgroup_map;

        s->maps[1].name = "execs";
        s->maps[1].map = &obj->maps.execs;

        s->maps[2].name = "events";
        s->maps[2].map = &obj->maps.events;

        s->maps[3].name = "execsnoo.rodata";
        s->maps[3].map = &obj->maps.rodata;
        s->maps[3].mmaped = (void **)&obj->rodata;

        /* programs */
        s->prog_cnt = 2;
        s->prog_skel_sz = sizeof(*s->progs);
        s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
        if (!s->progs) {
                err = -ENOMEM;
                goto err;
        }

        s->progs[0].name = "tracepoint__syscalls__sys_enter_execve";
        s->progs[0].prog = &obj->progs.tracepoint__syscalls__sys_enter_execve;
        s->progs[0].link = &obj->links.tracepoint__syscalls__sys_enter_execve;

        s->progs[1].name = "tracepoint__syscalls__sys_exit_execve";
        s->progs[1].prog = &obj->progs.tracepoint__syscalls__sys_exit_execve;
        s->progs[1].link = &obj->links.tracepoint__syscalls__sys_exit_execve;

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
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
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
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->ignore_failed = !env.fails;
	obj->rodata->targ_uid = env.uid;
	obj->rodata->max_args = env.max_args;
	obj->rodata->filter_cg = env.cg;

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

	clock_gettime(CLOCK_MONOTONIC, &start_time);
	err = bpf_object__attach_skeleton(obj->skeleton);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
	/* print headers */
	if (env.time) {
		printf("%-9s", "TIME");
	}
	if (env.timestamp) {
		printf("%-8s ", "TIME(s)");
	}
	if (env.print_uid) {
		printf("%-6s ", "UID");
	}

	printf("%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS");

	/* setup event callbacks */
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
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
