#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <sys/resource.h>
#include <linux/ring_buffer.h>
#include <bpf/libbpf.h>

#include "common.h"
#include "probe_execve.h"
#include "skeleton.skel.h"

#define MAP_PAGE_SIZE 1024
#define MAX_CNT 1000000llu

#if defined(__x86_64__)
#define SYS_STAT_NAME "__x64_sys_execve"
#elif defined(__aarch64__)
#define SYS_STAT_NAME "__arm64_sys_execve"
#else
#error "Unsupported architecture"
#endif

static __u64  cnt;
static int    event_map_fd = 0;
static struct bpf_object  *bpf_obj  = NULL;
static struct bpf_program *bpf_prog = NULL;
static struct bpf_link    *bpf_link = NULL;


static int print_bpf_output(void *ctx, void *data, size_t len) {
    struct event *v = (struct event *)data;
    printf("%s %llu %u %s %u %s %u\n", v->cookie, (unsigned long long)v->micro_second, (unsigned int)v->tgid, v->comm, (unsigned int)v->ppid, v->pcomm, v->uid);

    return 0;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    setrlimit(RLIMIT_MEMLOCK, &lim);

    bpf_obj = bpf_object__open_mem(obj_buf, obj_buf_sz, NULL);
    if (libbpf_get_error(bpf_obj)) {
        printf("ERROR: failed to open prog: '%s'\n", strerror(errno));
        return 1;
    }

    if (bpf_object__load(bpf_obj)) {
        printf("ERROR: failed to load prog: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_prog = bpf_object__find_program_by_name(bpf_obj,"sys_execve_enter");
    bpf_link = bpf_program__attach_kprobe(bpf_prog, 0, SYS_STAT_NAME);
    if (libbpf_get_error(bpf_link)) {
        return 2;
    }

    event_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "ring_map");
    if ( 0 >= event_map_fd){
        printf("ERROR: failed to load event_map_fd: '%s'\n", strerror(errno));
        return 1;
    }

    struct ring_buffer *ring_buffer;
    ring_buffer = ring_buffer__new(event_map_fd, print_bpf_output, NULL, NULL);
    if(!ring_buffer) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    while(1) {
        ring_buffer__consume(ring_buffer);
        sleep(1);
    }

    bpf_link__destroy(bpf_link);
    bpf_object__close(bpf_obj);

    return 0;
}
