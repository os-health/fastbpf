// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"
#include "probe_execve.h"

SEC(".maps")
struct {
    int (*type)[BPF_MAP_TYPE_RINGBUF];
    int (*max_entries)[4096 * 64];
} ring_map;

SEC("kprobe")
int sys_execve_enter(struct pt_regs *ctx){
    struct task_struct *task;
    struct task_struct *real_parent_task;

    struct event *event = bpf_ringbuf_reserve(&ring_map, sizeof(struct event), 0);
    if (!event) {
        return 1;
    }

    const char execve_type[] = "probe_execve";
    memcpy(&event->cookie, execve_type, sizeof(event->cookie));

    event->micro_second = bpf_ktime_get_ns();

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;

    event->tgid = id >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->uid = bpf_get_current_uid_gid();

    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&real_parent_task, sizeof(real_parent_task), &task->real_parent);
    bpf_probe_read_kernel(&event->ppid,      sizeof(event->ppid),       &real_parent_task->pid);
    bpf_probe_read_kernel_str(&event->pcomm,     sizeof(event->pcomm),      &real_parent_task->comm);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("license") char _license[] = "GPL";
