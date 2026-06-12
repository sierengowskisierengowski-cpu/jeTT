#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct security_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} event_ringbuf SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int intercept_execution(void *ctx) {
    struct security_event_t *event;

    event = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    event->ppid = BPF_CORE_READ(real_parent, tgid);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Read the filename pointer directly out of the raw tracepoint argument offset
    // On x86_64, the first argument to execve (filename) sits at ctx offset + 8 bytes
    unsigned long filename_ptr;
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), (void *)((unsigned long)ctx + 8));
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), (void *)filename_ptr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
