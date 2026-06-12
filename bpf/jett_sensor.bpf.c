// jeTT Phase 1 — successful exec telemetry via sched_process_exec (not execve enter).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define JETT_EVENT_VERSION 1
#define JETT_EVT_EXEC 1

struct jett_event {
	__u32 version;
	__u32 pid;
	__u32 uid;
	__u32 event_type;
	__u64 ts_ns;
	char comm[16];
	char path[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} jett_events SEC(".maps");

static __always_inline const char *jett_exec_filename(
	struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 off = ctx->__data_loc_filename & 0xFFFF;
	return (const char *)ctx + sizeof(*ctx) + off;
}

SEC("tp/sched/sched_process_exec")
int jett_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct jett_event *e;
	const char *fname;

	e = bpf_ringbuf_reserve(&jett_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->version = JETT_EVENT_VERSION;
	e->event_type = JETT_EVT_EXEC;
	e->pid = ctx->pid;
	e->uid = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	e->ts_ns = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname = jett_exec_filename(ctx);
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), fname);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
