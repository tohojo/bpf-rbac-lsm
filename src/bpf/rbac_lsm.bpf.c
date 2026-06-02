// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"

char _license[] SEC("license") = "GPL";

int seen_pin = 0;

enum event_type {
	BPF_SYSCALL
};

struct event {
	enum event_type event_type;
	int pid;
        u8 comm[16];
	enum bpf_cmd bpf_cmd;
};

// Dummy instance to get skeleton to generate definition for `struct event`
struct event _event = {0};

struct {
    /* bpflint: disable=perfbuf-usage */
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");


SEC("lsm/bpf")
int BPF_PROG(sys_bpf_hook, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct event event = {};
	struct task_struct *task;

        task = bpf_get_current_task_btf();

        event.event_type = BPF_SYSCALL;
        event.pid = task->pid;
	event.bpf_cmd = cmd;
        bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), task->comm);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	return 0;
}
