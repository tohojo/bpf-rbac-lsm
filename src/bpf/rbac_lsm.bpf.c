// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"

char _license[] SEC("license") = "GPL";

int seen_pin = 0;

enum event_type {
	BPF_SYSCALL,
	MAP_FD_ACCESS,
	MAP_CREATE,
	PROG_FD_ACCESS,
	PROG_LOAD,
};

struct event {
	enum event_type event_type;
	int pid;
        u8 comm[16];
	u8 obj_name[BPF_OBJ_NAME_LEN];
        u32 obj_id;
        enum bpf_prog_type prog_type;
        enum bpf_map_type map_type;
	enum bpf_cmd bpf_cmd;
};

// Dummy instance to get skeleton to generate definition for `struct event`
struct event _event = {0};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

static struct event *new_event(enum event_type type) {
        struct task_struct *task;
	struct event *event;

        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
		return NULL;

        task = bpf_get_current_task_btf();

        event->event_type = type;
        event->pid = task->pid;
        bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm),
                                  task->comm);
        return event;
}


SEC("lsm/bpf")
int BPF_PROG(sys_bpf_hook, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct event *event = new_event(BPF_SYSCALL);
	if (!event)
		goto out;

	event->bpf_cmd = cmd;

	bpf_ringbuf_submit(event, 0);
out:
	return 0;
}

SEC("lsm/bpf_map")
int BPF_PROG(sys_bpf_map_hook, struct bpf_map *map)
{
	struct event *event = new_event(MAP_FD_ACCESS);
        if (!event)
		goto out;

        bpf_probe_read_kernel_str(&event->obj_name, sizeof(event->obj_name),
                                  map->name);
        event->obj_id = map->id;

	bpf_ringbuf_submit(event, 0);
out:
	return 0;
}

SEC("lsm/bpf_map_create")
int BPF_PROG(sys_bpf_map_create_hook, struct bpf_map *map)
{
	struct event *event = new_event(MAP_CREATE);
	if (!event)
		goto out;

        bpf_probe_read_kernel_str(&event->obj_name, sizeof(event->obj_name),
                                  map->name);
        event->map_type = map->map_type;

        bpf_ringbuf_submit(event, 0);
out:
	return 0;
}

static void walk_bpf_instructions(struct bpf_prog *prog)
{
	int insn_cnt = prog->len, i;

	bpf_for(i, 0, insn_cnt) {
		struct bpf_insn insn;

                if (bpf_probe_read_kernel(&insn, sizeof(insn), &prog->insnsi[i]))
			continue;

		if (insn.code != (BPF_JMP | BPF_CALL))
			continue;

		if (insn.src_reg == 0) { /* helper */
			bpf_printk("BPF prog %s(%d) called helper %d at insn %d\n", prog->aux->name, prog->type, insn.imm, i);
		} else if (insn.src_reg == BPF_PSEUDO_KFUNC_CALL) { /* kfunc */
			bpf_printk("BPF prog %s(%d) called kfunc %d from BTF ID %d at insn %d\n", prog->aux->name, prog->type, insn.imm, insn.off, i);
		}
	}
}

SEC("lsm/bpf_prog_load")
int BPF_PROG(sys_bpf_prog_load_hook, struct bpf_prog *prog)
{
	struct event *event = new_event(PROG_LOAD);
        if (!event)
		goto out;

	walk_bpf_instructions(prog);

        bpf_probe_read_kernel_str(&event->obj_name, sizeof(event->obj_name),
                                  prog->aux->name);
        event->prog_type = prog->type;

        bpf_ringbuf_submit(event, 0);
out:
	return 0;
}

SEC("lsm/bpf_prog")
int BPF_PROG(sys_bpf_prog_hook, struct bpf_prog *prog)
{
	struct event *event = new_event(PROG_FD_ACCESS);
        if (!event)
		goto out;

        bpf_probe_read_kernel_str(&event->obj_name, sizeof(event->obj_name),
                                  prog->aux->name);
        event->obj_id = prog->aux->id;

	bpf_ringbuf_submit(event, 0);
out:
	return 0;
}
