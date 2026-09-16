// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"

char _license[] SEC("license") = "GPL";

volatile const u64 map_fops_addr = 0;

enum event_type {
	BPF_SYSCALL,
	MAP_FD_ACCESS,
	MAP_CREATE,
	MAP_MMAP,
	PROG_FD_ACCESS,
	PROG_LOAD,
};

enum func_type {
	FUNC_HELPER,
	FUNC_KFUNC,
};

struct bpf_func_entry {
	u16 call_type;
	u16 btf_id;
	u32 func_id;
};

struct bpf_func_list {
	u64 num_entries;
        struct bpf_func_entry entries[];
};

struct event {
	enum event_type event_type;
	int pid;
	u64 userns;
	u8 comm[16];
	u8 obj_name[BPF_OBJ_NAME_LEN];
	u32 obj_id;
	enum bpf_prog_type prog_type;
	enum bpf_map_type map_type;
        enum bpf_cmd bpf_cmd;
        u8 access_mode;
        struct bpf_func_list funcs; /* keep last */
};

#define MAX_FUNC_ENTRIES 1024

// Dummy instance to get skeleton to generate definition for `struct event`
struct event _event = {0};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_FUNC_ENTRIES);
    __type(key, u32);
    __type(value, sizeof(struct bpf_func_entry));
} func_entry_scratch SEC(".maps");

static void event_init(struct event *event, enum event_type type) {
        struct task_struct *task = bpf_get_current_task_btf();

        event->event_type = type;
        event->pid = task->pid;
        event->userns = task->cred->user_ns->ns.inum;
        bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm),
                                  task->comm);
}
static struct event *new_event(enum event_type type) {
	struct event *event;

        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
		return NULL;

        event_init(event, type);
        return event;
}

static void event_populate_map(struct event *event, struct bpf_map *map)
{
        bpf_probe_read_kernel_str(&event->obj_name, sizeof(event->obj_name),
                                  map->name);
        event->obj_id = map->id;
        event->map_type = map->map_type;
}

static void event_populate_prog(struct event *event, struct bpf_prog *prog)
{
        bpf_probe_read_kernel_str(&event->obj_name, sizeof(event->obj_name),
                                  prog->aux->name);
        event->prog_type = prog->type;
        event->obj_id = prog->aux->id;
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
int BPF_PROG(bpf_map_hook, struct bpf_map *map, unsigned int fmode)
{
	struct event *event = new_event(MAP_FD_ACCESS);
        if (!event)
		goto out;

        event_populate_map(event, map);
        event->access_mode = fmode;
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

        event_populate_map(event, map);
        bpf_ringbuf_submit(event, 0);
out:
	return 0;
}

static bool entry_exists(u16 call_type, u16 btf_id, u32 func_id,
                        int num_entries) {
	struct bpf_func_entry *entry;
	int i;

	bpf_for(i, 0, num_entries) {
                entry = bpf_map_lookup_elem(&func_entry_scratch, &i);
                if (!entry)
			return false;

                if (entry->call_type == call_type &&
                    entry->btf_id == btf_id &&
                    entry->func_id == func_id)
			return true;
        }
        return false;
}

static int walk_bpf_instructions(struct bpf_prog *prog)
{
	int insn_cnt = prog->len, i, num_entries = 0;

	bpf_for(i, 0, insn_cnt) {
		struct bpf_func_entry *entry;
		u16 call_type, btf_id;
                struct bpf_insn insn;
                u32 func_id;

                if (bpf_probe_read_kernel(&insn, sizeof(insn), &prog->insnsi[i]))
			continue;

		if (insn.code != (BPF_JMP | BPF_CALL))
			continue;

                if (insn.src_reg == 0) {
			call_type = FUNC_HELPER;
			btf_id = 0;
                } else {
			call_type = FUNC_KFUNC;
                        btf_id = insn.off;
		}
                func_id = insn.imm;

                if (entry_exists(call_type, btf_id, func_id, num_entries))
			continue;

                if (num_entries >= MAX_FUNC_ENTRIES)
			return -E2BIG;

                entry = bpf_map_lookup_elem(&func_entry_scratch, &num_entries);
                if (!entry)
			return -E2BIG;

		entry->call_type = call_type;
		entry->btf_id = btf_id;
		entry->func_id = func_id;
                num_entries++;
        }

        return num_entries;
}

SEC("lsm/bpf_prog_load")
int BPF_PROG(sys_bpf_prog_load_hook, struct bpf_prog *prog) {
        u32 extra_size, num_entries;
        struct bpf_dynptr ptr;
        struct event *event;
        int ret, i;

        ret = walk_bpf_instructions(prog);
        if (ret < 0)
		goto out;
        num_entries = ret;

        extra_size = num_entries * sizeof(struct bpf_func_entry);
        if (extra_size > sizeof(struct bpf_func_entry) * MAX_FUNC_ENTRIES)
		goto out;

        ret = bpf_ringbuf_reserve_dynptr(&events, sizeof(*event) + extra_size,
                                         0, &ptr);
        if (ret)
		goto err;

        event = bpf_dynptr_data(&ptr, 0, sizeof(*event));
        if (!event)
                goto err;

        event_init(event, PROG_LOAD);
        event_populate_prog(event, prog);
        event->funcs.num_entries = num_entries;
	bpf_for(i, 0, num_entries) {
		struct bpf_func_entry *entry = bpf_map_lookup_elem(&func_entry_scratch, &i);
		if (!entry)
			goto err;
		bpf_dynptr_write(&ptr, offsetof(struct event, funcs.entries[i]),
				 entry, sizeof(*entry), 0);
	}

        bpf_ringbuf_submit_dynptr(&ptr, 0);
out:
	return 0;
err:
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

SEC("lsm/bpf_prog")
int BPF_PROG(sys_bpf_prog_hook, struct bpf_prog *prog)
{
	struct event *event = new_event(PROG_FD_ACCESS);
        if (!event)
		goto out;

        event_populate_prog(event, prog);

	bpf_ringbuf_submit(event, 0);
out:
	return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file_hook, struct file *file, unsigned int mode) {
	struct bpf_map *map;

	if (!file || (u64)file->f_op != map_fops_addr)
		return 0;

        map = file->private_data;
	struct event *event = new_event(MAP_MMAP);
        if (!event)
		goto out;

        event_populate_map(event, map);
        event->access_mode = mode;
	bpf_ringbuf_submit(event, 0);
out:
	return 0;
}
