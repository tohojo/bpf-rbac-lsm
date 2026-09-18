// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"

char _license[] SEC("license") = "GPL";

volatile const u64 map_fops_addr = 0;
volatile const int enforcing = 0;

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
	u64 policy_id;
        u64 missed_events;
	u8 comm[16];
	u8 obj_name[BPF_OBJ_NAME_LEN];
	u32 obj_id;
	enum bpf_prog_type prog_type;
	enum bpf_map_type map_type;
        enum bpf_cmd bpf_cmd;
        u8 access_mode;
        char policy_verdict;
        struct bpf_func_list funcs; /* keep last */
};

#define MAX_FUNC_ENTRIES 1024
#define MAX_POLICIES 1024

#define word_type u64
#define word_bitsize (sizeof(word_type)*8)
#define bitmap_words(x) (((x-1)/(word_bitsize))+1)
#define bitmap(n, s) word_type n[bitmap_words(s)]

struct policy {
	u64 id;
	bitmap(allowed_commands, __MAX_BPF_CMD);
	bitmap(allowed_map_types, __MAX_BPF_MAP_TYPE);
	bitmap(allowed_prog_types, __MAX_BPF_PROG_TYPE);
	bitmap(allowed_helpers, __BPF_FUNC_MAX_ID);
};

#define bitmap_word(b) (b / word_bitsize)
#define bitmap_value(b) (1ULL << (b % word_bitsize))
#define bitmap_size(_p, _t) (sizeof((_p)->_t)*8)
#define check_policy_bit(_p, _t, _b) (_b < bitmap_size(_p, _t) && \
				      ((_p)->_t[bitmap_word(_b)] & bitmap_value(_b)))

// Dummy instance to get skeleton to generate definition for `struct event`
struct event _event = {0};
u64 missed_events = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_FUNC_ENTRIES);
	__type(key, u32);
	__type(value, struct bpf_func_entry);
} func_entry_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_POLICIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct policy);
} policies SEC(".maps");

static struct policy *get_policy(struct event *event)
{
	return bpf_map_lookup_elem(&policies, &event->userns);
}

static int check_policy(struct event *event)
{
	struct policy *policy;
        int ret = 0;

        policy = get_policy(event);
        if (!policy) {
		ret = -ENOENT;
                goto out;
        }

        event->policy_id = policy->id;

        switch (event->event_type) {
        case MAP_CREATE:
        case MAP_FD_ACCESS:
        case MAP_MMAP:
		if (!check_policy_bit(policy, allowed_map_types, event->map_type))
			ret = -EPERM;
                break;
        case PROG_LOAD:
	case PROG_FD_ACCESS:
		if (!check_policy_bit(policy, allowed_prog_types, event->prog_type))
			ret = -EPERM;
                break;
        case BPF_SYSCALL:
		if (!check_policy_bit(policy, allowed_commands, event->bpf_cmd))
			ret = -EPERM;
                break;
        }

        if (event->funcs.num_entries) {
		int i;

		bpf_for(i, 0, event->funcs.num_entries) {
			struct bpf_func_entry *entry = bpf_map_lookup_elem(&func_entry_scratch, &i);
			if (!entry)
				break;

			if (entry->call_type == FUNC_HELPER &&
			    !check_policy_bit(policy, allowed_helpers, entry->func_id)) {
				ret = -ENOEXEC;
				break;
			}
                }
	}
out:
	if (!event->policy_verdict)
		event->policy_verdict = ret;
        return (event->policy_verdict && enforcing) ? -EPERM : 0;
}

static void event_init(struct event *event, enum event_type type) {
	struct task_struct *task = bpf_get_current_task_btf();

	__builtin_memset(event, 0, sizeof(*event));

        event->event_type = type;
        event->pid = task->pid;
        event->userns = task->cred->user_ns->ns.inum;
        bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm),
                                  task->comm);
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

static void event_submit(struct event *event) {
	u64 missed = missed_events;
        int ret;

        if (missed) {
		if (__sync_bool_compare_and_swap(&missed_events, missed, 0))
			event->missed_events = missed;
                else
			missed = 0;
	}

        ret = bpf_ringbuf_output(&events, event, sizeof(*event), 0);
        if (ret)
                __sync_fetch_and_add(&missed_events, ++missed);
}

SEC("lsm/bpf")
int BPF_PROG(sys_bpf_hook, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct event event;
        int ret;

	event_init(&event, BPF_SYSCALL);
        event.bpf_cmd = cmd;

        ret = check_policy(&event);

        event_submit(&event);
	return ret;
}

SEC("lsm/bpf_map")
int BPF_PROG(bpf_map_hook, struct bpf_map *map, unsigned int fmode)
{
	struct event event;
        int ret;

	event_init(&event, MAP_FD_ACCESS);
        event_populate_map(&event, map);
        event.access_mode = fmode;

        ret = check_policy(&event);

        event_submit(&event);
	return ret;
}

SEC("lsm/bpf_map_create")
int BPF_PROG(sys_bpf_map_create_hook, struct bpf_map *map)
{
	struct event event;
	int ret;

	event_init(&event, MAP_CREATE);
        event_populate_map(&event, map);

        ret = check_policy(&event);
        event_submit(&event);

	return ret;
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
        struct event *event, evt;
        struct bpf_dynptr ptr;
        bool dptr = false;
        int ret, i;

        ret = walk_bpf_instructions(prog);
        if (ret < 0)
		goto out;
        num_entries = ret;
        extra_size = num_entries * sizeof(struct bpf_func_entry);

        ret = bpf_ringbuf_reserve_dynptr(&events, sizeof(*event) + extra_size,
                                         0, &ptr);
        if (ret) {
		event = &evt;
		bpf_ringbuf_discard_dynptr(&ptr, 0);
        } else {
		dptr = true;
		event = bpf_dynptr_data(&ptr, 0, sizeof(*event));
		if (!event)
			goto err;
	}

        event_init(event, PROG_LOAD);
        event_populate_prog(event, prog);
        event->funcs.num_entries = num_entries;

        if (!dptr)
		goto check;

	bpf_for(i, 0, num_entries) {
		struct bpf_func_entry *entry = bpf_map_lookup_elem(&func_entry_scratch, &i);
		if (!entry)
			goto err;

                bpf_dynptr_write(&ptr, offsetof(struct event, funcs.entries[i]),
				 entry, sizeof(*entry), 0);
        }

check:
        ret = check_policy(event);

        if (dptr)
		bpf_ringbuf_submit_dynptr(&ptr, 0);
        else
		event_submit(event);
out:
	if (ret < 4095) /* to appease the verifier */
		ret = -EINVAL;
	return ret;
err:
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return -ENOMEM;
}

SEC("lsm/bpf_prog")
int BPF_PROG(sys_bpf_prog_hook, struct bpf_prog *prog)
{
	struct event event;
        int ret;

	event_init(&event, PROG_FD_ACCESS);
        event_populate_prog(&event, prog);

        ret = check_policy(&event);
        event_submit(&event);
out:
	return ret;
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file_hook, struct file *file, unsigned int mode) {
	struct bpf_map *map;
        struct event event;
        int ret;

        /* we only care about bpf map fds */
	if (!file || (u64)file->f_op != map_fops_addr)
		return 0;

        map = file->private_data;

        event_init(&event, MAP_MMAP);
        event_populate_map(&event, map);
        event.access_mode = mode;

        ret = check_policy(&event);

        event_submit(&event);
	return ret;
}
