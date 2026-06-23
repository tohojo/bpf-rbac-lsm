#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

#define BPF_OBJ_NAME_LEN 16U

typedef unsigned char __u8;
typedef __u8 u8;
typedef short unsigned int __u16;
typedef __u16 u16;
typedef unsigned int __u32;
typedef __u32 u32;
typedef long long unsigned int __u64;
typedef __u64 u64;
typedef short int __s16;
typedef __s16 s16;
typedef int __s32;
typedef __s32 s32;


typedef int __kernel_pid_t;
typedef __kernel_pid_t pid_t;


struct task_struct {
	pid_t pid;
	pid_t tgid;
	char comm[16];
};

struct bpf_map {
	char name[BPF_OBJ_NAME_LEN];
};

struct bpf_prog_aux {
  char name[BPF_OBJ_NAME_LEN];
	u32 id;
};

struct bpf_prog {
	enum bpf_prog_type type;
	struct bpf_prog_aux *aux;
        u32 len;
        union {
		struct {
			struct {
			} __empty_insnsi;
			struct bpf_insn insnsi[0];
		};
	};
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
