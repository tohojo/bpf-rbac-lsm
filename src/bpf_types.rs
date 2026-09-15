use anyhow::{Error, Result, anyhow};
use plain::Plain;
use strum_macros::{Display as EnumDisplay, FromRepr};

use rbac_lsm::types::{bpf_cmd, bpf_map_type, bpf_prog_type};

pub(crate) mod rbac_lsm {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/rbac_lsm.skel.rs"
    ));
}

unsafe impl Plain for rbac_lsm::types::event {}

#[allow(non_camel_case_types)]
#[derive(Debug, EnumDisplay, FromRepr)]
#[repr(u32)]
pub enum BpfCmd {
    BPF_MAP_CREATE = 0,
    BPF_MAP_LOOKUP_ELEM = 1,
    BPF_MAP_UPDATE_ELEM = 2,
    BPF_MAP_DELETE_ELEM = 3,
    BPF_MAP_GET_NEXT_KEY = 4,
    BPF_PROG_LOAD = 5,
    BPF_OBJ_PIN = 6,
    BPF_OBJ_GET = 7,
    BPF_PROG_ATTACH = 8,
    BPF_PROG_DETACH = 9,
    BPF_PROG_TEST_RUN = 10,
    BPF_PROG_GET_NEXT_ID = 11,
    BPF_MAP_GET_NEXT_ID = 12,
    BPF_PROG_GET_FD_BY_ID = 13,
    BPF_MAP_GET_FD_BY_ID = 14,
    BPF_OBJ_GET_INFO_BY_FD = 15,
    BPF_PROG_QUERY = 16,
    BPF_RAW_TRACEPOINT_OPEN = 17,
    BPF_BTF_LOAD = 18,
    BPF_BTF_GET_FD_BY_ID = 19,
    BPF_TASK_FD_QUERY = 20,
    BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21,
    BPF_MAP_FREEZE = 22,
    BPF_BTF_GET_NEXT_ID = 23,
    BPF_MAP_LOOKUP_BATCH = 24,
    BPF_MAP_LOOKUP_AND_DELETE_BATCH = 25,
    BPF_MAP_UPDATE_BATCH = 26,
    BPF_MAP_DELETE_BATCH = 27,
    BPF_LINK_CREATE = 28,
    BPF_LINK_UPDATE = 29,
    BPF_LINK_GET_FD_BY_ID = 30,
    BPF_LINK_GET_NEXT_ID = 31,
    BPF_ENABLE_STATS = 32,
    BPF_ITER_CREATE = 33,
    BPF_LINK_DETACH = 34,
    BPF_PROG_BIND_MAP = 35,
    BPF_TOKEN_CREATE = 36,
    BPF_PROG_STREAM_READ_BY_FD = 37,
    BPF_PROG_ASSOC_STRUCT_OPS = 38,
}

impl TryFrom<bpf_cmd> for BpfCmd {
    type Error = Error;

    fn try_from(value: bpf_cmd) -> Result<Self, Self::Error> {
        match Self::from_repr(value.0) {
            Some(val) => Ok(val),
            _ => Err(anyhow!("Unknown BPF command {}", value.0)),
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, EnumDisplay, FromRepr)]
pub enum BpfMapType {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
    BPF_MAP_TYPE_BLOOM_FILTER = 30,
    BPF_MAP_TYPE_USER_RINGBUF = 31,
    BPF_MAP_TYPE_CGRP_STORAGE = 32,
    BPF_MAP_TYPE_ARENA = 33,
    BPF_MAP_TYPE_INSN_ARRAY = 34,
    BPF_MAP_TYPE_RHASH = 35,
}

impl TryFrom<bpf_map_type> for BpfMapType {
    type Error = Error;

    fn try_from(value: bpf_map_type) -> Result<Self, Self::Error> {
        match Self::from_repr(value.0) {
            Some(val) => Ok(val),
            _ => Err(anyhow!("Unknown BPF map type {}", value.0)),
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, EnumDisplay, FromRepr)]
pub enum BpfProgType {
    BPF_PROG_TYPE_UNSPEC = 0,
    BPF_PROG_TYPE_SOCKET_FILTER = 1,
    BPF_PROG_TYPE_KPROBE = 2,
    BPF_PROG_TYPE_SCHED_CLS = 3,
    BPF_PROG_TYPE_SCHED_ACT = 4,
    BPF_PROG_TYPE_TRACEPOINT = 5,
    BPF_PROG_TYPE_XDP = 6,
    BPF_PROG_TYPE_PERF_EVENT = 7,
    BPF_PROG_TYPE_CGROUP_SKB = 8,
    BPF_PROG_TYPE_CGROUP_SOCK = 9,
    BPF_PROG_TYPE_LWT_IN = 10,
    BPF_PROG_TYPE_LWT_OUT = 11,
    BPF_PROG_TYPE_LWT_XMIT = 12,
    BPF_PROG_TYPE_SOCK_OPS = 13,
    BPF_PROG_TYPE_SK_SKB = 14,
    BPF_PROG_TYPE_CGROUP_DEVICE = 15,
    BPF_PROG_TYPE_SK_MSG = 16,
    BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
    BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
    BPF_PROG_TYPE_LIRC_MODE2 = 20,
    BPF_PROG_TYPE_SK_REUSEPORT = 21,
    BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
    BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
    BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
    BPF_PROG_TYPE_TRACING = 26,
    BPF_PROG_TYPE_STRUCT_OPS = 27,
    BPF_PROG_TYPE_EXT = 28,
    BPF_PROG_TYPE_LSM = 29,
    BPF_PROG_TYPE_SK_LOOKUP = 30,
    BPF_PROG_TYPE_SYSCALL = 31,
    BPF_PROG_TYPE_NETFILTER = 32,
}

impl TryFrom<bpf_prog_type> for BpfProgType {
    type Error = Error;

    fn try_from(value: bpf_prog_type) -> Result<Self, Self::Error> {
        match Self::from_repr(value.0) {
            Some(val) => Ok(val),
            _ => Err(anyhow!("Unknown BPF prog type {}", value.0)),
        }
    }
}
