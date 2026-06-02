use std::mem::MaybeUninit;
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::PerfBufferBuilder;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use plain::Plain;
use time::OffsetDateTime;
use time::macros::format_description;

mod rbac_lsm {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/rbac_lsm.skel.rs"
    ));
}

#[allow(clippy::wildcard_imports)]
use rbac_lsm::*;

use rbac_lsm::types::bpf_cmd;
use rbac_lsm::types::event_type;

unsafe impl Plain for rbac_lsm::types::event {}

#[derive(Debug)]
enum EventType {
    BpfSyscall,
}

impl TryFrom<event_type> for EventType {
    type Error = &'static str;
    fn try_from(value: event_type) -> Result<Self, Self::Error> {
        match value {
            event_type::BPF_SYSCALL => Ok(Self::BpfSyscall),
            _ => Err("Unknown event"),
        }
    }
}

#[derive(Debug)]
enum BpfCmd {
    MapCreate,
    MapLookupElem,
    MapUpdateElem,
    MapDeleteElem,
    MapGetNextKey,
    ProgLoad,
    ObjPin,
    ObjGet,
    ProgAttach,
    ProgDetach,
    ProgRun,
    ProgGetNextId,
    MapGetNextId,
    ProgGetFdById,
    MapGetFdById,
    ObjGetInfoByFd,
    ProgQuery,
    RawTracepointOpen,
    BtfLoad,
    BtfGetFdById,
    TaskFdQuery,
    MapLookupAndDeleteElem,
    MapFreeze,
    BtfGetNextId,
    MapLookupBatch,
    MapLookupAndDeleteBatch,
    MapUpdateBatch,
    MapDeleteBatch,
    LinkCreate,
    LinkUpdate,
    LinkGetFdById,
    LinkGetNextId,
    EnableStats,
    IterCreate,
    LinkDetach,
    ProgBindMap,
    TokenCreate,
    ProgStreamReadByFd,
    ProgAssocStructOps,
}

impl TryFrom<bpf_cmd> for BpfCmd {
    type Error = &'static str;
    fn try_from(value: bpf_cmd) -> Result<Self, Self::Error> {
        match value {
            bpf_cmd::BPF_MAP_CREATE => Ok(Self::MapCreate),
            bpf_cmd::BPF_MAP_LOOKUP_ELEM => Ok(Self::MapLookupElem),
            bpf_cmd::BPF_MAP_UPDATE_ELEM => Ok(Self::MapUpdateElem),
            bpf_cmd::BPF_MAP_DELETE_ELEM => Ok(Self::MapDeleteElem),
            bpf_cmd::BPF_MAP_GET_NEXT_KEY => Ok(Self::MapGetNextKey),
            bpf_cmd::BPF_PROG_LOAD => Ok(Self::ProgLoad),
            bpf_cmd::BPF_OBJ_PIN => Ok(Self::ObjPin),
            bpf_cmd::BPF_OBJ_GET => Ok(Self::ObjGet),
            bpf_cmd::BPF_PROG_ATTACH => Ok(Self::ProgAttach),
            bpf_cmd::BPF_PROG_DETACH => Ok(Self::ProgDetach),
            bpf_cmd::BPF_PROG_RUN => Ok(Self::ProgRun),
            bpf_cmd::BPF_PROG_GET_NEXT_ID => Ok(Self::ProgGetNextId),
            bpf_cmd::BPF_MAP_GET_NEXT_ID => Ok(Self::MapGetNextId),
            bpf_cmd::BPF_PROG_GET_FD_BY_ID => Ok(Self::ProgGetFdById),
            bpf_cmd::BPF_MAP_GET_FD_BY_ID => Ok(Self::MapGetFdById),
            bpf_cmd::BPF_OBJ_GET_INFO_BY_FD => Ok(Self::ObjGetInfoByFd),
            bpf_cmd::BPF_PROG_QUERY => Ok(Self::ProgQuery),
            bpf_cmd::BPF_RAW_TRACEPOINT_OPEN => Ok(Self::RawTracepointOpen),
            bpf_cmd::BPF_BTF_LOAD => Ok(Self::BtfLoad),
            bpf_cmd::BPF_BTF_GET_FD_BY_ID => Ok(Self::BtfGetFdById),
            bpf_cmd::BPF_TASK_FD_QUERY => Ok(Self::TaskFdQuery),
            bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_ELEM => Ok(Self::MapLookupAndDeleteElem),
            bpf_cmd::BPF_MAP_FREEZE => Ok(Self::MapFreeze),
            bpf_cmd::BPF_BTF_GET_NEXT_ID => Ok(Self::BtfGetNextId),
            bpf_cmd::BPF_MAP_LOOKUP_BATCH => Ok(Self::MapLookupBatch),
            bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_BATCH => Ok(Self::MapLookupAndDeleteBatch),
            bpf_cmd::BPF_MAP_UPDATE_BATCH => Ok(Self::MapUpdateBatch),
            bpf_cmd::BPF_MAP_DELETE_BATCH => Ok(Self::MapDeleteBatch),
            bpf_cmd::BPF_LINK_CREATE => Ok(Self::LinkCreate),
            bpf_cmd::BPF_LINK_UPDATE => Ok(Self::LinkUpdate),
            bpf_cmd::BPF_LINK_GET_FD_BY_ID => Ok(Self::LinkGetFdById),
            bpf_cmd::BPF_LINK_GET_NEXT_ID => Ok(Self::LinkGetNextId),
            bpf_cmd::BPF_ENABLE_STATS => Ok(Self::EnableStats),
            bpf_cmd::BPF_ITER_CREATE => Ok(Self::IterCreate),
            bpf_cmd::BPF_LINK_DETACH => Ok(Self::LinkDetach),
            bpf_cmd::BPF_PROG_BIND_MAP => Ok(Self::ProgBindMap),
            bpf_cmd::BPF_TOKEN_CREATE => Ok(Self::TokenCreate),
            bpf_cmd::BPF_PROG_STREAM_READ_BY_FD => Ok(Self::ProgStreamReadByFd),
            bpf_cmd::BPF_PROG_ASSOC_STRUCT_OPS => Ok(Self::ProgAssocStructOps),
            _ => Err("Unknown event"),
        }
    }
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = rbac_lsm::types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    let comm = str::from_utf8(&event.comm).unwrap();
    let etyp: EventType = event.event_type.try_into().unwrap();
    let cmd: BpfCmd = event.bpf_cmd.try_into().unwrap();

    println!(
        "{:8} {:16} {:<7} {:20?}:{:<14?}",
        now,
        comm.trim_end_matches(char::from(0)),
        event.pid,
        etyp,
        cmd,
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<()> {
    let skel_builder = RbacLsmSkelBuilder::default();

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("Loaded BPF LSM. Press Ctrl-C to exit...");

    let perf = PerfBufferBuilder::new(&skel.maps.events)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
