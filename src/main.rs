use std::mem::MaybeUninit;
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::PerfBufferBuilder;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use plain::Plain;
use strum_macros::{Display as EnumDisplay, FromRepr};
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

#[derive(Debug, EnumDisplay, FromRepr)]
#[repr(u32)]
enum EventType {
    BpfSyscall,
}

impl TryFrom<event_type> for EventType {
    type Error = &'static str;

    fn try_from(value: event_type) -> Result<Self, Self::Error> {
        match Self::from_repr(value.0) {
            Some(val) => Ok(val),
            _ => Err("Unknown event"),
        }
    }
}

#[derive(Debug, EnumDisplay, FromRepr)]
#[repr(u32)]
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
        match Self::from_repr(value.0) {
            Some(val) => Ok(val),
            _ => Err("Unknown BPF command"),
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
        "{:8} {:16} {:<7} {}:{}",
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
