use std::ffi::CStr;
use std::fmt::{Display, Formatter};
use std::mem::MaybeUninit;
use std::time::Duration;

use anyhow::{Error, Result, anyhow, bail};
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

use rbac_lsm::types::{bpf_cmd, event, event_type};

unsafe impl Plain for rbac_lsm::types::event {}

#[derive(Debug, EnumDisplay)]
enum EventKind {
    BpfSyscall { cmd: BpfCmd },
    MapFdAccess { map_name: String },
    MapCreate { map_name: String },
    ProgFdAccess { prog_name: String },
    ProgLoad { prog_name: String },
}

#[derive(Debug)]
struct Event {
    comm: String,
    pid: i32,
    kind: EventKind,
}

fn buf_to_str(buf: &[u8]) -> Result<&str, Error> {
    Ok(CStr::from_bytes_until_nul(buf)?.to_str()?)
}

impl TryFrom<event> for Event {
    type Error = Error;

    fn try_from(evt: event) -> Result<Self, Self::Error> {
        let event = Event {
            comm: buf_to_str(&evt.comm)?.into(),
            pid: evt.pid,
            kind: match evt.event_type {
                event_type::BPF_SYSCALL => EventKind::BpfSyscall {
                    cmd: evt.bpf_cmd.try_into()?,
                },
                event_type::MAP_FD_ACCESS => EventKind::MapFdAccess {
                    map_name: buf_to_str(&evt.obj_name)?.into(),
                },
                event_type::MAP_CREATE => EventKind::MapCreate {
                    map_name: buf_to_str(&evt.obj_name)?.into(),
                },
                event_type::PROG_FD_ACCESS => EventKind::ProgFdAccess {
                    prog_name: buf_to_str(&evt.obj_name)?.into(),
                },
                event_type::PROG_LOAD => EventKind::ProgLoad {
                    prog_name: buf_to_str(&evt.obj_name)?.into(),
                },
                t => bail!("Unknown event type {:?}", t),
            },
        };

        Ok(event)
    }
}

impl Display for Event {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}({}): {:?}", self.comm, self.pid, self.kind)
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
    type Error = Error;

    fn try_from(value: bpf_cmd) -> Result<Self, Self::Error> {
        match Self::from_repr(value.0) {
            Some(val) => Ok(val),
            _ => Err(anyhow!("Unknown BPF command {}", value.0)),
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

    let evt: Result<Event> = event.try_into();
    if let Ok(e) = evt {
        println!("{:8} {}", now, e);
    } else {
        eprintln!("Error parsing event: {:?}", evt);
    }
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
