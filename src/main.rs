use std::ffi::CStr;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, BufRead};
use std::mem::{MaybeUninit, offset_of};
use std::time::Duration;

use anyhow::{Error, Result, anyhow, bail};
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use time::OffsetDateTime;
use time::macros::format_description;

mod bpf_types;

#[allow(clippy::wildcard_imports)]
use bpf_types::rbac_lsm::*;

use bpf_types::rbac_lsm::types::{bpf_func_entry, bpf_func_list, event, event_type};
use bpf_types::{BpfCmd, BpfFuncId, BpfMapType, BpfProgType};

#[derive(Clone, Debug)]
enum Funcall {
    Helper(BpfFuncId),
    Kfunc { btf_id: u16, func_id: u32 },
}

impl Display for Funcall {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        use Funcall::*;
        match self {
            Helper(id) => write!(f, "Helper({})", id),
            Kfunc { btf_id, func_id } => write!(f, "Kfunc({}:{})", btf_id, func_id),
        }
    }
}

impl TryFrom<&bpf_func_entry> for Funcall {
    type Error = Error;

    fn try_from(fe: &bpf_func_entry) -> Result<Self, Self::Error> {
        use Funcall::*;
        match fe.call_type {
            0 => Ok(Helper(fe.func_id.try_into()?)),
            _ => Ok(Kfunc {
                btf_id: fe.btf_id,
                func_id: fe.func_id,
            }),
        }
    }
}

#[derive(Debug)]
enum Fmode {
    NoAccess,
    Read,
    Write,
    ReadWrite,
}

impl Display for Fmode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        use Fmode::*;
        match self {
            NoAccess => write!(f, "-"),
            Read => write!(f, "r"),
            Write => write!(f, "w"),
            ReadWrite => write!(f, "rw"),
        }
    }
}

impl From<u8> for Fmode {
    fn from(mode: u8) -> Self {
        use Fmode::*;
        match mode & 3 {
            0 => NoAccess,
            1 => Read,
            2 => Write,
            3 => ReadWrite,
            _ => panic!("can't happen"),
        }
    }
}

#[derive(Debug)]
enum EventKind {
    BpfSyscall {
        cmd: BpfCmd,
    },
    MapFdAccess {
        map_id: u32,
        map_name: String,
        map_type: BpfMapType,
        access_mode: Fmode,
    },
    MapCreate {
        map_name: String,
        map_type: BpfMapType,
    },
    MapMmap {
        map_id: u32,
        map_name: String,
        map_type: BpfMapType,
        access_mode: Fmode,
    },
    ProgFdAccess {
        prog_id: u32,
        prog_name: String,
        prog_type: BpfProgType,
    },
    ProgLoad {
        prog_name: String,
        prog_type: BpfProgType,
        funcs: Vec<Funcall>,
    },
}

impl Display for EventKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        use EventKind::*;
        match self {
            BpfSyscall { cmd } => write!(f, "Syscall ({})", cmd),
            MapFdAccess {
                map_id,
                map_name,
                map_type,
                access_mode,
            } => write!(
                f,
                "Map FD access (id: {} name: {} type: {} mode: {})",
                map_id, map_name, map_type, access_mode
            ),
            MapCreate { map_name, map_type } => {
                write!(f, "Map create (name: {} type: {})", map_name, map_type)
            }

            MapMmap {
                map_id,
                map_name,
                map_type,
                access_mode,
            } => write!(
                f,
                "Map MMAP (id: {} name: {} type: {} mode: {})",
                map_id, map_name, map_type, access_mode
            ),
            ProgFdAccess {
                prog_id,
                prog_name,
                prog_type,
            } => write!(
                f,
                "Prog FD access (id: {} name: {} type: {})",
                prog_id, prog_name, prog_type
            ),
            ProgLoad {
                prog_name,
                prog_type,
                funcs,
            } => {
                write!(
                    f,
                    "Prog load (name: {} type: {} funcalls: {}",
                    prog_name,
                    prog_type,
                    funcs.len()
                )?;
                if funcs.len() > 0 {
                    write!(f, " (")?;
                    funcs.iter().for_each(|func| {
                        let _ = write!(f, "{} ", func);
                    });
                    write!(f, "))")
                } else {
                    write!(f, ")")
                }
            }
        }
    }
}

#[derive(Debug)]
struct Event {
    comm: String,
    pid: i32,
    userns: u64,
    kind: EventKind,
}

fn buf_to_str(buf: &[u8]) -> Result<&str, Error> {
    Ok(CStr::from_bytes_until_nul(buf)?.to_str()?)
}

impl TryFrom<&event> for Event {
    type Error = Error;

    fn try_from(evt: &event) -> Result<Self, Self::Error> {
        let event = Event {
            comm: buf_to_str(&evt.comm)?.into(),
            pid: evt.pid,
            userns: evt.userns,
            kind: match evt.event_type {
                event_type::BPF_SYSCALL => EventKind::BpfSyscall {
                    cmd: evt.bpf_cmd.try_into()?,
                },
                event_type::MAP_FD_ACCESS => EventKind::MapFdAccess {
                    map_name: buf_to_str(&evt.obj_name)?.into(),
                    map_id: evt.obj_id,
                    map_type: evt.map_type.try_into()?,
                    access_mode: evt.access_mode.into(),
                },
                event_type::MAP_MMAP => EventKind::MapMmap {
                    map_name: buf_to_str(&evt.obj_name)?.into(),
                    map_id: evt.obj_id,
                    map_type: evt.map_type.try_into()?,
                    access_mode: evt.access_mode.into(),
                },
                event_type::MAP_CREATE => EventKind::MapCreate {
                    map_name: buf_to_str(&evt.obj_name)?.into(),
                    map_type: evt.map_type.try_into()?,
                },
                event_type::PROG_FD_ACCESS => EventKind::ProgFdAccess {
                    prog_name: buf_to_str(&evt.obj_name)?.into(),
                    prog_id: evt.obj_id,
                    prog_type: evt.prog_type.try_into()?,
                },
                event_type::PROG_LOAD => EventKind::ProgLoad {
                    prog_name: buf_to_str(&evt.obj_name)?.into(),
                    prog_type: evt.prog_type.try_into()?,
                    funcs: Vec::with_capacity(evt.funcs.num_entries as usize),
                },
                t => bail!("Unknown event type {:?}", t),
            },
        };

        Ok(event)
    }
}

impl Display for Event {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}({}) in {}: {}",
            self.comm, self.pid, self.userns, self.kind
        )
    }
}

fn collect_funcalls(event: &mut Event, data: &[u8]) -> Result<()> {
    match &mut event.kind {
        EventKind::ProgLoad { funcs, .. } => {
            let extra_data = &data[offset_of!(event, funcs)..];
            let flist: &bpf_func_list = plain::from_bytes(extra_data)
                .or(Err(anyhow!("Couldn't get func list entry count")))?;

            if flist.num_entries > 0 {
                let entries: &[bpf_func_entry] = plain::slice_from_bytes_len(
                    &extra_data[offset_of!(bpf_func_list, entries)..],
                    flist.num_entries as usize,
                )
                .or(Err(anyhow!("Couldn't parse func list entries")))?;

                for f in entries.iter() {
                    let func: Funcall = f.try_into()?;
                    funcs.push(func);
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn handle_event(data: &[u8]) -> i32 {
    let event: &event = plain::from_bytes(data).expect("Data buffer was too short");

    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second].[subsecond digits:6]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    let evt: Result<Event> = event.try_into();
    if let Ok(mut e) = evt {
        if let Err(e) = collect_funcalls(&mut e, data) {
            eprintln!("{} ERROR: collecting function calls: {}", now, e);
        }
        println!("{:8} {}", now, e);
    } else {
        eprintln!("{} ERROR parsing event: {:?}", now, evt);
    }
    0
}

fn resolve_ksym(name: &str) -> Result<u64> {
    let file = File::open("/proc/kallsyms")?;
    let mut lines = io::BufReader::new(file).lines();
    if let Some(Ok(line)) =
        lines.find(|l| l.as_ref().is_ok_and(|l| l.split(" ").nth(2) == Some(name)))
    {
        if let Some((addr, _)) = line.split_once(" ") {
            return Ok(u64::from_str_radix(addr, 16)?);
        }
    }
    Err(anyhow!("ksym '{}' not found", name))
}

fn main() -> Result<()> {
    let skel_builder = RbacLsmSkelBuilder::default();

    let addr = resolve_ksym("bpf_map_fops")?;
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;
    open_skel.maps.rodata_data.as_mut().map(|d| {
        d.map_fops_addr = addr;
    });
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("Loaded BPF LSM. Press Ctrl-C to exit...");

    let mut r = RingBufferBuilder::new();
    r.add(&skel.maps.events, handle_event)?;
    let ring = r.build()?;

    loop {
        ring.poll(Duration::from_millis(100))?;
    }
}
