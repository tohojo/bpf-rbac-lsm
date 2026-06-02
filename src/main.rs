use std::mem::MaybeUninit;

use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;

mod rbac_lsm {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/rbac_lsm.skel.rs"
    ));
}

#[allow(clippy::wildcard_imports)]
use rbac_lsm::*;

const PIN_PATH: &str = "/sys/fs/bpf/lsm-nobpf";

fn main() -> Result<()> {
    let skel_builder = RbacLsmSkelBuilder::default();

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("Loaded BPF LSM");

    if let Some(mut link) = skel.links.sys_bpf_hook {
        link.pin(PIN_PATH)?;
        println!(
            "Pinned LSM link at {} - unlink file to restore BPF functionality",
            PIN_PATH
        );
    }
    Ok(())
}
