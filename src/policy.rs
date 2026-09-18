use crate::bpf_types::rbac_lsm::types::policy;
use crate::bpf_types::{BpfCmd, BpfFuncId, BpfMapType, BpfProgType};
use anyhow::{Error, Result, anyhow};
use std::mem::size_of;
use strum::IntoEnumIterator;

const WORD_BITSIZE: usize = size_of::<u64>() * 8;

fn set_bit(bitmap: &mut [u64], bit: usize) -> Result<()> {
    let word = bit / WORD_BITSIZE;
    let value = 1 << bit % WORD_BITSIZE;
    if let Some(v) = bitmap.get_mut(word) {
        *v |= value;
        Ok(())
    } else {
        Err(anyhow!("bit {} out of range", bit))
    }
}

fn is_bit_set(bitmap: &[u64], bit: usize) -> Result<bool> {
    let word = bit / WORD_BITSIZE;
    let value = 1 << bit % WORD_BITSIZE;
    if let Some(v) = bitmap.get(word) {
        Ok(v & value > 0)
    } else {
        Err(anyhow!("bit {} out of range", bit))
    }
}

#[derive(Debug, Default)]
pub struct Policy {
    allowed_commands: Vec<BpfCmd>,
    allowed_map_types: Vec<BpfMapType>,
    allowed_prog_types: Vec<BpfProgType>,
    allowed_helpers: Vec<BpfFuncId>,
}

#[allow(unused)]
impl Policy {
    pub fn add_allowed_cmd(self: &mut Self, cmd: BpfCmd) {
        self.allowed_commands.push(cmd)
    }
    pub fn add_allowed_map_type(self: &mut Self, map_type: BpfMapType) {
        self.allowed_map_types.push(map_type)
    }
    pub fn add_allowed_prog_type(self: &mut Self, prog_type: BpfProgType) {
        self.allowed_prog_types.push(prog_type)
    }
    pub fn add_allowed_helper(self: &mut Self, helper: BpfFuncId) {
        self.allowed_helpers.push(helper)
    }

    pub fn into_bpf_policy(self: &Self, id: u64) -> Result<policy> {
        let mut policy: policy = self.try_into()?;
        policy.id = id;
        Ok(policy)
    }
}

macro_rules! to_bit {
    ($to:ident, $from:ident, $name:ident) => {
        for i in $from.$name.iter() {
            set_bit(&mut $to.$name, *i as usize)?;
        }
    };
}

impl TryInto<policy> for &Policy {
    type Error = Error;

    fn try_into(self) -> Result<policy, Self::Error> {
        let mut pol: policy = policy::default();

        to_bit!(pol, self, allowed_commands);
        to_bit!(pol, self, allowed_map_types);
        to_bit!(pol, self, allowed_prog_types);
        to_bit!(pol, self, allowed_helpers);

        Ok(pol)
    }
}

macro_rules! from_bit {
    ($to:ident, $from:ident, $name:ident, $type:ident) => {
        for i in $type::iter() {
            if is_bit_set(&$from.$name, i as usize)? {
                $to.$name.push(i);
            }
        }
    };
}

impl TryFrom<policy> for Policy {
    type Error = Error;

    fn try_from(pol: policy) -> Result<Self, Self::Error> {
        let mut new = Self::default();

        from_bit!(new, pol, allowed_commands, BpfCmd);
        from_bit!(new, pol, allowed_map_types, BpfMapType);
        from_bit!(new, pol, allowed_prog_types, BpfProgType);
        from_bit!(new, pol, allowed_helpers, BpfFuncId);

        Ok(new)
    }
}
