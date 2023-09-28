use crate::{
    cost::Cost,
    util::{arithmetic::PrimeField, Itertools},
};
use std::{
    io::{self, Write},
    iter,
    process::{Command, Stdio},
};

pub use executor::deploy_and_call;
pub use revm::primitives::ruint::aliases::{B160 as Address, B256, U256, U512};

pub(crate) mod executor;

/// Memory chunk in EVM.
#[derive(Debug)]
pub struct MemoryChunk {
    ptr: usize,
    len: usize,
}

impl MemoryChunk {
    pub(crate) fn new(ptr: usize) -> Self {
        Self { ptr, len: 0 }
    }

    pub(crate) fn ptr(&self) -> usize {
        self.ptr
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn end(&self) -> usize {
        self.ptr + self.len
    }

    pub(crate) fn reset(&mut self, ptr: usize) {
        self.ptr = ptr;
        self.len = 0;
    }

    pub(crate) fn extend(&mut self, size: usize) {
        self.len += size;
    }
}

/// Convert a [`PrimeField`] into a [`U256`].
/// Assuming fields that implement traits in crate `ff` always have
/// little-endian representation.
pub fn fe_to_u256<F>(f: F) -> U256
where
    F: PrimeField<Repr = [u8; 32]>,
{
    U256::from_le_bytes(f.to_repr())
}

/// Convert a [`U256`] into a [`PrimeField`].
pub fn u256_to_fe<F>(value: U256) -> F
where
    F: PrimeField<Repr = [u8; 32]>,
{
    let value = value % modulus::<F>();
    F::from_repr(value.to_le_bytes::<32>()).unwrap()
}

/// Returns modulus of [`PrimeField`] as [`U256`].
pub fn modulus<F>() -> U256
where
    F: PrimeField<Repr = [u8; 32]>,
{
    U256::from_le_bytes((-F::ONE).to_repr()) + U256::from(1)
}

/// Encode instances and proof into calldata.
pub fn encode_calldata<F>(instances: &[Vec<F>], proof: &[u8]) -> Vec<u8>
where
    F: PrimeField<Repr = [u8; 32]>,
{
    iter::empty()
        .chain(
            instances
                .iter()
                .flatten()
                .flat_map(|value| value.to_repr().as_ref().iter().rev().cloned().collect_vec()),
        )
        .chain(proof.iter().cloned())
        .collect()
}

/// Estimate gas cost with given [`Cost`].
pub fn estimate_gas(cost: Cost) -> usize {
    let proof_size = cost.num_commitment * 64 + (cost.num_evaluation + cost.num_instance) * 32;

    let intrinsic_cost = 21000;
    let calldata_cost = (proof_size as f64 * 15.25).ceil() as usize;
    let ec_operation_cost = (45100 + cost.num_pairing * 34000) + (cost.num_msm - 2) * 6350;

    intrinsic_cost + calldata_cost + ec_operation_cost
}

/// Compile given Solidity `code` into deployment bytecode.
pub fn compile_solidity(code: &str) -> Vec<u8> {
    let mut cmd = match Command::new("solc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("--bin")
        .arg("-")
        .spawn()
    {
        Ok(cmd) => cmd,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            panic!("Command 'solc' not found");
        }
        Err(err) => {
            panic!("Failed to spawn cmd with command 'solc':\n{err}");
        }
    };

    cmd.stdin
        .take()
        .unwrap()
        .write_all(code.as_bytes())
        .unwrap();
    let output = cmd.wait_with_output().unwrap().stdout;
    let binary = *split_by_ascii_whitespace(&output).last().unwrap();
    hex::decode(binary).unwrap()
}

fn split_by_ascii_whitespace(bytes: &[u8]) -> Vec<&[u8]> {
    let mut split = Vec::new();
    let mut start = None;
    for (idx, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_whitespace() {
            if let Some(start) = start.take() {
                split.push(&bytes[start..idx]);
            }
        } else if start.is_none() {
            start = Some(idx);
        }
    }
    split
}
