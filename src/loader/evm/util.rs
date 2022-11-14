use crate::{
    cost::Cost,
    util::{arithmetic::PrimeField, Itertools},
};
use ethereum_types::U256;
use std::{
    io::Write,
    iter,
    process::{Command, Stdio},
};

pub(crate) mod executor;

pub use executor::ExecutorBuilder;

pub struct MemoryChunk {
    ptr: usize,
    len: usize,
}

impl MemoryChunk {
    pub fn new(ptr: usize) -> Self {
        Self { ptr, len: 0 }
    }

    pub fn ptr(&self) -> usize {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn end(&self) -> usize {
        self.ptr + self.len
    }

    pub fn reset(&mut self, ptr: usize) {
        self.ptr = ptr;
        self.len = 0;
    }

    pub fn extend(&mut self, size: usize) {
        self.len += size;
    }
}

// Assume fields implements traits in crate `ff` always have little-endian representation.
pub fn fe_to_u256<F>(f: F) -> U256
where
    F: PrimeField<Repr = [u8; 32]>,
{
    U256::from_little_endian(f.to_repr().as_ref())
}

pub fn u256_to_fe<F>(value: U256) -> F
where
    F: PrimeField<Repr = [u8; 32]>,
{
    let value = value % modulus::<F>();
    let mut repr = F::Repr::default();
    value.to_little_endian(repr.as_mut());
    F::from_repr(repr).unwrap()
}

pub fn modulus<F>() -> U256
where
    F: PrimeField<Repr = [u8; 32]>,
{
    U256::from_little_endian((-F::one()).to_repr().as_ref()) + 1
}

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

pub fn estimate_gas(cost: Cost) -> usize {
    let proof_size = cost.num_commitment * 64 + (cost.num_evaluation + cost.num_instance) * 32;

    let intrinsic_cost = 21000;
    let calldata_cost = (proof_size as f64 * 15.25).ceil() as usize;
    let ec_operation_cost = 113100 + (cost.num_msm - 2) * 6350;

    intrinsic_cost + calldata_cost + ec_operation_cost
}

pub fn compile_yul(code: &str) -> Vec<u8> {
    let mut cmd = Command::new("solc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("--bin")
        .arg("--yul")
        .arg("-")
        .spawn()
        .unwrap();
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
