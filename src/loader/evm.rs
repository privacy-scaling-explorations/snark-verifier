use crate::{
    scheme::kzg::Cost,
    util::{Itertools, PrimeField},
};
use ethereum_types::U256;
use std::iter;

mod accumulation;
mod code;
mod loader;
mod transcript;

#[cfg(test)]
mod test;

pub use loader::EvmLoader;
pub use transcript::EvmTranscript;

#[cfg(test)]
pub use test::execute;

// Assert F::Repr in little-endian
pub fn field_to_u256<F>(f: &F) -> U256
where
    F: PrimeField<Repr = [u8; 32]>,
{
    U256::from_little_endian(f.to_repr().as_ref())
}

pub fn u256_to_field<F>(value: U256) -> F
where
    F: PrimeField<Repr = [u8; 32]>,
{
    let value = value % (field_to_u256(&-F::one()) + 1u64);
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

pub fn encode_calldata<F>(instances: Vec<Vec<F>>, proof: Vec<u8>) -> Vec<u8>
where
    F: PrimeField<Repr = [u8; 32]>,
{
    iter::empty()
        .chain(
            instances
                .into_iter()
                .flatten()
                .flat_map(|value| value.to_repr().as_ref().iter().rev().cloned().collect_vec()),
        )
        .chain(proof)
        .collect()
}

pub fn estimate_gas(cost: Cost) -> usize {
    let proof_size = cost.num_commitment * 64 + (cost.num_evaluation + cost.num_instance) * 32;

    let intrinsic_cost = 21000;
    let calldata_cost = (proof_size as f64 * 15.25).ceil() as usize;
    let ec_operation_cost = 113100 + (cost.num_msm - 2) * 6350;

    intrinsic_cost + calldata_cost + ec_operation_cost
}
