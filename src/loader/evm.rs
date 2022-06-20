use crate::util::PrimeField;
use ethereum_types::U256;

mod code;
mod decider;
mod loader;
mod transcript;
#[cfg(test)]
mod tui;

pub use code::{Code, Precompiled};
pub use decider::EvmDecider;
pub use loader::EvmLoader;
pub use transcript::EvmTranscript;

#[cfg(test)]
pub use crate::loader::evm::{loader::test::execute, tui::Tui};

// Assert F::Repr in little-endian
pub fn field_to_u256<F: PrimeField>(f: &F) -> U256 {
    U256::from_little_endian(f.to_repr().as_ref())
}

pub fn u256_to_field<F: PrimeField>(value: U256) -> F {
    let value = value % (field_to_u256(&-F::one()) + 1u64);
    let mut repr = F::Repr::default();
    value.to_little_endian(repr.as_mut());
    F::from_repr(repr).unwrap()
}
