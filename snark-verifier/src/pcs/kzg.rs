//! [KZG](<https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf>)
//! polynomial commitment scheme and accumulation scheme.

mod accumulation;
mod accumulator;
mod decider;
mod multiopen;

pub use accumulation::{KzgAs, KzgAsProvingKey, KzgAsVerifyingKey};
pub use accumulator::{KzgAccumulator, LimbsEncoding};
pub use decider::KzgDecidingKey;
pub use multiopen::{Bdfg21, Bdfg21Proof, Gwc19, Gwc19Proof};

#[cfg(feature = "loader_halo2")]
pub use accumulator::LimbsEncodingInstructions;

/// KZG succinct verifying key.
#[derive(Clone, Copy, Debug)]
pub struct KzgSuccinctVerifyingKey<C> {
    /// Generator.
    pub g: C,
}

impl<C> KzgSuccinctVerifyingKey<C> {
    /// Initialize a [`KzgSuccinctVerifyingKey`].
    pub fn new(g: C) -> Self {
        Self { g }
    }
}

impl<C> From<C> for KzgSuccinctVerifyingKey<C> {
    fn from(g: C) -> KzgSuccinctVerifyingKey<C> {
        KzgSuccinctVerifyingKey::new(g)
    }
}
