use crate::{
    loader::Loader,
    pcs::PolynomialCommitmentScheme,
    util::arithmetic::{CurveAffine, MultiMillerLoop},
};
use std::{fmt::Debug, marker::PhantomData};

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

#[derive(Clone, Debug)]
pub struct Kzg<M, MOS>(PhantomData<(M, MOS)>);

impl<M, L, MOS> PolynomialCommitmentScheme<M::G1Affine, L> for Kzg<M, MOS>
where
    M: MultiMillerLoop,
    L: Loader<M::G1Affine>,
    MOS: Clone + Debug,
{
    type Accumulator = KzgAccumulator<M::G1Affine, L>;
}

#[derive(Clone, Copy, Debug)]
pub struct KzgSuccinctVerifyingKey<C: CurveAffine> {
    pub g: C,
}

impl<C: CurveAffine> KzgSuccinctVerifyingKey<C> {
    pub fn new(g: C) -> Self {
        Self { g }
    }
}

impl<C: CurveAffine> From<C> for KzgSuccinctVerifyingKey<C> {
    fn from(g: C) -> KzgSuccinctVerifyingKey<C> {
        KzgSuccinctVerifyingKey::new(g)
    }
}
