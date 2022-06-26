use crate::{
    loader::Loader,
    protocol::Protocol,
    scheme::kzg::msm::MSM,
    util::{Curve, Transcript},
    Error,
};
use std::ops::Mul;

pub mod plonk;
pub mod shplonk;

pub trait AccumulationScheme<C, L, T, S>
where
    C: Curve,
    L: Loader<C>,
    T: Transcript<C, L>,
    S: AccumulationStrategy<C, L, T, Self::Proof>,
{
    type Proof;

    fn accumulate(
        &mut self,
        protocol: &Protocol<C>,
        loader: &L,
        statements: &[&[L::LoadedScalar]],
        transcript: &mut T,
        strategy: &mut S,
    ) -> Result<S::Output, Error>;
}

pub trait AccumulationStrategy<C, L, T, P>
where
    C: Curve,
    L: Loader<C>,
    T: Transcript<C, L>,
{
    type Output;

    fn extract_accumulator(
        _: &Protocol<C>,
        _: &L,
        _: &[&[L::LoadedScalar]],
        _: &mut T,
    ) -> Option<Accumulator<C, L>> {
        None
    }

    fn process(
        &mut self,
        loader: &L,
        proof: P,
        accumulator: Accumulator<C, L>,
    ) -> Result<Self::Output, Error>;
}

pub struct Accumulator<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    pub lhs: MSM<C, L>,
    pub rhs: MSM<C, L>,
}

impl<C, L> Accumulator<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    pub fn new(lhs: MSM<C, L>, rhs: MSM<C, L>) -> Self {
        Self { lhs, rhs }
    }

    pub fn scale(&mut self, scalar: &L::LoadedScalar) {
        self.lhs *= scalar;
        self.rhs *= scalar;
    }
}

impl<C, L> Mul<&L::LoadedScalar> for Accumulator<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    type Output = Self;

    fn mul(mut self, rhs: &L::LoadedScalar) -> Self::Output {
        self.scale(rhs);
        self
    }
}
