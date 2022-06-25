use crate::{
    loader::Loader,
    protocol::Protocol,
    scheme::kzg::msm::MSM,
    util::{Curve, Transcript},
    Error,
};

pub mod plonk;
pub mod shplonk;

pub trait Accumulator<C, L, T, S>
where
    C: Curve,
    L: Loader<C>,
    T: Transcript<C, L>,
    S: AccumulationStrategy<C, L, Self::Proof>,
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

pub trait AccumulationStrategy<C, L, P>
where
    C: Curve,
    L: Loader<C>,
{
    type Output;

    fn process(
        &mut self,
        loader: &L,
        proof: P,
        lhs: MSM<C, L>,
        rhs: MSM<C, L>,
    ) -> Result<Self::Output, Error>;
}
