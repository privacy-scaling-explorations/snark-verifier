use crate::{
    loader::Loader,
    protocol::Protocol,
    scheme::kzg::msm::MSM,
    util::{Curve, Transcript},
    Error,
};
use std::ops::{Add, AddAssign, Mul, MulAssign};

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
        &self,
        protocol: &Protocol<C>,
        loader: &L,
        statements: Vec<Vec<L::LoadedScalar>>,
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
        &self,
        _: &Protocol<C>,
        _: &L,
        _: &mut T,
        _: &[Vec<L::LoadedScalar>],
    ) -> Option<Accumulator<C, L>> {
        None
    }

    fn process(
        &mut self,
        loader: &L,
        transcript: &mut T,
        proof: P,
        accumulator: Accumulator<C, L>,
    ) -> Result<Self::Output, Error>;
}

#[derive(Clone, Debug)]
pub struct Accumulator<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    lhs: MSM<C, L>,
    rhs: MSM<C, L>,
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

    pub fn extend(&mut self, other: Self) {
        self.lhs += other.lhs;
        self.rhs += other.rhs;
    }

    pub fn evaluate(self, g1: C) -> (L::LoadedEcPoint, L::LoadedEcPoint) {
        (self.lhs.evaluate(g1), self.rhs.evaluate(g1))
    }

    pub fn random_linear_combine(
        scaled_accumulators: impl IntoIterator<Item = (Option<L::LoadedScalar>, Self)>,
    ) -> Self {
        scaled_accumulators
            .into_iter()
            .map(|(scalar, accumulator)| match scalar {
                Some(scalar) => accumulator * &scalar,
                None => accumulator,
            })
            .reduce(|acc, scaled_accumulator| acc + scaled_accumulator)
            .unwrap_or_default()
    }
}

impl<C, L> Default for Accumulator<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    fn default() -> Self {
        Self {
            lhs: MSM::default(),
            rhs: MSM::default(),
        }
    }
}

impl<C, L> Add<Self> for Accumulator<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.extend(rhs);
        self
    }
}

impl<C, L> AddAssign<Self> for Accumulator<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    fn add_assign(&mut self, rhs: Self) {
        self.extend(rhs);
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

impl<C, L> MulAssign<&L::LoadedScalar> for Accumulator<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    fn mul_assign(&mut self, rhs: &L::LoadedScalar) {
        self.scale(rhs);
    }
}

pub struct SameCurveAccumulation<C: Curve, L: Loader<C>, const LIMBS: usize, const BITS: usize> {
    pub accumulator: Option<Accumulator<C, L>>,
}

impl<C: Curve, L: Loader<C>, const LIMBS: usize, const BITS: usize> Default
    for SameCurveAccumulation<C, L, LIMBS, BITS>
{
    fn default() -> Self {
        Self { accumulator: None }
    }
}
