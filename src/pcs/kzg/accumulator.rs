use crate::{
    loader::Loader,
    pcs,
    util::{arithmetic::CurveAffine, msm::Msm},
};
use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign},
};

#[derive(Clone, Debug)]
pub struct PreAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    g1: C,
    lhs: Msm<C, L>,
    rhs: Msm<C, L>,
}

impl<C, L> pcs::PreAccumulator for PreAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    type Accumulator = Accumulator<C, L>;

    fn evaluate(self) -> Accumulator<C, L> {
        Accumulator::new(self.lhs.evaluate(self.g1), self.rhs.evaluate(self.g1))
    }
}

impl<C, L> PreAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub fn new(g1: C, lhs: Msm<C, L>, rhs: Msm<C, L>) -> Self {
        Self { g1, lhs, rhs }
    }

    pub fn scale(&mut self, scalar: &L::LoadedScalar) {
        self.lhs *= scalar;
        self.rhs *= scalar;
    }

    pub fn extend(&mut self, other: Self) {
        assert_eq!(self.g1, other.g1);
        self.lhs += other.lhs;
        self.rhs += other.rhs;
    }

    pub fn random_linear_combine(
        scaled_accumulators: impl IntoIterator<Item = (L::LoadedScalar, Self)>,
    ) -> Self {
        scaled_accumulators
            .into_iter()
            .map(|(scalar, accumulator)| accumulator * scalar)
            .reduce(|acc, scaled_accumulator| acc + scaled_accumulator)
            .unwrap()
    }
}

impl<C, L> Add<Self> for PreAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.extend(rhs);
        self
    }
}

impl<C, L> AddAssign<Self> for PreAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn add_assign(&mut self, rhs: Self) {
        self.extend(rhs);
    }
}

impl<C, L> AddAssign<(L::LoadedScalar, Accumulator<C, L>)> for PreAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn add_assign(&mut self, (scalar, accumulator): (L::LoadedScalar, Accumulator<C, L>)) {
        let Accumulator { lhs, rhs } = accumulator;
        self.lhs.push(scalar.clone(), lhs);
        self.rhs.push(scalar, rhs);
    }
}

impl<C, L> Mul<L::LoadedScalar> for PreAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    type Output = Self;

    fn mul(mut self, rhs: L::LoadedScalar) -> Self::Output {
        self.scale(&rhs);
        self
    }
}

impl<C, L> MulAssign<&L::LoadedScalar> for PreAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn mul_assign(&mut self, rhs: &L::LoadedScalar) {
        self.scale(rhs);
    }
}

#[derive(Clone, Debug)]
pub struct Accumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub lhs: L::LoadedEcPoint,
    pub rhs: L::LoadedEcPoint,
}

impl<C, L> Accumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub fn new(lhs: L::LoadedEcPoint, rhs: L::LoadedEcPoint) -> Self {
        Self { lhs, rhs }
    }
}

impl<C, L> From<Accumulator<C, L>> for (L::LoadedEcPoint, L::LoadedEcPoint)
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn from(Accumulator { lhs, rhs }: Accumulator<C, L>) -> (L::LoadedEcPoint, L::LoadedEcPoint) {
        (lhs, rhs)
    }
}
