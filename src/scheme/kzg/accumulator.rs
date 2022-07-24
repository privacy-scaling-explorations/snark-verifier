use crate::{loader::Loader, scheme::kzg::msm::MSM, util::Curve};
use std::ops::{Add, AddAssign, Mul, MulAssign};

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
        scaled_accumulators: impl IntoIterator<Item = (L::LoadedScalar, Self)>,
    ) -> Self {
        scaled_accumulators
            .into_iter()
            .map(|(scalar, accumulator)| accumulator * &scalar)
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
