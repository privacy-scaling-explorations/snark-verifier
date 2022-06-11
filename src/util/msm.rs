use crate::{
    loader::{LoadedEcPoint, Loader, Scalar},
    util::Curve,
};
use std::{
    default::Default,
    iter,
    ops::{Add, Mul, Neg, Sub},
};

#[derive(Clone, Debug)]
pub struct MSM<C: Curve, L: Loader<C>> {
    pub scalar: Scalar<C, L>,
    bases: Vec<L::LoadedEcPoint>,
    scalars: Vec<Scalar<C, L>>,
}

impl<C: Curve, L: Loader<C>> Default for MSM<C, L> {
    fn default() -> Self {
        Self {
            scalar: Scalar::zero(),
            bases: Vec::new(),
            scalars: Vec::new(),
        }
    }
}

impl<C: Curve, L: Loader<C>> MSM<C, L> {
    pub fn scalar(scalar: L::LoadedScalar) -> Self {
        MSM {
            scalar: Scalar::Loaded(scalar),
            ..Default::default()
        }
    }

    pub fn base(base: L::LoadedEcPoint) -> Self {
        MSM {
            bases: vec![base],
            scalars: vec![Scalar::one()],
            ..Default::default()
        }
    }

    pub fn evaluate(self, gen: L::LoadedEcPoint) -> L::LoadedEcPoint {
        L::LoadedEcPoint::multi_scalar_multiplication(
            iter::once((self.scalar, gen))
                .chain(self.scalars.into_iter().zip(self.bases.into_iter())),
        )
    }

    pub fn scale(&mut self, factor: L::LoadedScalar) {
        let factor = Scalar::Loaded(factor);
        self.scalar *= factor.clone();
        for scalar in self.scalars.iter_mut() {
            *scalar *= factor.clone()
        }
    }

    pub fn push(&mut self, base: L::LoadedEcPoint, scalar: L::LoadedScalar) {
        self.bases.push(base);
        self.scalars.push(Scalar::Loaded(scalar));
    }

    pub fn extend(&mut self, other: Self) {
        self.scalar += other.scalar;
        self.bases.extend(other.bases);
        self.scalars.extend(other.scalars);
    }
}

impl<C: Curve, L: Loader<C>> Add<MSM<C, L>> for MSM<C, L> {
    type Output = MSM<C, L>;

    fn add(mut self, rhs: MSM<C, L>) -> Self::Output {
        self.extend(rhs);
        self
    }
}

impl<C: Curve, L: Loader<C>> Sub<MSM<C, L>> for MSM<C, L> {
    type Output = MSM<C, L>;

    fn sub(mut self, rhs: MSM<C, L>) -> Self::Output {
        self.extend(-rhs);
        self
    }
}

impl<C: Curve, L: Loader<C>> Mul<L::LoadedScalar> for MSM<C, L> {
    type Output = MSM<C, L>;

    fn mul(mut self, rhs: L::LoadedScalar) -> Self::Output {
        self.scale(rhs);
        self
    }
}

impl<C: Curve, L: Loader<C>> Neg for MSM<C, L> {
    type Output = MSM<C, L>;
    fn neg(mut self) -> MSM<C, L> {
        self.scalar = -self.scalar;
        for scalar in self.scalars.iter_mut() {
            *scalar = -scalar.clone();
        }
        self
    }
}
