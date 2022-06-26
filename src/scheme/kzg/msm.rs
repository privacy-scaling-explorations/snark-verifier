use crate::{
    loader::{LoadedEcPoint, Loader},
    util::Curve,
};
use std::{
    default::Default,
    iter::{self, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Debug)]
pub struct MSM<C: Curve, L: Loader<C>> {
    pub scalar: Option<L::LoadedScalar>,
    bases: Vec<L::LoadedEcPoint>,
    scalars: Vec<L::LoadedScalar>,
}

impl<C: Curve, L: Loader<C>> Default for MSM<C, L> {
    fn default() -> Self {
        Self {
            scalar: None,
            scalars: Vec::new(),
            bases: Vec::new(),
        }
    }
}

impl<C: Curve, L: Loader<C>> MSM<C, L> {
    pub fn scalar(scalar: L::LoadedScalar) -> Self {
        MSM {
            scalar: Some(scalar),
            ..Default::default()
        }
    }

    pub fn base(base: L::LoadedEcPoint) -> Self {
        let one = base.loader().load_one();
        MSM {
            scalars: vec![one],
            bases: vec![base],
            ..Default::default()
        }
    }

    pub fn evaluate(self, gen: C) -> L::LoadedEcPoint {
        let gen = self
            .bases
            .first()
            .unwrap()
            .loader()
            .ec_point_load_const(&gen);
        L::LoadedEcPoint::multi_scalar_multiplication(
            iter::empty()
                .chain(self.scalar.map(|scalar| (scalar, gen)))
                .chain(self.scalars.into_iter().zip(self.bases.into_iter())),
        )
    }

    pub fn scale(&mut self, factor: &L::LoadedScalar) {
        if let Some(scalar) = self.scalar.as_mut() {
            *scalar *= factor;
        }
        for scalar in self.scalars.iter_mut() {
            *scalar *= factor
        }
    }

    pub fn push(&mut self, scalar: L::LoadedScalar, base: L::LoadedEcPoint) {
        if let Some(pos) = self.bases.iter().position(|exist| exist.eq(&base)) {
            self.scalars[pos] += scalar;
        } else {
            self.scalars.push(scalar);
            self.bases.push(base);
        }
    }

    pub fn extend(&mut self, mut other: Self) {
        match (self.scalar.as_mut(), other.scalar.as_ref()) {
            (Some(lhs), Some(rhs)) => *lhs += rhs,
            (None, Some(_)) => self.scalar = other.scalar.take(),
            _ => {}
        };
        for (scalar, base) in other.scalars.into_iter().zip(other.bases) {
            self.push(scalar, base);
        }
    }
}

impl<C: Curve, L: Loader<C>> Add<MSM<C, L>> for MSM<C, L> {
    type Output = MSM<C, L>;

    fn add(mut self, rhs: MSM<C, L>) -> Self::Output {
        self.extend(rhs);
        self
    }
}

impl<C: Curve, L: Loader<C>> AddAssign<MSM<C, L>> for MSM<C, L> {
    fn add_assign(&mut self, rhs: MSM<C, L>) {
        self.extend(rhs);
    }
}

impl<C: Curve, L: Loader<C>> Sub<MSM<C, L>> for MSM<C, L> {
    type Output = MSM<C, L>;

    fn sub(mut self, rhs: MSM<C, L>) -> Self::Output {
        self.extend(-rhs);
        self
    }
}

impl<C: Curve, L: Loader<C>> SubAssign<MSM<C, L>> for MSM<C, L> {
    fn sub_assign(&mut self, rhs: MSM<C, L>) {
        self.extend(-rhs);
    }
}

impl<C: Curve, L: Loader<C>> Mul<&L::LoadedScalar> for MSM<C, L> {
    type Output = MSM<C, L>;

    fn mul(mut self, rhs: &L::LoadedScalar) -> Self::Output {
        self.scale(rhs);
        self
    }
}

impl<C: Curve, L: Loader<C>> MulAssign<&L::LoadedScalar> for MSM<C, L> {
    fn mul_assign(&mut self, rhs: &L::LoadedScalar) {
        self.scale(rhs);
    }
}

impl<C: Curve, L: Loader<C>> Neg for MSM<C, L> {
    type Output = MSM<C, L>;
    fn neg(mut self) -> MSM<C, L> {
        self.scalar = self.scalar.map(|scalar| -scalar);
        for scalar in self.scalars.iter_mut() {
            *scalar = -scalar.clone();
        }
        self
    }
}

impl<C: Curve, L: Loader<C>> Sum for MSM<C, L> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, item| acc + item).unwrap_or_default()
    }
}
