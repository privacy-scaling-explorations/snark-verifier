use crate::{
    loader::{LoadedEcPoint, Loader},
    util::arithmetic::CurveAffine,
};
use std::{
    default::Default,
    iter::{self, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Debug)]
pub struct Msm<C: CurveAffine, L: Loader<C>> {
    constant: Option<L::LoadedScalar>,
    bases: Vec<L::LoadedEcPoint>,
    scalars: Vec<L::LoadedScalar>,
}

impl<C: CurveAffine, L: Loader<C>> Default for Msm<C, L> {
    fn default() -> Self {
        Self {
            constant: None,
            scalars: Vec::new(),
            bases: Vec::new(),
        }
    }
}

impl<C: CurveAffine, L: Loader<C>> Msm<C, L> {
    pub fn constant(constant: L::LoadedScalar) -> Self {
        Msm {
            constant: Some(constant),
            ..Default::default()
        }
    }

    pub fn base(base: L::LoadedEcPoint) -> Self {
        let one = base.loader().load_one();
        Msm {
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
                .chain(self.constant.map(|constant| (constant, gen)))
                .chain(self.scalars.into_iter().zip(self.bases.into_iter())),
        )
    }

    pub fn scale(&mut self, factor: &L::LoadedScalar) {
        if let Some(constant) = self.constant.as_mut() {
            *constant *= factor;
        }
        for constant in self.scalars.iter_mut() {
            *constant *= factor
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
        match (self.constant.as_mut(), other.constant.as_ref()) {
            (Some(lhs), Some(rhs)) => *lhs += rhs,
            (None, Some(_)) => self.constant = other.constant.take(),
            _ => {}
        };
        for (constant, base) in other.scalars.into_iter().zip(other.bases) {
            self.push(constant, base);
        }
    }
}

impl<C: CurveAffine, L: Loader<C>> Add<Msm<C, L>> for Msm<C, L> {
    type Output = Msm<C, L>;

    fn add(mut self, rhs: Msm<C, L>) -> Self::Output {
        self.extend(rhs);
        self
    }
}

impl<C: CurveAffine, L: Loader<C>> AddAssign<Msm<C, L>> for Msm<C, L> {
    fn add_assign(&mut self, rhs: Msm<C, L>) {
        self.extend(rhs);
    }
}

impl<C: CurveAffine, L: Loader<C>> Sub<Msm<C, L>> for Msm<C, L> {
    type Output = Msm<C, L>;

    fn sub(mut self, rhs: Msm<C, L>) -> Self::Output {
        self.extend(-rhs);
        self
    }
}

impl<C: CurveAffine, L: Loader<C>> SubAssign<Msm<C, L>> for Msm<C, L> {
    fn sub_assign(&mut self, rhs: Msm<C, L>) {
        self.extend(-rhs);
    }
}

impl<C: CurveAffine, L: Loader<C>> Mul<&L::LoadedScalar> for Msm<C, L> {
    type Output = Msm<C, L>;

    fn mul(mut self, rhs: &L::LoadedScalar) -> Self::Output {
        self.scale(rhs);
        self
    }
}

impl<C: CurveAffine, L: Loader<C>> MulAssign<&L::LoadedScalar> for Msm<C, L> {
    fn mul_assign(&mut self, rhs: &L::LoadedScalar) {
        self.scale(rhs);
    }
}

impl<C: CurveAffine, L: Loader<C>> Neg for Msm<C, L> {
    type Output = Msm<C, L>;
    fn neg(mut self) -> Msm<C, L> {
        self.constant = self.constant.map(|constant| -constant);
        for constant in self.scalars.iter_mut() {
            *constant = -constant.clone();
        }
        self
    }
}

impl<C: CurveAffine, L: Loader<C>> Sum for Msm<C, L> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, item| acc + item).unwrap_or_default()
    }
}
