use crate::{
    loader::{LoadedEcPoint, Loader},
    util::{arithmetic::CurveAffine, Itertools},
};
use std::{
    default::Default,
    iter::{self, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Debug)]
pub struct Msm<'a, C: CurveAffine, L: Loader<C>> {
    constant: Option<L::LoadedScalar>,
    scalars: Vec<L::LoadedScalar>,
    bases: Vec<&'a L::LoadedEcPoint>,
}

impl<'a, C, L> Default for Msm<'a, C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn default() -> Self {
        Self {
            constant: None,
            scalars: Vec::new(),
            bases: Vec::new(),
        }
    }
}

impl<'a, C, L> Msm<'a, C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub fn constant(constant: L::LoadedScalar) -> Self {
        Msm {
            constant: Some(constant),
            ..Default::default()
        }
    }

    pub fn base<'b: 'a>(base: &'b L::LoadedEcPoint) -> Self {
        let one = base.loader().load_one();
        Msm {
            scalars: vec![one],
            bases: vec![base],
            ..Default::default()
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.bases.len()
    }

    pub(crate) fn split(mut self) -> (Self, Option<L::LoadedScalar>) {
        let constant = self.constant.take();
        (self, constant)
    }

    pub(crate) fn try_into_constant(self) -> Option<L::LoadedScalar> {
        self.bases.is_empty().then(|| self.constant.unwrap())
    }

    pub fn evaluate(self, gen: Option<C>) -> L::LoadedEcPoint {
        let gen = gen.map(|gen| {
            self.bases
                .first()
                .unwrap()
                .loader()
                .ec_point_load_const(&gen)
        });
        let pairs = iter::empty()
            .chain(
                self.constant
                    .as_ref()
                    .map(|constant| (constant, gen.as_ref().unwrap())),
            )
            .chain(self.scalars.iter().zip(self.bases.into_iter()))
            .collect_vec();
        L::multi_scalar_multiplication(&pairs)
    }

    pub fn scale(&mut self, factor: &L::LoadedScalar) {
        if let Some(constant) = self.constant.as_mut() {
            *constant *= factor;
        }
        for scalar in self.scalars.iter_mut() {
            *scalar *= factor
        }
    }

    pub fn push<'b: 'a>(&mut self, scalar: L::LoadedScalar, base: &'b L::LoadedEcPoint) {
        if let Some(pos) = self.bases.iter().position(|exist| exist.eq(&base)) {
            self.scalars[pos] += &scalar;
        } else {
            self.scalars.push(scalar);
            self.bases.push(base);
        }
    }

    pub fn extend<'b: 'a>(&mut self, mut other: Msm<'b, C, L>) {
        match (self.constant.as_mut(), other.constant.as_ref()) {
            (Some(lhs), Some(rhs)) => *lhs += rhs,
            (None, Some(_)) => self.constant = other.constant.take(),
            _ => {}
        };
        for (scalar, base) in other.scalars.into_iter().zip(other.bases) {
            self.push(scalar, base);
        }
    }
}

impl<'a, 'b, C, L> Add<Msm<'b, C, L>> for Msm<'a, C, L>
where
    'b: 'a,
    C: CurveAffine,
    L: Loader<C>,
{
    type Output = Msm<'a, C, L>;

    fn add(mut self, rhs: Msm<'b, C, L>) -> Self::Output {
        self.extend(rhs);
        self
    }
}

impl<'a, 'b, C, L> AddAssign<Msm<'b, C, L>> for Msm<'a, C, L>
where
    'b: 'a,
    C: CurveAffine,
    L: Loader<C>,
{
    fn add_assign(&mut self, rhs: Msm<'b, C, L>) {
        self.extend(rhs);
    }
}

impl<'a, 'b, C, L> Sub<Msm<'b, C, L>> for Msm<'a, C, L>
where
    'b: 'a,
    C: CurveAffine,
    L: Loader<C>,
{
    type Output = Msm<'a, C, L>;

    fn sub(mut self, rhs: Msm<'b, C, L>) -> Self::Output {
        self.extend(-rhs);
        self
    }
}

impl<'a, 'b, C, L> SubAssign<Msm<'b, C, L>> for Msm<'a, C, L>
where
    'b: 'a,
    C: CurveAffine,
    L: Loader<C>,
{
    fn sub_assign(&mut self, rhs: Msm<'b, C, L>) {
        self.extend(-rhs);
    }
}

impl<'a, C, L> Mul<&L::LoadedScalar> for Msm<'a, C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    type Output = Msm<'a, C, L>;

    fn mul(mut self, rhs: &L::LoadedScalar) -> Self::Output {
        self.scale(rhs);
        self
    }
}

impl<'a, C, L> MulAssign<&L::LoadedScalar> for Msm<'a, C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn mul_assign(&mut self, rhs: &L::LoadedScalar) {
        self.scale(rhs);
    }
}

impl<'a, C, L> Neg for Msm<'a, C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    type Output = Msm<'a, C, L>;
    fn neg(mut self) -> Msm<'a, C, L> {
        self.constant = self.constant.map(|constant| -constant);
        for scalar in self.scalars.iter_mut() {
            *scalar = -scalar.clone();
        }
        self
    }
}

impl<'a, C, L> Sum for Msm<'a, C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, item| acc + item).unwrap_or_default()
    }
}
