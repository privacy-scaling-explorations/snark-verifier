use crate::{
    protocol::Protocol,
    util::{
        loader::{LoadedEcPoint, Loader},
        Curve, Expression, Group,
    },
    Error,
};
use halo2_proofs::halo2curves::pairing::{MillerLoopResult, MultiMillerLoop};
use std::{
    default::Default,
    iter::{self, Sum},
    ops::{Add, Mul, Neg, Sub},
};

pub mod plonk;
pub mod shplonk;

pub trait VerificationStrategy<C, L, P>
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

    fn finalize(self) -> bool;
}

pub struct NativeDecider<M: MultiMillerLoop> {
    g1: M::G1Affine,
    g2: M::G2Affine,
    s_g2: M::G2Affine,
}

impl<M: MultiMillerLoop> NativeDecider<M> {
    pub fn new(g1: M::G1Affine, g2: M::G2Affine, s_g2: M::G2Affine) -> Self {
        NativeDecider { g1, g2, s_g2 }
    }
}

impl<M, L, P> VerificationStrategy<M::G1, L, P> for NativeDecider<M>
where
    M: MultiMillerLoop,
    L: Loader<M::G1, LoadedEcPoint = M::G1, LoadedScalar = M::Scalar>,
{
    type Output = bool;

    fn process(
        &mut self,
        loader: &L,
        _: P,
        lhs: MSM<M::G1, L>,
        rhs: MSM<M::G1, L>,
    ) -> Result<Self::Output, Error> {
        let g2 = M::G2Prepared::from(self.g2);
        let minus_s_g2 = M::G2Prepared::from(-self.s_g2);

        let lhs = lhs.evaluate(loader.ec_point_load_const(&self.g1.into()));
        let rhs = rhs.evaluate(loader.ec_point_load_const(&self.g1.into()));

        Ok(
            M::multi_miller_loop(&[(&lhs.into(), &g2), (&rhs.into(), &minus_s_g2)])
                .final_exponentiation()
                .is_identity()
                .into(),
        )
    }

    fn finalize(self) -> bool {
        unreachable!()
    }
}

pub fn langranges<C: Curve, L: Loader<C>>(
    protocol: &Protocol<C>,
    statements: &[&[L::LoadedScalar]],
) -> impl IntoIterator<Item = i32> {
    protocol
        .relations
        .iter()
        .cloned()
        .sum::<Expression<_>>()
        .used_langrange()
        .into_iter()
        .chain(
            0..statements
                .iter()
                .map(|statement| statement.len())
                .max()
                .unwrap_or_default() as i32,
        )
}

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

    pub fn evaluate(self, gen: L::LoadedEcPoint) -> L::LoadedEcPoint {
        L::LoadedEcPoint::multi_scalar_multiplication(
            iter::empty()
                .chain(self.scalar.map(|scalar| (scalar, gen)))
                .chain(self.scalars.into_iter().zip(self.bases.into_iter())),
        )
    }

    pub fn scale(&mut self, factor: L::LoadedScalar) {
        self.scalar = self.scalar.clone().map(|scalar| scalar * factor.clone());
        for scalar in self.scalars.iter_mut() {
            *scalar *= factor.clone()
        }
    }

    pub fn push(&mut self, scalar: L::LoadedScalar, base: L::LoadedEcPoint) {
        self.scalars.push(scalar);
        self.bases.push(base);
    }

    pub fn extend(&mut self, other: Self) {
        self.scalar = match (self.scalar.clone(), other.scalar.clone()) {
            (Some(lhs), Some(rhs)) => Some(lhs + rhs),
            (Some(scalar), None) | (None, Some(scalar)) => Some(scalar),
            (None, None) => None,
        };
        self.scalars.extend(other.scalars);
        self.bases.extend(other.bases);
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
