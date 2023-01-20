//! Multi-scalar multiplication algorithm.

use crate::{
    loader::{LoadedEcPoint, Loader},
    util::{
        arithmetic::{CurveAffine, Group, PrimeField},
        Itertools,
    },
};
use num_integer::Integer;
use std::{
    default::Default,
    iter::{self, Sum},
    mem::size_of,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Debug)]
/// Contains unevaluated multi-scalar multiplication.
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
    /// Initialize with a constant.
    pub fn constant(constant: L::LoadedScalar) -> Self {
        Msm {
            constant: Some(constant),
            ..Default::default()
        }
    }

    /// Initialize with a base.
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

    /// Evaluate multi-scalar multiplication.
    ///
    /// # Panic
    ///
    /// If given `gen` is `None` but there `constant` has some value.
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

    fn scale(&mut self, factor: &L::LoadedScalar) {
        if let Some(constant) = self.constant.as_mut() {
            *constant *= factor;
        }
        for scalar in self.scalars.iter_mut() {
            *scalar *= factor
        }
    }

    fn push<'b: 'a>(&mut self, scalar: L::LoadedScalar, base: &'b L::LoadedEcPoint) {
        if let Some(pos) = self.bases.iter().position(|exist| exist.eq(&base)) {
            self.scalars[pos] += &scalar;
        } else {
            self.scalars.push(scalar);
            self.bases.push(base);
        }
    }

    fn extend<'b: 'a>(&mut self, mut other: Msm<'b, C, L>) {
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

#[derive(Clone, Copy)]
enum Bucket<C: CurveAffine> {
    None,
    Affine(C),
    Projective(C::Curve),
}

impl<C: CurveAffine> Bucket<C> {
    fn add_assign(&mut self, rhs: &C) {
        *self = match *self {
            Bucket::None => Bucket::Affine(*rhs),
            Bucket::Affine(lhs) => Bucket::Projective(lhs + *rhs),
            Bucket::Projective(mut lhs) => {
                lhs += *rhs;
                Bucket::Projective(lhs)
            }
        }
    }

    fn add(self, mut rhs: C::Curve) -> C::Curve {
        match self {
            Bucket::None => rhs,
            Bucket::Affine(lhs) => {
                rhs += lhs;
                rhs
            }
            Bucket::Projective(lhs) => lhs + rhs,
        }
    }
}

fn multi_scalar_multiplication_serial<C: CurveAffine>(
    scalars: &[C::Scalar],
    bases: &[C],
    result: &mut C::Curve,
) {
    let scalars = scalars.iter().map(|scalar| scalar.to_repr()).collect_vec();
    let num_bytes = scalars[0].as_ref().len();
    let num_bits = 8 * num_bytes;

    let window_size = (scalars.len() as f64).ln().ceil() as usize + 2;
    let num_buckets = (1 << window_size) - 1;

    let windowed_scalar = |idx: usize, bytes: &<C::Scalar as PrimeField>::Repr| {
        let skip_bits = idx * window_size;
        let skip_bytes = skip_bits / 8;

        let mut value = [0; size_of::<usize>()];
        for (dst, src) in value.iter_mut().zip(bytes.as_ref()[skip_bytes..].iter()) {
            *dst = *src;
        }

        (usize::from_le_bytes(value) >> (skip_bits - (skip_bytes * 8))) & num_buckets
    };

    let num_window = Integer::div_ceil(&num_bits, &window_size);
    for idx in (0..num_window).rev() {
        for _ in 0..window_size {
            *result = result.double();
        }

        let mut buckets = vec![Bucket::None; num_buckets];

        for (scalar, base) in scalars.iter().zip(bases.iter()) {
            let scalar = windowed_scalar(idx, scalar);
            if scalar != 0 {
                buckets[scalar - 1].add_assign(base);
            }
        }

        let mut running_sum = C::Curve::identity();
        for bucket in buckets.into_iter().rev() {
            running_sum = bucket.add(running_sum);
            *result += &running_sum;
        }
    }
}

/// Multi-scalar multiplication algorithm copied from
/// <https://github.com/zcash/halo2/blob/main/halo2_proofs/src/arithmetic.rs>.
pub fn multi_scalar_multiplication<C: CurveAffine>(scalars: &[C::Scalar], bases: &[C]) -> C::Curve {
    assert_eq!(scalars.len(), bases.len());

    #[cfg(feature = "parallel")]
    {
        use crate::util::{current_num_threads, parallelize_iter};

        let num_threads = current_num_threads();
        if scalars.len() < num_threads {
            let mut result = C::Curve::identity();
            multi_scalar_multiplication_serial(scalars, bases, &mut result);
            return result;
        }

        let chunk_size = Integer::div_ceil(&scalars.len(), &num_threads);
        let mut results = vec![C::Curve::identity(); num_threads];
        parallelize_iter(
            scalars
                .chunks(chunk_size)
                .zip(bases.chunks(chunk_size))
                .zip(results.iter_mut()),
            |((scalars, bases), result)| {
                multi_scalar_multiplication_serial(scalars, bases, result);
            },
        );
        results
            .iter()
            .fold(C::Curve::identity(), |acc, result| acc + result)
    }
    #[cfg(not(feature = "parallel"))]
    {
        let mut result = C::Curve::identity();
        multi_scalar_multiplication_serial(scalars, bases, &mut result);
        result
    }
}
