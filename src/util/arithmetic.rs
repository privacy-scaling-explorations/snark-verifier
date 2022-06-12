use std::{
    cmp::Ordering,
    fmt::Debug,
    iter, mem,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

pub use ff::{Field, PrimeField};
pub use group::{Curve, Group, GroupEncoding};

pub trait GroupOps:
    Sized
    + Add<Output = Self>
    + Sub<Output = Self>
    + Neg<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + AddAssign
    + SubAssign
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
{
}

impl<T> GroupOps for T where
    T: Sized
        + Add<Output = Self>
        + Sub<Output = Self>
        + Neg<Output = Self>
        + for<'a> Add<&'a Self, Output = Self>
        + for<'a> Sub<&'a Self, Output = Self>
        + AddAssign
        + SubAssign
        + for<'a> AddAssign<&'a Self>
        + for<'a> SubAssign<&'a Self>
{
}

pub trait FieldOps:
    Sized
    + GroupOps
    + Mul<Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + MulAssign
    + for<'a> MulAssign<&'a Self>
{
    fn invert(&self) -> Option<Self>;
}

pub fn batch_invert_and_mul<F: PrimeField>(values: &mut [F], coeff: &F) {
    let products = values
        .iter()
        .filter(|value| !value.is_zero_vartime())
        .scan(F::one(), |acc, value| {
            *acc *= value;
            Some(*acc)
        })
        .collect::<Vec<_>>();

    let mut all_product_inv = products.last().unwrap().invert().unwrap() * coeff;

    for (value, product) in values
        .iter_mut()
        .rev()
        .filter(|value| !value.is_zero_vartime())
        .zip(products.into_iter().rev().skip(1).chain(Some(F::one())))
    {
        let mut inv = all_product_inv * product;
        mem::swap(value, &mut inv);
        all_product_inv *= inv;
    }
}

pub fn batch_invert<F: PrimeField>(values: &mut [F]) {
    batch_invert_and_mul(values, &F::one())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rotation(pub i32);

impl Rotation {
    pub fn cur() -> Self {
        Rotation(0)
    }

    pub fn prev() -> Self {
        Rotation(-1)
    }

    pub fn next() -> Self {
        Rotation(1)
    }
}

impl From<i32> for Rotation {
    fn from(rotation: i32) -> Self {
        Self(rotation)
    }
}

#[derive(Clone, Debug)]
pub struct Domain<F: PrimeField> {
    pub k: usize,
    pub n: usize,
    pub n_inv: F,
    pub gen: F,
    pub gen_inv: F,
}

impl<F: PrimeField> Domain<F> {
    pub fn new(k: usize) -> Self {
        assert!(k <= F::S as usize);

        let n = 1 << k;
        let n_inv = F::from(n as u64).invert().unwrap();
        let gen = iter::successors(Some(F::root_of_unity()), |acc| Some(acc.square()))
            .take(F::S as usize - k + 1)
            .last()
            .unwrap();
        let gen_inv = gen.invert().unwrap();

        Self {
            k,
            n,
            n_inv,
            gen,
            gen_inv,
        }
    }

    pub fn rotate_scalar(&self, scalar: F, rotation: Rotation) -> F {
        match rotation.0.cmp(&0) {
            Ordering::Equal => scalar,
            Ordering::Greater => scalar * self.gen.pow_vartime(&[rotation.0 as u64]),
            Ordering::Less => scalar * self.gen_inv.pow_vartime(&[(-rotation.0) as u64]),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Fraction<F> {
    numer: Option<F>,
    denom: F,
    inv: bool,
}

impl<F> Fraction<F> {
    pub fn new(numer: F, denom: F) -> Self {
        Self {
            numer: Some(numer),
            denom,
            inv: false,
        }
    }

    pub fn one_over(denom: F) -> Self {
        Self {
            numer: None,
            denom,
            inv: false,
        }
    }

    pub fn denom(&self) -> Option<&F> {
        if !self.inv {
            Some(&self.denom)
        } else {
            None
        }
    }

    pub fn denom_mut(&mut self) -> Option<&mut F> {
        if !self.inv {
            self.inv = true;
            Some(&mut self.denom)
        } else {
            None
        }
    }
}

impl<F: FieldOps + Clone> Fraction<F> {
    pub fn evaluate(&self) -> F {
        let denom = if self.inv {
            self.denom.clone()
        } else {
            self.denom.invert().unwrap()
        };
        self.numer
            .clone()
            .map(|numer| numer * &denom)
            .unwrap_or(denom)
    }
}
