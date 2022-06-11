use crate::util::{Curve, Field, PrimeField};
use std::{
    fmt::Debug,
    iter,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

pub mod native;

mod sealed {
    use crate::util::{Curve, PrimeField};

    pub trait LoadedEcPoint<C: Curve, L: super::Loader<C>> {
        fn loader(&self) -> &L;
    }

    pub trait LoadedScalar<F: PrimeField, L: super::ScalarLoader<F>> {
        fn loader(&self) -> &L;
    }
}

pub trait LoadedEcPoint<C: Curve>:
    'static
    + Eq
    + Clone
    + Debug
    + Send
    + Sync
    + Sized
    + Add<Output = Self>
    + Sub<Output = Self>
    + Neg<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + AddAssign
    + SubAssign
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + sealed::LoadedEcPoint<C, Self::Loader>
{
    type Loader: Loader<C, LoadedEcPoint = Self>;

    fn multi_scalar_multiplication(
        pairs: impl IntoIterator<Item = (Scalar<C, Self::Loader>, Self)>,
    ) -> Self;
}

pub trait LoadedScalar<F: PrimeField>:
    'static
    + Eq
    + Clone
    + Debug
    + Send
    + Sync
    + Sized
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + MulAssign
    + AddAssign
    + SubAssign
    + for<'a> MulAssign<&'a Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + sealed::LoadedScalar<F, Self::Loader>
{
    type Loader: ScalarLoader<F, LoadedScalar = Self>;

    fn sum_with_coeff_and_constant(values: &[(F, Self)], constant: &F) -> Self {
        assert!(!values.is_empty());

        let loader = values.first().unwrap().1.loader();
        values
            .iter()
            .fold(loader.load_const(constant), |acc, (coeff, value)| {
                acc + loader.load_const(coeff) * value
            })
    }

    fn sum_products_with_coeff_and_constant(values: &[(F, Self, Self)], constant: &F) -> Self {
        assert!(!values.is_empty());

        let loader = values.first().unwrap().1.loader();
        values
            .iter()
            .fold(loader.load_const(constant), |acc, (coeff, lhs, rhs)| {
                acc + loader.load_const(coeff) * lhs * rhs
            })
    }

    fn sum_with_coeff(values: &[(F, Self)]) -> Self {
        Self::sum_with_coeff_and_constant(values, &F::zero())
    }

    fn sum_with_const(values: &[Self], constant: &F) -> Self {
        Self::sum_with_coeff_and_constant(
            &values
                .iter()
                .map(|value| (F::one(), value.clone()))
                .collect::<Vec<_>>(),
            constant,
        )
    }

    fn sum(values: &[Self]) -> Self {
        Self::sum_with_const(values, &F::zero())
    }

    fn invert(&self) -> Option<Self>;

    fn pow_const(&self, mut exp: u64) -> Self {
        assert!(exp > 0);

        let mut base = self.clone();

        while exp & 1 == 0 {
            base *= base.clone();
            exp >>= 1;
        }

        let mut acc = base.clone();
        while exp > 1 {
            exp >>= 1;
            base *= base.clone();
            if exp & 1 == 1 {
                acc *= &base;
            }
        }
        acc
    }

    fn powers(&self, n: usize) -> Vec<Self> {
        iter::once(self.loader().load_one())
            .chain(
                iter::successors(Some(self.clone()), |power| Some(power.clone() * self))
                    .take(n - 1),
            )
            .collect::<Vec<_>>()
    }
}

pub trait EcPointLoader<C: Curve>: Debug {
    type LoadedEcPoint: LoadedEcPoint<C, Loader = Self>;

    fn ec_point_load_const(&self, value: &C) -> Self::LoadedEcPoint;

    fn ec_point_load_var(&self, value: &C) -> Self::LoadedEcPoint;

    fn ec_point_load_zero(&self) -> Self::LoadedEcPoint {
        self.ec_point_load_const(&C::identity())
    }

    fn ec_point_load_one(&self) -> Self::LoadedEcPoint {
        self.ec_point_load_const(&C::generator())
    }
}

pub trait ScalarLoader<F: PrimeField>: Debug {
    type LoadedScalar: LoadedScalar<F, Loader = Self>;

    fn load_const(&self, value: &F) -> Self::LoadedScalar;

    fn load_var(&self, value: &F) -> Self::LoadedScalar;

    fn load_zero(&self) -> Self::LoadedScalar {
        self.load_const(&F::zero())
    }

    fn load_one(&self) -> Self::LoadedScalar {
        self.load_const(&F::one())
    }
}

pub trait Loader<C: Curve>: EcPointLoader<C> + ScalarLoader<C::Scalar> + Clone {}

impl<C: Curve, T: EcPointLoader<C> + ScalarLoader<C::Scalar> + Clone> Loader<C> for T {}

#[derive(Clone, Debug)]
pub enum Scalar<C: Curve, L: Loader<C>> {
    Const(C::Scalar),
    Loaded(L::LoadedScalar),
}

impl<C: Curve, L: Loader<C>> Scalar<C, L> {
    pub fn zero() -> Self {
        Self::Const(C::Scalar::zero())
    }

    pub fn one() -> Self {
        Self::Const(C::Scalar::one())
    }
}

impl<C: Curve, L: Loader<C>> Add for Scalar<C, L> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        use sealed::LoadedScalar;
        match (self, rhs) {
            (Scalar::Const(lhs), Scalar::Const(rhs)) => Scalar::Const(lhs + rhs),
            (Scalar::Loaded(lhs), Scalar::Loaded(rhs)) => Scalar::Loaded(lhs + rhs),
            (Scalar::Const(constant), Scalar::Loaded(loaded))
            | (Scalar::Loaded(loaded), Scalar::Const(constant)) => {
                Scalar::Loaded(loaded.loader().load_const(&constant) + loaded)
            }
        }
    }
}

impl<C: Curve, L: Loader<C>> AddAssign for Scalar<C, L> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl<C: Curve, L: Loader<C>> Sub for Scalar<C, L> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl<C: Curve, L: Loader<C>> SubAssign for Scalar<C, L> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<C: Curve, L: Loader<C>> Mul for Scalar<C, L> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        use sealed::LoadedScalar;
        match (self, rhs) {
            (Scalar::Const(lhs), Scalar::Const(rhs)) => Scalar::Const(lhs * rhs),
            (Scalar::Loaded(lhs), Scalar::Loaded(rhs)) => Scalar::Loaded(lhs * rhs),
            (Scalar::Const(constant), Scalar::Loaded(loaded))
            | (Scalar::Loaded(loaded), Scalar::Const(constant)) => {
                Scalar::Loaded(loaded.loader().load_const(&constant) * loaded)
            }
        }
    }
}

impl<C: Curve, L: Loader<C>> MulAssign for Scalar<C, L> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl<C: Curve, L: Loader<C>> Neg for Scalar<C, L> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self {
            Scalar::Const(constant) => Scalar::Const(-constant),
            Scalar::Loaded(loaded) => Scalar::Loaded(-loaded),
        }
    }
}
