use crate::util::{Curve, FieldOps, GroupOps, PrimeField};
use std::{fmt::Debug, iter};

pub mod native;

#[cfg(feature = "evm")]
pub mod evm;

pub trait LoadedEcPoint<C: Curve>: Clone + Debug + GroupOps + PartialEq {
    type Loader: Loader<C, LoadedEcPoint = Self>;

    fn loader(&self) -> &Self::Loader;

    fn multi_scalar_multiplication(
        pairs: impl IntoIterator<
            Item = (
                <Self::Loader as ScalarLoader<C::Scalar>>::LoadedScalar,
                Self,
            ),
        >,
    ) -> Self;
}

pub trait LoadedScalar<F: PrimeField>: Clone + Debug + FieldOps {
    type Loader: ScalarLoader<F, LoadedScalar = Self>;

    fn loader(&self) -> &Self::Loader;

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

    fn square(&self) -> Self {
        self.clone() * self
    }

    fn invert(&self) -> Option<Self> {
        FieldOps::invert(self)
    }

    fn batch_invert<'a>(values: impl IntoIterator<Item = &'a mut Self>)
    where
        Self: 'a,
    {
        values
            .into_iter()
            .for_each(|value| *value = LoadedScalar::invert(value).unwrap_or_else(|| value.clone()))
    }

    fn pow_const(&self, mut exp: u64) -> Self {
        assert!(exp > 0);

        let mut base = self.clone();

        while exp & 1 == 0 {
            base = base.square();
            exp >>= 1;
        }

        let mut acc = base.clone();
        while exp > 1 {
            exp >>= 1;
            base = base.square();
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

pub trait EcPointLoader<C: Curve> {
    type LoadedEcPoint: LoadedEcPoint<C, Loader = Self>;

    fn ec_point_load_const(&self, value: &C) -> Self::LoadedEcPoint;

    fn ec_point_load_zero(&self) -> Self::LoadedEcPoint {
        self.ec_point_load_const(&C::identity())
    }

    fn ec_point_load_one(&self) -> Self::LoadedEcPoint {
        self.ec_point_load_const(&C::generator())
    }
}

pub trait ScalarLoader<F: PrimeField> {
    type LoadedScalar: LoadedScalar<F, Loader = Self>;

    fn load_const(&self, value: &F) -> Self::LoadedScalar;

    fn load_zero(&self) -> Self::LoadedScalar {
        self.load_const(&F::zero())
    }

    fn load_one(&self) -> Self::LoadedScalar {
        self.load_const(&F::one())
    }
}

pub trait Loader<C: Curve>: EcPointLoader<C> + ScalarLoader<C::Scalar> + Clone {}

impl<C: Curve, T: EcPointLoader<C> + ScalarLoader<C::Scalar> + Clone> Loader<C> for T {}
