use crate::util::{Curve, FieldOps, GroupOps, PrimeField};
use std::{fmt::Debug, iter};

#[cfg(feature = "evm")]
pub mod evm;

pub mod native;

pub(super) mod sealed {
    use crate::util::{Curve, PrimeField};

    pub trait LoadedEcPoint<C: Curve, L: super::Loader<C>> {
        fn loader(&self) -> &L;
    }

    pub trait LoadedScalar<F: PrimeField, L: super::ScalarLoader<F>> {
        fn loader(&self) -> &L;
    }
}

pub trait LoadedEcPoint<C: Curve>:
    'static + Clone + Debug + GroupOps + sealed::LoadedEcPoint<C, Self::Loader>
{
    type Loader: Loader<C, LoadedEcPoint = Self>;

    fn multi_scalar_multiplication(
        pairs: impl IntoIterator<
            Item = (
                <Self::Loader as ScalarLoader<C::Scalar>>::LoadedScalar,
                Self,
            ),
        >,
    ) -> Self;
}

pub trait LoadedScalar<F: PrimeField>:
    'static + Clone + Debug + FieldOps + sealed::LoadedScalar<F, Self::Loader>
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

    fn invert(&self) -> Option<Self> {
        FieldOps::invert(self)
    }

    fn batch_invert<'a>(values: impl IntoIterator<Item = &'a mut Self>) {
        values
            .into_iter()
            .for_each(|value| *value = LoadedScalar::invert(value).unwrap_or_else(|| value.clone()))
    }

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
