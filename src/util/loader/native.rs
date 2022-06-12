use crate::util::{
    loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, ScalarLoader},
    Curve, PrimeField,
};
use lazy_static::lazy_static;
use std::fmt::Debug;

lazy_static! {
    static ref LOADER: NativeLoader = NativeLoader;
}

impl<C: Curve> super::sealed::LoadedEcPoint<C, NativeLoader> for C {
    fn loader(&self) -> &NativeLoader {
        &LOADER
    }
}

impl<C: Curve> LoadedEcPoint<C> for C {
    type Loader = NativeLoader;

    fn multi_scalar_multiplication(pairs: impl IntoIterator<Item = (C::Scalar, C)>) -> Self {
        pairs
            .into_iter()
            .map(|(scalar, base)| base * scalar)
            .reduce(|acc, value| acc + value)
            .unwrap()
    }
}

impl<F: PrimeField> super::sealed::LoadedScalar<F, NativeLoader> for F {
    fn loader(&self) -> &NativeLoader {
        &LOADER
    }
}

impl<F: PrimeField> LoadedScalar<F> for F {
    type Loader = NativeLoader;

    fn invert(&self) -> Option<Self> {
        self.invert().into()
    }
}

#[derive(Clone, Debug)]
pub struct NativeLoader;

impl<C: Curve> EcPointLoader<C> for NativeLoader {
    type LoadedEcPoint = C;

    fn ec_point_load_const(&self, value: &C) -> Self::LoadedEcPoint {
        *value
    }

    fn ec_point_load_var(&self, value: &C) -> Self::LoadedEcPoint {
        *value
    }
}

impl<F: PrimeField> ScalarLoader<F> for NativeLoader {
    type LoadedScalar = F;

    fn load_const(&self, value: &F) -> Self::LoadedScalar {
        *value
    }

    fn load_var(&self, value: &F) -> Self::LoadedScalar {
        *value
    }
}
