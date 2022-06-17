use crate::util::{
    loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, ScalarLoader},
    Curve, FieldOps, PrimeField,
};
use lazy_static::lazy_static;
use std::fmt::Debug;

lazy_static! {
    static ref LOADER: NativeLoader = NativeLoader;
}

impl<C: Curve> LoadedEcPoint<C> for C {
    type Loader = NativeLoader;

    fn loader(&self) -> &NativeLoader {
        &LOADER
    }

    fn multi_scalar_multiplication(pairs: impl IntoIterator<Item = (C::Scalar, C)>) -> Self {
        pairs
            .into_iter()
            .map(|(scalar, base)| base * scalar)
            .reduce(|acc, value| acc + value)
            .unwrap()
    }
}

impl<F: PrimeField> FieldOps for F {
    fn invert(&self) -> Option<F> {
        self.invert().into()
    }
}

impl<F: PrimeField> LoadedScalar<F> for F {
    type Loader = NativeLoader;

    fn loader(&self) -> &NativeLoader {
        &LOADER
    }
}

#[derive(Clone, Debug)]
pub struct NativeLoader;

impl<C: Curve> EcPointLoader<C> for NativeLoader {
    type LoadedEcPoint = C;

    fn ec_point_load_const(&self, value: &C) -> Self::LoadedEcPoint {
        *value
    }
}

impl<F: PrimeField> ScalarLoader<F> for NativeLoader {
    type LoadedScalar = F;

    fn load_const(&self, value: &F) -> Self::LoadedScalar {
        *value
    }
}
