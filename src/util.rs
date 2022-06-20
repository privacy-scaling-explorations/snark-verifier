mod arithmetic;
mod expression;

pub mod loader;
pub use arithmetic::{
    batch_invert, batch_invert_and_mul, Curve, Domain, Field, FieldOps, Fraction, Group,
    GroupEncoding, GroupOps, PrimeCurveAffine, PrimeField, Rotation, UncompressedEncoding,
};
#[cfg(feature = "evm")]
pub use arithmetic::{field_to_u256, u256_to_field};
pub use expression::{CommonPolynomial, CommonPolynomialEvaluation, Expression, Query};

#[macro_export]
macro_rules! hex {
    ($bytes:expr) => {
        hex::encode(
            $bytes
                .iter()
                .position(|byte| *byte != 0)
                .map_or(vec![0], |pos| $bytes.into_iter().skip(pos).collect()),
        )
    };
}

#[macro_export]
macro_rules! collect_slice {
    ($vec:ident) => {
        let $vec = $vec.iter().map(|vec| vec.as_slice()).collect::<Vec<_>>();
    };
    ($vec:ident, 2) => {
        let $vec = $vec
            .iter()
            .map(|vec| {
                collect_slice!(vec);
                vec
            })
            .collect::<Vec<_>>();
        let $vec = $vec.iter().map(|vec| vec.as_slice()).collect::<Vec<_>>();
    };
}
