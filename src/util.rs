mod arithmetic;
mod expression;
mod transcript;

pub use arithmetic::{
    batch_invert, batch_invert_and_mul, fe_from_limbs, fe_to_limbs, BatchInvert, Curve, Domain,
    Field, FieldOps, Fraction, Group, GroupEncoding, GroupOps, PrimeCurveAffine, PrimeField,
    Rotation, UncompressedEncoding,
};
pub use expression::{CommonPolynomial, CommonPolynomialEvaluation, Expression, Query};
pub use transcript::{Transcript, TranscriptRead};

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
