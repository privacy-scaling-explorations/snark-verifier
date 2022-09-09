use crate::{
    loader::Loader,
    util::{
        arithmetic::{CurveAffine, FieldExt},
        msm::Msm,
        transcript::TranscriptRead,
    },
    Error,
};
use std::{fmt::Debug, ops::AddAssign};

pub mod kzg;

pub trait PreAccumulator: Sized + Clone + Debug {
    type Accumulator;

    fn evaluate(self) -> Self::Accumulator;
}

pub trait AccumulationStrategy<C, L, PCS>: Clone + Debug
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
{
    type Output: Debug;

    fn extract_accumulators(
        accumulator_indices: &[Vec<(usize, usize)>],
        instances: &[Vec<L::LoadedScalar>],
    ) -> Result<Vec<PCS::Accumulator>, Error>;

    fn finalize(_: &PCS::DecidingKey, _: PCS::Accumulator) -> Result<Self::Output, Error> {
        unimplemented!()
    }
}

#[derive(Clone, Debug)]
pub struct Query<F: FieldExt, T = ()> {
    pub poly: usize,
    pub shift: F,
    pub evaluation: T,
}

impl<F: FieldExt> Query<F> {
    pub fn with_evaluation<T>(self, evaluation: T) -> Query<F, T> {
        Query {
            poly: self.poly,
            shift: self.shift,
            evaluation,
        }
    }
}

pub trait PolynomialCommitmentScheme<C, L>: Clone + Debug
where
    C: CurveAffine,
    L: Loader<C>,
{
    type SuccinctVerifyingKey: Clone + Debug;
    type DecidingKey: Clone + Debug;
    type Proof: Clone + Debug;
    type PreAccumulator: PreAccumulator<Accumulator = Self::Accumulator>
        + for<'a> AddAssign<&'a Self::PreAccumulator>
        + for<'a> AddAssign<&'a (L::LoadedScalar, Self::Accumulator)>;
    type Accumulator: Clone + Debug;

    fn read_proof<T>(
        queries: &[Query<C::Scalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>;

    fn succinct_verify(
        svk: &Self::SuccinctVerifyingKey,
        commitments: &[Msm<C, L>],
        point: &L::LoadedScalar,
        queries: &[Query<C::Scalar, L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::PreAccumulator, Error>;
}
