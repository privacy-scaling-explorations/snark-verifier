use crate::{
    loader::{native::NativeLoader, Loader},
    util::{
        arithmetic::{CurveAffine, PrimeField},
        msm::Msm,
        transcript::{TranscriptRead, TranscriptWrite},
    },
    Error,
};
use rand::Rng;
use std::{fmt::Debug, marker::PhantomData};

pub mod ipa;
pub mod kzg;

#[derive(Clone, Debug)]
pub struct Query<F: PrimeField, T = ()> {
    pub poly: usize,
    pub shift: F,
    pub eval: T,
}

impl<F: PrimeField> Query<F> {
    pub fn with_evaluation<T>(self, eval: T) -> Query<F, T> {
        Query {
            poly: self.poly,
            shift: self.shift,
            eval,
        }
    }
}

pub trait PolynomialCommitmentScheme<C, L>: Clone + Debug
where
    C: CurveAffine,
    L: Loader<C>,
{
    type VerifyingKey: Clone + Debug;
    type Proof: Clone + Debug;
    type Output: Clone + Debug;

    fn read_proof<T>(
        vk: &Self::VerifyingKey,
        queries: &[Query<C::Scalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>;

    fn verify(
        vk: &Self::VerifyingKey,
        commitments: &[Msm<C, L>],
        point: &L::LoadedScalar,
        queries: &[Query<C::Scalar, L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::Output, Error>;
}

pub trait AccumulationScheme<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    type Accumulator: Clone + Debug;
    type VerifyingKey: Clone + Debug;
    type Proof: Clone + Debug;

    fn read_proof<T>(
        vk: &Self::VerifyingKey,
        instances: &[Self::Accumulator],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>;

    fn verify(
        vk: &Self::VerifyingKey,
        instances: &[Self::Accumulator],
        proof: &Self::Proof,
    ) -> Result<Self::Accumulator, Error>;
}

pub trait AccumulationDecider<C, L>: AccumulationScheme<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    type DecidingKey: Clone + Debug;

    fn decide(dk: &Self::DecidingKey, accumulator: Self::Accumulator) -> Result<(), Error>;

    fn decide_all(
        dk: &Self::DecidingKey,
        accumulators: Vec<Self::Accumulator>,
    ) -> Result<(), Error>;
}

pub trait AccumulationSchemeProver<C>: AccumulationScheme<C, NativeLoader>
where
    C: CurveAffine,
{
    type ProvingKey: Clone + Debug;

    fn create_proof<T, R>(
        pk: &Self::ProvingKey,
        instances: &[Self::Accumulator],
        transcript: &mut T,
        rng: R,
    ) -> Result<Self::Accumulator, Error>
    where
        T: TranscriptWrite<C>,
        R: Rng;
}

pub trait AccumulatorEncoding<C, L>: Clone + Debug
where
    C: CurveAffine,
    L: Loader<C>,
{
    type Accumulator: Clone + Debug;

    fn from_repr(repr: &[&L::LoadedScalar]) -> Result<Self::Accumulator, Error>;
}

impl<C, L, PCS> AccumulatorEncoding<C, L> for PhantomData<PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
{
    type Accumulator = PCS::Output;

    fn from_repr(_: &[&L::LoadedScalar]) -> Result<Self::Accumulator, Error> {
        unimplemented!()
    }
}
