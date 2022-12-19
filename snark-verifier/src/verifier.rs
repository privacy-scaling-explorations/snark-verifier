use crate::{
    loader::Loader,
    util::{arithmetic::CurveAffine, transcript::TranscriptRead},
    Error,
};
use std::fmt::Debug;

pub mod plonk;

pub trait SnarkVerifier<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    type VerifyingKey: Clone + Debug;
    type Protocol: Clone + Debug;
    type Proof: Clone + Debug;
    type Output: Clone + Debug;

    fn read_proof<T>(
        vk: &Self::VerifyingKey,
        protocol: &Self::Protocol,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>;

    fn verify(
        vk: &Self::VerifyingKey,
        protocol: &Self::Protocol,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::Output, Error>;
}
