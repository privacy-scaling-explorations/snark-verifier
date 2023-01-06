//! Verifiers for (S)NARK.

use crate::{
    loader::Loader,
    util::{arithmetic::CurveAffine, transcript::TranscriptRead},
    Error,
};
use std::fmt::Debug;

pub mod plonk;

/// (S)NARK verifier for verifying a (S)NARK.
pub trait SnarkVerifier<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    /// Verifying key for subroutines if any.
    type VerifyingKey: Clone + Debug;
    /// Protocol specifying configuration of a (S)NARK.
    type Protocol: Clone + Debug;
    /// Structured proof read from transcript.
    type Proof: Clone + Debug;
    /// Output of verification.
    type Output: Clone + Debug;

    /// Read [`SnarkVerifier::Proof`] from transcript.
    fn read_proof<T>(
        vk: &Self::VerifyingKey,
        protocol: &Self::Protocol,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>;

    /// Verify [`SnarkVerifier::Proof`] and output [`SnarkVerifier::Output`].
    fn verify(
        vk: &Self::VerifyingKey,
        protocol: &Self::Protocol,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::Output, Error>;
}
