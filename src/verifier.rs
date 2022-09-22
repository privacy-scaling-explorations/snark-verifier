use crate::{
    loader::Loader,
    pcs::{Decider, PolynomialCommitmentScheme},
    util::{arithmetic::CurveAffine, transcript::TranscriptRead},
    Error, Protocol,
};
use std::fmt::Debug;

mod plonk;

pub use plonk::{Plonk, PlonkProof};

pub trait PlonkVerifier<C, L, PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
{
    type Proof: Clone + Debug;

    fn read_proof<T>(
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>;

    fn succinct_verify(
        svk: &PCS::SuccinctVerifyingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Vec<PCS::Accumulator>, Error>;

    fn verify(
        svk: &PCS::SuccinctVerifyingKey,
        dk: &PCS::DecidingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<PCS::Output, Error>
    where
        PCS: Decider<C, L>,
    {
        let accumulators = Self::succinct_verify(svk, protocol, instances, proof)?;
        let output = PCS::decide_all(dk, accumulators);
        Ok(output)
    }
}
