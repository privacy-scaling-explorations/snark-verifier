use crate::{
    loader::Loader,
    pcs::{AccumulationStrategy, PolynomialCommitmentScheme, PreAccumulator},
    util::{arithmetic::CurveAffine, transcript::TranscriptRead},
    Error, Protocol,
};
use std::fmt::Debug;

mod plonk;

pub use plonk::{Plonk, PlonkProof};

pub trait PlonkVerifier<C, L, PCS, AS, T>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
    AS: AccumulationStrategy<C, L, PCS>,
    T: TranscriptRead<C, L>,
{
    type Proof: Debug;

    fn read_proof(
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>;

    fn succint_verify(
        svk: &PCS::SuccinctVerifyingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
        proof: &Self::Proof,
    ) -> Result<PCS::PreAccumulator, Error>;

    fn verify(
        svk: &PCS::SuccinctVerifyingKey,
        dk: &PCS::DecidingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<AS::Output, Error> {
        let proof = Self::read_proof(protocol, instances, transcript).unwrap();
        let accumulator = Self::succint_verify(svk, protocol, instances, transcript, &proof)
            .unwrap()
            .evaluate();
        AS::finalize(dk, accumulator)
    }
}
