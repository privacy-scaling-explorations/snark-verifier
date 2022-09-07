use crate::{
    loader::Loader,
    pcs::{AccumulationStrategy, PolynomialCommitmentScheme, PreAccumulator},
    util::{arithmetic::CurveAffine, transcript::TranscriptRead},
    Error, Protocol,
};
use std::fmt::Debug;

mod plonk;

pub use plonk::{Plonk, PlonkProof};

pub trait PlonkVerifier<C, L, PCS, AS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
    AS: AccumulationStrategy<C, L, PCS>,
{
    type Proof: Debug;

    fn read_proof<T>(
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>;

    fn succint_verify(
        svk: &PCS::SuccinctVerifyingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<PCS::PreAccumulator, Error>;

    fn verify(
        svk: &PCS::SuccinctVerifyingKey,
        dk: &PCS::DecidingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<AS::Output, Error> {
        let accumulator = Self::succint_verify(svk, protocol, instances, proof)
            .unwrap()
            .evaluate();
        AS::finalize(dk, accumulator)
    }
}
