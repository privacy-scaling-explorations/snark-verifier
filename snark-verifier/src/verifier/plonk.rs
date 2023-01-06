//! Verifiers for [PLONK], currently there are [`PlonkSuccinctVerifier`] and
//! [`PlonkVerifier`] implemented and both are implemented assuming the used
//! [`PolynomialCommitmentScheme`] has [atomic] or [split] accumulation scheme
//! ([`PlonkVerifier`] is just [`PlonkSuccinctVerifier`] plus doing accumulator
//! deciding then returns accept/reject as ouput).
//!
//! [PLONK]: https://eprint.iacr.org/2019/953
//! [atomic]: https://eprint.iacr.org/2020/499
//! [split]: https://eprint.iacr.org/2020/1618

use crate::{
    cost::{Cost, CostEstimation},
    loader::Loader,
    pcs::{
        AccumulationDecider, AccumulationScheme, AccumulatorEncoding, PolynomialCommitmentScheme,
        Query,
    },
    util::{arithmetic::CurveAffine, transcript::TranscriptRead},
    verifier::{plonk::protocol::CommonPolynomialEvaluation, SnarkVerifier},
    Error,
};
use std::{iter, marker::PhantomData};

mod proof;
pub(crate) mod protocol;

pub use proof::PlonkProof;
pub use protocol::PlonkProtocol;

/// Verifier that verifies the cheap part of PLONK and ouput the accumulator.
#[derive(Debug)]
pub struct PlonkSuccinctVerifier<AS, AE = PhantomData<AS>>(PhantomData<(AS, AE)>);

impl<C, L, AS, AE> SnarkVerifier<C, L> for PlonkSuccinctVerifier<AS, AE>
where
    C: CurveAffine,
    L: Loader<C>,
    AS: AccumulationScheme<C, L> + PolynomialCommitmentScheme<C, L, Output = AS::Accumulator>,
    AE: AccumulatorEncoding<C, L, Accumulator = AS::Accumulator>,
{
    type VerifyingKey = <AS as PolynomialCommitmentScheme<C, L>>::VerifyingKey;
    type Protocol = PlonkProtocol<C, L>;
    type Proof = PlonkProof<C, L, AS>;
    type Output = Vec<AE::Accumulator>;

    fn read_proof<T>(
        svk: &Self::VerifyingKey,
        protocol: &Self::Protocol,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>,
    {
        PlonkProof::read::<T, AE>(svk, protocol, instances, transcript)
    }

    fn verify(
        svk: &Self::VerifyingKey,
        protocol: &Self::Protocol,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::Output, Error> {
        let common_poly_eval = {
            let mut common_poly_eval =
                CommonPolynomialEvaluation::new(&protocol.domain, protocol.langranges(), &proof.z);

            L::batch_invert(common_poly_eval.denoms());
            common_poly_eval.evaluate();

            common_poly_eval
        };

        let mut evaluations = proof.evaluations(protocol, instances, &common_poly_eval)?;
        let commitments = proof.commitments(protocol, &common_poly_eval, &mut evaluations)?;
        let queries = proof.queries(protocol, evaluations);

        let accumulator = <AS as PolynomialCommitmentScheme<C, L>>::verify(
            svk,
            &commitments,
            &proof.z,
            &queries,
            &proof.pcs,
        )?;

        let accumulators = iter::empty()
            .chain(Some(accumulator))
            .chain(proof.old_accumulators.iter().cloned())
            .collect();

        Ok(accumulators)
    }
}

/// Verifier that first verifies the cheap part of PLONK, then decides
/// accumulator and returns accept/reject as ouput.
#[derive(Debug)]
pub struct PlonkVerifier<AS, AE = PhantomData<AS>>(PhantomData<(AS, AE)>);

impl<C, L, AS, AE> SnarkVerifier<C, L> for PlonkVerifier<AS, AE>
where
    C: CurveAffine,
    L: Loader<C>,
    AS: AccumulationDecider<C, L> + PolynomialCommitmentScheme<C, L, Output = AS::Accumulator>,
    AS::DecidingKey: AsRef<<AS as PolynomialCommitmentScheme<C, L>>::VerifyingKey>,
    AE: AccumulatorEncoding<C, L, Accumulator = AS::Accumulator>,
{
    type VerifyingKey = AS::DecidingKey;
    type Protocol = PlonkProtocol<C, L>;
    type Proof = PlonkProof<C, L, AS>;
    type Output = ();

    fn read_proof<T>(
        vk: &Self::VerifyingKey,
        protocol: &Self::Protocol,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>,
    {
        PlonkProof::read::<T, AE>(vk.as_ref(), protocol, instances, transcript)
    }

    fn verify(
        vk: &Self::VerifyingKey,
        protocol: &Self::Protocol,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::Output, Error> {
        let accumulators =
            PlonkSuccinctVerifier::<AS, AE>::verify(vk.as_ref(), protocol, instances, proof)?;
        AS::decide_all(vk, accumulators)
    }
}

impl<C, L, AS, AE> CostEstimation<(C, L)> for PlonkSuccinctVerifier<AS, AE>
where
    C: CurveAffine,
    L: Loader<C>,
    AS: AccumulationScheme<C, L>
        + PolynomialCommitmentScheme<C, L, Output = AS::Accumulator>
        + CostEstimation<C, Input = Vec<Query<C::Scalar>>>,
{
    type Input = PlonkProtocol<C, L>;

    fn estimate_cost(protocol: &PlonkProtocol<C, L>) -> Cost {
        let plonk_cost = {
            let num_accumulator = protocol.accumulator_indices.len();
            let num_instance = protocol.num_instance.iter().sum();
            let num_commitment =
                protocol.num_witness.iter().sum::<usize>() + protocol.quotient.num_chunk();
            let num_evaluation = protocol.evaluations.len();
            let num_msm = protocol.preprocessed.len() + num_commitment + 1 + 2 * num_accumulator;
            Cost {
                num_instance,
                num_commitment,
                num_evaluation,
                num_msm,
                ..Default::default()
            }
        };
        let pcs_cost = {
            let queries = PlonkProof::<C, L, AS>::empty_queries(protocol);
            AS::estimate_cost(&queries)
        };
        plonk_cost + pcs_cost
    }
}

impl<C, L, AS, AE> CostEstimation<(C, L)> for PlonkVerifier<AS, AE>
where
    C: CurveAffine,
    L: Loader<C>,
    AS: AccumulationScheme<C, L>
        + PolynomialCommitmentScheme<C, L, Output = AS::Accumulator>
        + CostEstimation<C, Input = Vec<Query<C::Scalar>>>,
{
    type Input = PlonkProtocol<C, L>;

    fn estimate_cost(protocol: &PlonkProtocol<C, L>) -> Cost {
        PlonkSuccinctVerifier::<AS, AE>::estimate_cost(protocol)
            + Cost {
                num_pairing: 2,
                ..Default::default()
            }
    }
}
