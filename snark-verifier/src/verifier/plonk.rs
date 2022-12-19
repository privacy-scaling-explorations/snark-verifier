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

pub struct PlonkSuccinctVerifier<AS, AE = PhantomData<AS>>(PhantomData<(AS, AE)>);

impl<C, L, AS, AE> SnarkVerifier<C, L> for PlonkSuccinctVerifier<AS, AE>
where
    C: CurveAffine,
    L: Loader<C>,
    AS: AccumulationScheme<C, L>
        + PolynomialCommitmentScheme<C, L, Output = <AS as AccumulationScheme<C, L>>::Accumulator>,
    AE: AccumulatorEncoding<C, L, Accumulator = <AS as AccumulationScheme<C, L>>::Accumulator>,
{
    type VerifyingKey = <AS as PolynomialCommitmentScheme<C, L>>::VerifyingKey;
    type Protocol = PlonkProtocol<C, L>;
    type Proof = PlonkProof<C, L, AS, AE>;
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
        PlonkProof::read::<T>(svk, protocol, instances, transcript)
    }

    fn verify(
        svk: &Self::VerifyingKey,
        protocol: &Self::Protocol,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::Output, Error> {
        let common_poly_eval = {
            let mut common_poly_eval = CommonPolynomialEvaluation::new(
                &protocol.domain,
                langranges(protocol, instances),
                &proof.z,
            );

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

pub struct PlonkVerifier<AS, AE = PhantomData<AS>>(PhantomData<(AS, AE)>);

impl<C, L, AS, AE> SnarkVerifier<C, L> for PlonkVerifier<AS, AE>
where
    C: CurveAffine,
    L: Loader<C>,
    AS: AccumulationDecider<C, L>
        + PolynomialCommitmentScheme<C, L, Output = <AS as AccumulationScheme<C, L>>::Accumulator>,
    AS::DecidingKey: AsRef<<AS as PolynomialCommitmentScheme<C, L>>::VerifyingKey>,
    AE: AccumulatorEncoding<C, L, Accumulator = <AS as AccumulationScheme<C, L>>::Accumulator>,
{
    type VerifyingKey = AS::DecidingKey;
    type Protocol = PlonkProtocol<C, L>;
    type Proof = PlonkProof<C, L, AS, AE>;
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
        PlonkProof::read::<T>(vk.as_ref(), protocol, instances, transcript)
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
    AS: PolynomialCommitmentScheme<C, L> + CostEstimation<C, Input = Vec<Query<C::Scalar>>>,
    AE: AccumulatorEncoding<C, L>,
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
            Cost::new(num_instance, num_commitment, num_evaluation, num_msm)
        };
        let pcs_cost = {
            let queries = PlonkProof::<C, L, AS, AE>::empty_queries(protocol);
            AS::estimate_cost(&queries)
        };
        plonk_cost + pcs_cost
    }
}

fn langranges<C, L>(
    protocol: &PlonkProtocol<C, L>,
    instances: &[Vec<L::LoadedScalar>],
) -> impl IntoIterator<Item = i32>
where
    C: CurveAffine,
    L: Loader<C>,
{
    let instance_eval_lagrange = protocol.instance_committing_key.is_none().then(|| {
        let queries = {
            let offset = protocol.preprocessed.len();
            let range = offset..offset + protocol.num_instance.len();
            protocol
                .quotient
                .numerator
                .used_query()
                .into_iter()
                .filter(move |query| range.contains(&query.poly))
        };
        let (min_rotation, max_rotation) = queries.fold((0, 0), |(min, max), query| {
            if query.rotation.0 < min {
                (query.rotation.0, max)
            } else if query.rotation.0 > max {
                (min, query.rotation.0)
            } else {
                (min, max)
            }
        });
        let max_instance_len = instances
            .iter()
            .map(|instance| instance.len())
            .max()
            .unwrap_or_default();
        -max_rotation..max_instance_len as i32 + min_rotation.abs()
    });
    protocol
        .quotient
        .numerator
        .used_langrange()
        .into_iter()
        .chain(instance_eval_lagrange.into_iter().flatten())
}
