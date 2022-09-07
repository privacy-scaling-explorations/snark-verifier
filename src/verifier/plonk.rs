use crate::{
    cost::{Cost, CostEstimation},
    loader::{native::NativeLoader, LoadedScalar, Loader},
    pcs::{self, AccumulationStrategy, PolynomialCommitmentScheme},
    util::{
        arithmetic::{CurveAffine, Field, Rotation},
        expression::{CommonPolynomial, CommonPolynomialEvaluation, Expression, Query},
        msm::Msm,
        transcript::TranscriptRead,
        Itertools,
    },
    verifier::PlonkVerifier,
    Error, Protocol,
};
use std::{collections::HashMap, iter, marker::PhantomData};

pub struct Plonk<AS>(PhantomData<AS>);

impl<C, L, PCS, AS, T> PlonkVerifier<C, L, PCS, AS, T> for Plonk<AS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
    AS: AccumulationStrategy<C, L, PCS>,
    T: TranscriptRead<C, L>,
{
    type Proof = PlonkProof<C, L, PCS>;

    fn read_proof(
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error> {
        PlonkProof::read(protocol, instances, transcript)
    }

    fn succint_verify(
        svk: &PCS::SuccinctVerifyingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
        proof: &Self::Proof,
    ) -> Result<PCS::PreAccumulator, Error> {
        let common_poly_eval = {
            let mut common_poly_eval = CommonPolynomialEvaluation::new(
                &protocol.domain,
                langranges(protocol, instances),
                &proof.z,
            );

            L::LoadedScalar::batch_invert(common_poly_eval.denoms());
            common_poly_eval.evaluate();

            common_poly_eval
        };

        let commitments = proof.commitments(protocol, &common_poly_eval);
        let queries = proof.queries(protocol, instances, &common_poly_eval)?;

        let mut accumulator =
            PCS::succinct_verify(svk, &commitments, &proof.z, &queries, &proof.pcs)?;
        for old_accumulator in AS::extract_accumulators(&protocol.accumulator_indices, instances)? {
            accumulator += (transcript.squeeze_challenge(), old_accumulator);
        }
        Ok(accumulator)
    }
}

#[derive(Debug)]
pub struct PlonkProof<C, L, PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
{
    auxiliaries: Vec<L::LoadedEcPoint>,
    challenges: Vec<L::LoadedScalar>,
    alpha: L::LoadedScalar,
    quotients: Vec<L::LoadedEcPoint>,
    z: L::LoadedScalar,
    evaluations: Vec<L::LoadedScalar>,
    pcs: PCS::Proof,
}

impl<C, L, PCS> PlonkProof<C, L, PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
{
    fn read<T>(
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self, Error>
    where
        T: TranscriptRead<C, L>,
    {
        let loader = transcript.loader();
        transcript.common_scalar(&loader.load_const(&protocol.transcript_initial_state))?;

        if protocol.num_instance
            != instances
                .iter()
                .map(|instances| instances.len())
                .collect_vec()
        {
            return Err(Error::InvalidInstances);
        }
        for instances in instances.iter() {
            for instance in instances.iter() {
                transcript.common_scalar(instance)?;
            }
        }

        let (auxiliaries, challenges) = {
            let (auxiliaries, challenges) = protocol
                .num_witness
                .iter()
                .zip(protocol.num_challenge.iter())
                .map(|(&n, &m)| {
                    Ok((
                        transcript.read_n_ec_points(n)?,
                        transcript.squeeze_n_challenges(m),
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?
                .into_iter()
                .unzip::<_, _, Vec<_>, Vec<_>>();

            (
                auxiliaries.into_iter().flatten().collect_vec(),
                challenges.into_iter().flatten().collect_vec(),
            )
        };

        let alpha = transcript.squeeze_challenge();
        let quotients = {
            let max_degree = protocol
                .constraints
                .iter()
                .map(Expression::degree)
                .max()
                .unwrap();
            transcript.read_n_ec_points(max_degree - 1)?
        };

        let z = transcript.squeeze_challenge();
        let evaluations = transcript.read_n_scalars(protocol.evaluations.len())?;

        let pcs = PCS::read_proof(&Self::empty_queries(protocol), transcript)?;

        Ok(Self {
            auxiliaries,
            challenges,
            alpha,
            quotients,
            z,
            evaluations,
            pcs,
        })
    }

    fn empty_queries(protocol: &Protocol<C>) -> Vec<pcs::Query<C::Scalar>> {
        protocol
            .queries
            .iter()
            .map(|query| pcs::Query {
                poly: query.poly,
                shift: protocol
                    .domain
                    .rotate_scalar(C::Scalar::one(), query.rotation),
                evaluation: (),
            })
            .collect()
    }

    fn commitments(
        &self,
        protocol: &Protocol<C>,
        common_poly_eval: &CommonPolynomialEvaluation<C, L>,
    ) -> Vec<Msm<C, L>> {
        let loader = common_poly_eval.zn().loader();
        iter::empty()
            .chain(
                protocol
                    .preprocessed
                    .iter()
                    .map(|value| Msm::base(loader.ec_point_load_const(value))),
            )
            .chain(iter::repeat_with(Default::default).take(protocol.num_instance.len()))
            .chain(self.auxiliaries.iter().cloned().map(Msm::base))
            .chain(Some(
                common_poly_eval
                    .zn()
                    .powers(self.quotients.len())
                    .into_iter()
                    .zip(self.quotients.iter().cloned().map(Msm::base))
                    .map(|(coeff, piece)| piece * &coeff)
                    .sum(),
            ))
            .collect()
    }

    fn queries(
        &self,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        common_poly_eval: &CommonPolynomialEvaluation<C, L>,
    ) -> Result<Vec<pcs::Query<C::Scalar, L::LoadedScalar>>, Error> {
        let loader = common_poly_eval.zn().loader();
        let instance_evaluations = instances.iter().map(|instances| {
            loader.sum_products(
                &instances
                    .iter()
                    .enumerate()
                    .map(|(i, instance)| {
                        (
                            common_poly_eval.get(CommonPolynomial::Lagrange(i as i32)),
                            instance,
                        )
                    })
                    .collect_vec(),
            )
        });

        let mut evaluations = HashMap::<Query, L::LoadedScalar>::from_iter(
            iter::empty()
                .chain(
                    instance_evaluations
                        .into_iter()
                        .enumerate()
                        .map(|(i, evaluation)| {
                            (
                                Query {
                                    poly: protocol.preprocessed.len() + i,
                                    rotation: Rotation::cur(),
                                },
                                evaluation,
                            )
                        }),
                )
                .chain(
                    protocol
                        .evaluations
                        .iter()
                        .cloned()
                        .zip(self.evaluations.iter().cloned()),
                ),
        );

        let mut quotient_evaluation = {
            let powers_of_alpha = self.alpha.powers(protocol.constraints.len());
            let constraint_evaluations = protocol
                .constraints
                .iter()
                .map(|constraint| {
                    constraint.evaluate(
                        &|scalar| Ok(loader.load_const(&scalar)),
                        &|poly| Ok(common_poly_eval.get(poly).clone()),
                        &|index| {
                            evaluations
                                .get(&index)
                                .cloned()
                                .ok_or(Error::MissingQuery(index))
                        },
                        &|index| {
                            self.challenges
                                .get(index)
                                .cloned()
                                .ok_or(Error::MissingChallenge(index))
                        },
                        &|a| a.map(|a| -a),
                        &|a, b| a.and_then(|a| Ok(a + b?)),
                        &|a, b| a.and_then(|a| Ok(a * b?)),
                        &|a, scalar| a.map(|a| a * loader.load_const(&scalar)),
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?;

            Some(
                loader.sum_products(
                    &powers_of_alpha
                        .iter()
                        .rev()
                        .zip(constraint_evaluations.iter())
                        .collect_vec(),
                ) * common_poly_eval.zn_minus_one_inv(),
            )
        };

        let evaluations = protocol.queries.iter().map(|query| {
            evaluations
                .remove(query)
                .or_else(|| quotient_evaluation.take())
                .unwrap()
        });

        Ok(Self::empty_queries(protocol)
            .into_iter()
            .zip(evaluations)
            .map(|(query, evaluation)| query.with_evaluation(evaluation))
            .collect())
    }
}

impl<C, PCS, AS> CostEstimation<(C, PCS)> for Plonk<AS>
where
    C: CurveAffine,
    PCS: PolynomialCommitmentScheme<C, NativeLoader>
        + CostEstimation<C, Input = Vec<pcs::Query<C::Scalar>>>,
    AS: AccumulationStrategy<C, NativeLoader, PCS>,
{
    type Input = Protocol<C>;

    fn estimate_cost(protocol: &Protocol<C>) -> Cost {
        let plonk_cost = {
            let num_quotient = protocol
                .constraints
                .iter()
                .map(Expression::degree)
                .max()
                .unwrap()
                - 1;
            let num_accumulator = protocol.accumulator_indices.len();
            let num_instance = protocol.num_instance.iter().sum();
            let num_commitment = protocol.num_witness.iter().sum::<usize>() + num_quotient;
            let num_evaluation = protocol.evaluations.len();
            let num_msm = protocol.preprocessed.len() + num_commitment + 1 + 2 * num_accumulator;
            Cost::new(num_instance, num_commitment, num_evaluation, num_msm)
        };
        let pcs_cost =
            PCS::estimate_cost(&PlonkProof::<C, NativeLoader, PCS>::empty_queries(protocol));
        plonk_cost + pcs_cost
    }
}

fn langranges<C, T>(protocol: &Protocol<C>, instances: &[Vec<T>]) -> impl IntoIterator<Item = i32>
where
    C: CurveAffine,
{
    protocol
        .constraints
        .iter()
        .cloned()
        .sum::<Expression<_>>()
        .used_langrange()
        .into_iter()
        .chain(
            0..instances
                .iter()
                .map(|instance| instance.len())
                .max()
                .unwrap_or_default() as i32,
        )
}
