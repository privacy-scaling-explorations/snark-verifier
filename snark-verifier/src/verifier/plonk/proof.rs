use crate::{
    loader::{LoadedScalar, Loader},
    pcs::{self, AccumulationScheme, AccumulatorEncoding, PolynomialCommitmentScheme},
    util::{
        arithmetic::{CurveAffine, Field, Rotation},
        msm::Msm,
        transcript::TranscriptRead,
        Itertools,
    },
    verifier::plonk::protocol::{
        CommonPolynomial::Lagrange, CommonPolynomialEvaluation, LinearizationStrategy,
        PlonkProtocol, Query,
    },
    Error,
};
use std::{collections::HashMap, iter};

/// Proof of PLONK with [`PolynomialCommitmentScheme`] that has
/// [`AccumulationScheme`].
#[derive(Clone, Debug)]
pub struct PlonkProof<C, L, AS>
where
    C: CurveAffine,
    L: Loader<C>,
    AS: AccumulationScheme<C, L> + PolynomialCommitmentScheme<C, L, Output = AS::Accumulator>,
{
    /// Computed commitments of instance polynomials.
    pub committed_instances: Option<Vec<L::LoadedEcPoint>>,
    /// Commitments of witness polynomials read from transcript.
    pub witnesses: Vec<L::LoadedEcPoint>,
    /// Challenges squeezed from transcript.
    pub challenges: Vec<L::LoadedScalar>,
    /// Quotient commitments read from transcript.
    pub quotients: Vec<L::LoadedEcPoint>,
    /// Query point squeezed from transcript.
    pub z: L::LoadedScalar,
    /// Evaluations read from transcript.
    pub evaluations: Vec<L::LoadedScalar>,
    /// Proof of [`PolynomialCommitmentScheme`].
    pub pcs: <AS as PolynomialCommitmentScheme<C, L>>::Proof,
    /// Old [`AccumulationScheme::Accumulator`]s read from instnaces.
    pub old_accumulators: Vec<AS::Accumulator>,
}

impl<C, L, AS> PlonkProof<C, L, AS>
where
    C: CurveAffine,
    L: Loader<C>,
    AS: AccumulationScheme<C, L> + PolynomialCommitmentScheme<C, L, Output = AS::Accumulator>,
{
    /// Reads each part from transcript as [`PlonkProof`].
    pub fn read<T, AE>(
        svk: &<AS as PolynomialCommitmentScheme<C, L>>::VerifyingKey,
        protocol: &PlonkProtocol<C, L>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self, Error>
    where
        T: TranscriptRead<C, L>,
        AE: AccumulatorEncoding<C, L, Accumulator = AS::Accumulator>,
    {
        if let Some(transcript_initial_state) = &protocol.transcript_initial_state {
            transcript.common_scalar(transcript_initial_state)?;
        }

        if protocol.num_instance
            != instances
                .iter()
                .map(|instances| instances.len())
                .collect_vec()
        {
            return Err(Error::InvalidInstances);
        }

        let committed_instances = if let Some(ick) = &protocol.instance_committing_key {
            let loader = transcript.loader();
            let bases = ick
                .bases
                .iter()
                .map(|value| loader.ec_point_load_const(value))
                .collect_vec();
            let constant = ick
                .constant
                .as_ref()
                .map(|value| loader.ec_point_load_const(value));

            let committed_instances = instances
                .iter()
                .map(|instances| {
                    instances
                        .iter()
                        .zip(bases.iter())
                        .map(|(scalar, base)| Msm::<C, L>::base(base) * scalar)
                        .chain(constant.as_ref().map(Msm::base))
                        .sum::<Msm<_, _>>()
                        .evaluate(None)
                })
                .collect_vec();
            for committed_instance in committed_instances.iter() {
                transcript.common_ec_point(committed_instance)?;
            }

            Some(committed_instances)
        } else {
            for instances in instances.iter() {
                for instance in instances.iter() {
                    transcript.common_scalar(instance)?;
                }
            }

            None
        };

        let (witnesses, challenges) = {
            let (witnesses, challenges) = protocol
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
                witnesses.into_iter().flatten().collect_vec(),
                challenges.into_iter().flatten().collect_vec(),
            )
        };

        let quotients = transcript.read_n_ec_points(protocol.quotient.num_chunk())?;

        let z = transcript.squeeze_challenge();
        let evaluations = transcript.read_n_scalars(protocol.evaluations.len())?;

        let pcs = <AS as PolynomialCommitmentScheme<C, L>>::read_proof(
            svk,
            &Self::empty_queries(protocol),
            transcript,
        )?;

        let old_accumulators = protocol
            .accumulator_indices
            .iter()
            .map(|accumulator_indices| {
                AE::from_repr(
                    &accumulator_indices
                        .iter()
                        .map(|&(i, j)| &instances[i][j])
                        .collect_vec(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            committed_instances,
            witnesses,
            challenges,
            quotients,
            z,
            evaluations,
            pcs,
            old_accumulators,
        })
    }

    pub(super) fn empty_queries(protocol: &PlonkProtocol<C, L>) -> Vec<pcs::Query<C::Scalar>> {
        protocol
            .queries
            .iter()
            .map(|query| {
                let shift = protocol
                    .domain
                    .rotate_scalar(C::Scalar::ONE, query.rotation);
                pcs::Query::new(query.poly, shift)
            })
            .collect()
    }

    pub(super) fn queries(
        &self,
        protocol: &PlonkProtocol<C, L>,
        mut evaluations: HashMap<Query, L::LoadedScalar>,
    ) -> Vec<pcs::Query<C::Scalar, L::LoadedScalar>> {
        Self::empty_queries(protocol)
            .into_iter()
            .zip(
                protocol
                    .queries
                    .iter()
                    .map(|query| evaluations.remove(query).unwrap()),
            )
            .map(|(query, eval)| query.with_evaluation(eval))
            .collect()
    }

    pub(super) fn commitments<'a>(
        &'a self,
        protocol: &'a PlonkProtocol<C, L>,
        common_poly_eval: &CommonPolynomialEvaluation<C, L>,
        evaluations: &mut HashMap<Query, L::LoadedScalar>,
    ) -> Result<Vec<Msm<C, L>>, Error> {
        let loader = common_poly_eval.zn().loader();
        let mut commitments = iter::empty()
            .chain(protocol.preprocessed.iter().map(Msm::base))
            .chain(
                self.committed_instances
                    .as_ref()
                    .map(|committed_instances| {
                        committed_instances.iter().map(Msm::base).collect_vec()
                    })
                    .unwrap_or_else(|| {
                        iter::repeat_with(Default::default)
                            .take(protocol.num_instance.len())
                            .collect_vec()
                    }),
            )
            .chain(self.witnesses.iter().map(Msm::base))
            .collect_vec();

        let numerator = protocol.quotient.numerator.evaluate(
            &|scalar| Ok(Msm::constant(loader.load_const(&scalar))),
            &|poly| Ok(Msm::constant(common_poly_eval.get(poly).clone())),
            &|query| {
                evaluations
                    .get(&query)
                    .cloned()
                    .map(Msm::constant)
                    .or_else(|| {
                        (query.rotation == Rotation::cur())
                            .then(|| commitments.get(query.poly).cloned())
                            .flatten()
                    })
                    .ok_or_else(|| Error::InvalidProtocol(format!("Missing query {query:?}")))
            },
            &|index| {
                self.challenges
                    .get(index)
                    .cloned()
                    .map(Msm::constant)
                    .ok_or_else(|| Error::InvalidProtocol(format!("Missing challenge {index}")))
            },
            &|a| Ok(-a?),
            &|a, b| Ok(a? + b?),
            &|a, b| {
                let (a, b) = (a?, b?);
                match (a.size(), b.size()) {
                    (0, _) => Ok(b * &a.try_into_constant().unwrap()),
                    (_, 0) => Ok(a * &b.try_into_constant().unwrap()),
                    (_, _) => Err(Error::InvalidProtocol("Invalid linearization".to_string())),
                }
            },
            &|a, scalar| Ok(a? * &loader.load_const(&scalar)),
        )?;

        let quotient_query = Query::new(
            protocol.preprocessed.len() + protocol.num_instance.len() + self.witnesses.len(),
            Rotation::cur(),
        );
        let quotient = common_poly_eval
            .zn()
            .pow_const(protocol.quotient.chunk_degree as u64)
            .powers(self.quotients.len())
            .into_iter()
            .zip(self.quotients.iter().map(Msm::base))
            .map(|(coeff, chunk)| chunk * &coeff)
            .sum::<Msm<_, _>>();
        match protocol.linearization {
            Some(LinearizationStrategy::WithoutConstant) => {
                let linearization_query = Query::new(quotient_query.poly + 1, Rotation::cur());
                let (msm, constant) = numerator.split();
                commitments.push(quotient);
                commitments.push(msm);
                evaluations.insert(
                    quotient_query,
                    (constant.unwrap_or_else(|| loader.load_zero())
                        + evaluations.get(&linearization_query).unwrap())
                        * common_poly_eval.zn_minus_one_inv(),
                );
            }
            Some(LinearizationStrategy::MinusVanishingTimesQuotient) => {
                let (msm, constant) =
                    (numerator - quotient * common_poly_eval.zn_minus_one()).split();
                commitments.push(msm);
                evaluations.insert(
                    quotient_query,
                    constant.unwrap_or_else(|| loader.load_zero()),
                );
            }
            None => {
                commitments.push(quotient);
                evaluations.insert(
                    quotient_query,
                    numerator.try_into_constant().ok_or_else(|| {
                        Error::InvalidProtocol("Invalid linearization".to_string())
                    })? * common_poly_eval.zn_minus_one_inv(),
                );
            }
        }

        Ok(commitments)
    }

    pub(super) fn evaluations(
        &self,
        protocol: &PlonkProtocol<C, L>,
        instances: &[Vec<L::LoadedScalar>],
        common_poly_eval: &CommonPolynomialEvaluation<C, L>,
    ) -> Result<HashMap<Query, L::LoadedScalar>, Error> {
        let loader = common_poly_eval.zn().loader();
        let instance_evals = protocol.instance_committing_key.is_none().then(|| {
            let offset = protocol.preprocessed.len();
            let queries = {
                let range = offset..offset + protocol.num_instance.len();
                protocol
                    .quotient
                    .numerator
                    .used_query()
                    .into_iter()
                    .filter(move |query| range.contains(&query.poly))
            };
            queries
                .map(move |query| {
                    let instances = instances[query.poly - offset].iter();
                    let l_i_minus_r = (-query.rotation.0..)
                        .map(|i_minus_r| common_poly_eval.get(Lagrange(i_minus_r)));
                    let eval = loader.sum_products(&instances.zip(l_i_minus_r).collect_vec());
                    (query, eval)
                })
                .collect_vec()
        });

        let evals = iter::empty()
            .chain(instance_evals.into_iter().flatten())
            .chain(
                protocol
                    .evaluations
                    .iter()
                    .cloned()
                    .zip(self.evaluations.iter().cloned()),
            )
            .collect();

        Ok(evals)
    }
}
