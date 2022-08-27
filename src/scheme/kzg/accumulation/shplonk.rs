use crate::{
    loader::{LoadedScalar, Loader},
    protocol::Protocol,
    scheme::kzg::{
        accumulation::{AccumulationScheme, AccumulationStrategy, Accumulator},
        cost::{Cost, CostEstimation},
        langranges,
        msm::MSM,
    },
    util::{
        CommonPolynomial, CommonPolynomialEvaluation, Curve, Domain, Expression, Field, Fraction,
        Itertools, Query, Rotation, TranscriptRead,
    },
    Error,
};
use std::{
    collections::{BTreeSet, HashMap},
    iter,
};

#[derive(Default)]
pub struct ShplonkAccumulationScheme;

impl<C, L, T, S> AccumulationScheme<C, L, T, S> for ShplonkAccumulationScheme
where
    C: Curve,
    L: Loader<C>,
    T: TranscriptRead<C, L>,
    S: AccumulationStrategy<C, L, T, ShplonkProof<C, L>>,
{
    type Proof = ShplonkProof<C, L>;

    fn accumulate(
        protocol: &Protocol<C>,
        loader: &L,
        instances: Vec<Vec<L::LoadedScalar>>,
        transcript: &mut T,
        strategy: &mut S,
    ) -> Result<S::Output, Error> {
        transcript.common_scalar(&loader.load_const(&protocol.transcript_initial_state))?;

        let proof = ShplonkProof::read(protocol, instances, transcript)?;
        let old_accumulator =
            strategy.extract_accumulator(protocol, loader, transcript, &proof.instances);

        let (common_poly_eval, sets) = {
            let mut common_poly_eval = CommonPolynomialEvaluation::new(
                &protocol.domain,
                loader,
                langranges(protocol, &proof.instances),
                &proof.z,
            );
            let mut sets = intermediate_sets(protocol, loader, &proof.z, &proof.z_prime);

            L::LoadedScalar::batch_invert(
                iter::empty()
                    .chain(common_poly_eval.denoms())
                    .chain(sets.iter_mut().flat_map(IntermediateSet::denoms)),
            );
            L::LoadedScalar::batch_invert(sets.iter_mut().flat_map(IntermediateSet::denoms));

            (common_poly_eval, sets)
        };

        let commitments = proof.commitments(protocol, loader, &common_poly_eval);
        let evaluations = proof.evaluations(protocol, loader, &common_poly_eval)?;

        let f = {
            let powers_of_mu = proof
                .mu
                .powers(sets.iter().map(|set| set.polys.len()).max().unwrap());
            let msms = sets
                .iter()
                .map(|set| set.msm(&commitments, &evaluations, &powers_of_mu));

            msms.zip(proof.gamma.powers(sets.len()).into_iter())
                .map(|(msm, power_of_gamma)| msm * &power_of_gamma)
                .sum::<MSM<_, _>>()
                - MSM::base(proof.w.clone()) * &sets[0].z_s
        };

        let rhs = MSM::base(proof.w_prime.clone());
        let lhs = f + rhs.clone() * &proof.z_prime;

        let mut accumulator = Accumulator::new(lhs, rhs);
        if let Some(old_accumulator) = old_accumulator {
            accumulator += old_accumulator;
        }
        strategy.process(loader, transcript, proof, accumulator)
    }
}

pub struct ShplonkProof<C: Curve, L: Loader<C>> {
    instances: Vec<Vec<L::LoadedScalar>>,
    auxiliaries: Vec<L::LoadedEcPoint>,
    challenges: Vec<L::LoadedScalar>,
    alpha: L::LoadedScalar,
    quotients: Vec<L::LoadedEcPoint>,
    z: L::LoadedScalar,
    evaluations: Vec<L::LoadedScalar>,
    mu: L::LoadedScalar,
    gamma: L::LoadedScalar,
    w: L::LoadedEcPoint,
    z_prime: L::LoadedScalar,
    w_prime: L::LoadedEcPoint,
}

impl<C: Curve, L: Loader<C>> ShplonkProof<C, L> {
    fn read<T: TranscriptRead<C, L>>(
        protocol: &Protocol<C>,
        instances: Vec<Vec<L::LoadedScalar>>,
        transcript: &mut T,
    ) -> Result<Self, Error> {
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
                .relations
                .iter()
                .map(Expression::degree)
                .max()
                .unwrap();
            transcript.read_n_ec_points(max_degree - 1)?
        };

        let z = transcript.squeeze_challenge();
        let evaluations = transcript.read_n_scalars(protocol.evaluations.len())?;

        let mu = transcript.squeeze_challenge();
        let gamma = transcript.squeeze_challenge();
        let w = transcript.read_ec_point()?;
        let z_prime = transcript.squeeze_challenge();
        let w_prime = transcript.read_ec_point()?;

        Ok(Self {
            instances,
            auxiliaries,
            challenges,
            alpha,
            quotients,
            z,
            evaluations,
            mu,
            gamma,
            w,
            z_prime,
            w_prime,
        })
    }

    fn commitments(
        &self,
        protocol: &Protocol<C>,
        loader: &L,
        common_poly_eval: &CommonPolynomialEvaluation<C, L>,
    ) -> HashMap<usize, MSM<C, L>> {
        iter::empty()
            .chain(
                protocol
                    .preprocessed
                    .iter()
                    .map(|value| MSM::base(loader.ec_point_load_const(value)))
                    .enumerate(),
            )
            .chain({
                let witness_offset = protocol.preprocessed.len() + protocol.num_instance.len();
                self.auxiliaries
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(move |(i, witness)| (witness_offset + i, MSM::base(witness)))
            })
            .chain(iter::once((
                protocol.vanishing_poly(),
                common_poly_eval
                    .zn()
                    .powers(self.quotients.len())
                    .into_iter()
                    .zip(self.quotients.iter().cloned().map(MSM::base))
                    .map(|(coeff, piece)| piece * &coeff)
                    .sum(),
            )))
            .collect()
    }

    fn evaluations(
        &self,
        protocol: &Protocol<C>,
        loader: &L,
        common_poly_eval: &CommonPolynomialEvaluation<C, L>,
    ) -> Result<HashMap<Query, L::LoadedScalar>, Error> {
        let instance_evaluations = self.instances.iter().map(|instances| {
            L::LoadedScalar::sum_products(
                &instances
                    .iter()
                    .enumerate()
                    .map(|(i, instance)| {
                        (
                            common_poly_eval.get(CommonPolynomial::Lagrange(i as i32)),
                            instance.clone(),
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

        let powers_of_alpha = self.alpha.powers(protocol.relations.len());
        let relation_evaluations = protocol
            .relations
            .iter()
            .map(|relation| {
                relation.evaluate(
                    &|scalar| Ok(loader.load_const(&scalar)),
                    &|poly| Ok(common_poly_eval.get(poly)),
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
        let quotient_evaluation = L::LoadedScalar::sum_products(
            &powers_of_alpha
                .into_iter()
                .rev()
                .zip(relation_evaluations)
                .collect_vec(),
        ) * &common_poly_eval.zn_minus_one_inv();

        evaluations.insert(
            Query {
                poly: protocol.vanishing_poly(),
                rotation: Rotation::cur(),
            },
            quotient_evaluation,
        );

        Ok(evaluations)
    }
}

struct IntermediateSet<C: Curve, L: Loader<C>> {
    rotations: Vec<Rotation>,
    polys: Vec<usize>,
    z_s: L::LoadedScalar,
    evaluation_coeffs: Vec<Fraction<L::LoadedScalar>>,
    commitment_coeff: Option<Fraction<L::LoadedScalar>>,
    remainder_coeff: Option<Fraction<L::LoadedScalar>>,
}

impl<C: Curve, L: Loader<C>> IntermediateSet<C, L> {
    fn new(
        domain: &Domain<C::Scalar>,
        loader: &L,
        rotations: Vec<Rotation>,
        powers_of_z: &[L::LoadedScalar],
        z_prime: &L::LoadedScalar,
        z_prime_minus_z_omega_i: &HashMap<Rotation, L::LoadedScalar>,
        z_s_1: &Option<L::LoadedScalar>,
    ) -> Self {
        let omegas = rotations
            .iter()
            .map(|rotation| domain.rotate_scalar(C::Scalar::one(), *rotation))
            .collect_vec();

        let normalized_ell_primes = omegas
            .iter()
            .enumerate()
            .map(|(j, omega_j)| {
                omegas
                    .iter()
                    .enumerate()
                    .filter(|&(i, _)| i != j)
                    .fold(C::Scalar::one(), |acc, (_, omega_i)| {
                        acc * (*omega_j - omega_i)
                    })
            })
            .collect_vec();

        let z = &powers_of_z[1].clone();
        let z_pow_k_minus_one = {
            let k_minus_one = rotations.len() - 1;
            powers_of_z.iter().enumerate().skip(1).fold(
                loader.load_one(),
                |acc, (i, power_of_z)| {
                    if k_minus_one & (1 << i) == 1 {
                        acc * power_of_z
                    } else {
                        acc
                    }
                },
            )
        };

        let barycentric_weights = omegas
            .iter()
            .zip(normalized_ell_primes.iter())
            .map(|(omega, normalized_ell_prime)| {
                L::LoadedScalar::sum_products_with_coeff(&[
                    (
                        *normalized_ell_prime,
                        z_pow_k_minus_one.clone(),
                        z_prime.clone(),
                    ),
                    (
                        -(*normalized_ell_prime * omega),
                        z_pow_k_minus_one.clone(),
                        z.clone(),
                    ),
                ])
            })
            .map(Fraction::one_over)
            .collect_vec();

        let z_s = rotations
            .iter()
            .map(|rotation| z_prime_minus_z_omega_i.get(rotation).unwrap().clone())
            .reduce(|acc, z_prime_minus_z_omega_i| acc * z_prime_minus_z_omega_i)
            .unwrap();
        let z_s_1_over_z_s = z_s_1.clone().map(|z_s_1| Fraction::new(z_s_1, z_s.clone()));

        Self {
            rotations,
            polys: Vec::new(),
            z_s,
            evaluation_coeffs: barycentric_weights,
            commitment_coeff: z_s_1_over_z_s,
            remainder_coeff: None,
        }
    }

    fn denoms(&mut self) -> impl IntoIterator<Item = &'_ mut L::LoadedScalar> {
        if self.evaluation_coeffs.first().unwrap().denom().is_some() {
            self.evaluation_coeffs
                .iter_mut()
                .chain(self.commitment_coeff.as_mut())
                .filter_map(Fraction::denom_mut)
                .collect_vec()
        } else if self.remainder_coeff.is_none() {
            let barycentric_weights_sum = L::LoadedScalar::sum(
                &self
                    .evaluation_coeffs
                    .iter()
                    .map(Fraction::evaluate)
                    .collect_vec(),
            );
            self.remainder_coeff = Some(match self.commitment_coeff.clone() {
                Some(coeff) => Fraction::new(coeff.evaluate(), barycentric_weights_sum),
                None => Fraction::one_over(barycentric_weights_sum),
            });
            vec![self.remainder_coeff.as_mut().unwrap().denom_mut().unwrap()]
        } else {
            unreachable!()
        }
    }

    fn msm(
        &self,
        commitments: &HashMap<usize, MSM<C, L>>,
        evaluations: &HashMap<Query, L::LoadedScalar>,
        powers_of_mu: &[L::LoadedScalar],
    ) -> MSM<C, L> {
        self.polys
            .iter()
            .zip(powers_of_mu.iter())
            .map(|(poly, power_of_mu)| {
                let commitment = self
                    .commitment_coeff
                    .as_ref()
                    .map(|commitment_coeff| {
                        commitments.get(poly).unwrap().clone() * &commitment_coeff.evaluate()
                    })
                    .unwrap_or_else(|| commitments.get(poly).unwrap().clone());
                let remainder = self.remainder_coeff.as_ref().unwrap().evaluate()
                    * L::LoadedScalar::sum_products(
                        &self
                            .rotations
                            .iter()
                            .zip(self.evaluation_coeffs.iter())
                            .map(|(rotation, coeff)| {
                                (
                                    coeff.evaluate(),
                                    evaluations
                                        .get(&Query::new(*poly, *rotation))
                                        .unwrap()
                                        .clone(),
                                )
                            })
                            .collect_vec(),
                    );
                (commitment - MSM::constant(remainder)) * power_of_mu
            })
            .sum()
    }
}

fn intermediate_sets<C: Curve, L: Loader<C>>(
    protocol: &Protocol<C>,
    loader: &L,
    z: &L::LoadedScalar,
    z_prime: &L::LoadedScalar,
) -> Vec<IntermediateSet<C, L>> {
    let rotations_sets = rotations_sets(protocol);
    let superset = rotations_sets
        .iter()
        .flat_map(|set| set.rotations.clone())
        .sorted()
        .dedup();

    let size = 2.max(
        (rotations_sets
            .iter()
            .map(|set| set.rotations.len())
            .max()
            .unwrap()
            - 1)
        .next_power_of_two()
        .ilog2() as usize
            + 1,
    );
    let powers_of_z = z.powers(size);
    let z_prime_minus_z_omega_i = HashMap::from_iter(
        superset
            .map(|rotation| {
                (
                    rotation,
                    loader.load_const(&protocol.domain.rotate_scalar(C::Scalar::one(), rotation)),
                )
            })
            .map(|(rotation, omega)| (rotation, z_prime.clone() - z.clone() * omega)),
    );

    let mut z_s_1 = None;
    rotations_sets
        .into_iter()
        .map(|set| {
            let intermetidate_set = IntermediateSet {
                polys: set.polys,
                ..IntermediateSet::new(
                    &protocol.domain,
                    loader,
                    set.rotations,
                    &powers_of_z,
                    z_prime,
                    &z_prime_minus_z_omega_i,
                    &z_s_1,
                )
            };
            if z_s_1.is_none() {
                z_s_1 = Some(intermetidate_set.z_s.clone());
            };
            intermetidate_set
        })
        .collect()
}

struct RotationsSet {
    rotations: Vec<Rotation>,
    polys: Vec<usize>,
}

fn rotations_sets<C: Curve>(protocol: &Protocol<C>) -> Vec<RotationsSet> {
    let poly_rotations = protocol.queries.iter().fold(
        Vec::<(usize, Vec<Rotation>)>::new(),
        |mut poly_rotations, query| {
            if let Some(pos) = poly_rotations
                .iter()
                .position(|(poly, _)| *poly == query.poly)
            {
                let (_, rotations) = &mut poly_rotations[pos];
                if !rotations.contains(&query.rotation) {
                    rotations.push(query.rotation);
                }
            } else {
                poly_rotations.push((query.poly, vec![query.rotation]));
            }
            poly_rotations
        },
    );

    poly_rotations
        .into_iter()
        .fold(Vec::<RotationsSet>::new(), |mut sets, (poly, rotations)| {
            if let Some(pos) = sets.iter().position(|set| {
                BTreeSet::from_iter(set.rotations.iter()) == BTreeSet::from_iter(rotations.iter())
            }) {
                let set = &mut sets[pos];
                if !set.polys.contains(&poly) {
                    set.polys.push(poly);
                }
            } else {
                let set = RotationsSet {
                    rotations,
                    polys: vec![poly],
                };
                sets.push(set);
            }
            sets
        })
}

impl CostEstimation for ShplonkAccumulationScheme {
    fn estimate_cost<C: Curve>(protocol: &Protocol<C>) -> Cost {
        let num_quotient = protocol
            .relations
            .iter()
            .map(Expression::degree)
            .max()
            .unwrap()
            - 1;
        let num_accumulator = protocol
            .accumulator_indices
            .as_ref()
            .map(|accumulator_indices| accumulator_indices.len())
            .unwrap_or_default();

        let num_instance = protocol.num_instance.iter().sum();
        let num_commitment = protocol.num_witness.iter().sum::<usize>() + num_quotient + 2;
        let num_evaluation = protocol.evaluations.len();
        let num_msm = protocol.preprocessed.len() + num_commitment + 3 + 2 * num_accumulator;

        Cost::new(num_instance, num_commitment, num_evaluation, num_msm)
    }
}
