use crate::{
    protocol::{
        halo2::verifier::kzg::{langranges, VerificationStrategy, MSM},
        Protocol,
    },
    transcript::Transcript,
    util::{
        loader::{LoadedScalar, Loader},
        CommonPolynomial, CommonPolynomialEvaluation, Curve, Domain, Expression, Field, Fraction,
        Query, Rotation,
    },
    Error,
};
use std::{
    collections::{HashMap, HashSet},
    iter,
};

pub fn verify_proof<C, L, V, T>(
    protocol: &Protocol<C>,
    loader: &L,
    statements: &[&[L::LoadedScalar]],
    transcript: &mut T,
    strategy: &mut V,
) -> Result<V::Output, Error>
where
    C: Curve,
    L: Loader<C>,
    V: VerificationStrategy<C, L, Proof<C, L>>,
    T: Transcript<C, L>,
{
    transcript.common_scalar(&loader.load_const(&protocol.transcript_initial_state))?;

    let proof = Proof::read(protocol, statements, transcript)?;

    let (common_poly_eval, sets) = {
        let mut common_poly_eval = CommonPolynomialEvaluation::new(
            &protocol.domain,
            loader,
            langranges::<_, L>(protocol, statements),
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

        msms.zip(proof.gamma.powers(sets.len()).into_iter().rev())
            .map(|(msm, power_of_gamma)| msm * power_of_gamma)
            .sum::<MSM<_, _>>()
            - MSM::base(proof.w.clone()) * sets[0].z_s.clone()
    };

    let rhs = MSM::base(proof.w_prime.clone());
    let lhs = f + rhs.clone() * proof.z_prime.clone();

    strategy.process(loader, proof, lhs, rhs)
}

pub struct Proof<C: Curve, L: Loader<C>> {
    statements: Vec<Vec<L::LoadedScalar>>,
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

impl<C: Curve, L: Loader<C>> Proof<C, L> {
    fn read<T: Transcript<C, L>>(
        protocol: &Protocol<C>,
        statements: &[&[L::LoadedScalar]],
        transcript: &mut T,
    ) -> Result<Self, Error> {
        let statements = {
            if statements.len() != protocol.num_statement {
                return Err(Error::InvalidInstances);
            }

            statements
                .iter()
                .map(|statements| {
                    statements
                        .iter()
                        .cloned()
                        .map(|statement| {
                            transcript.common_scalar(&statement)?;
                            Ok(statement)
                        })
                        .collect::<Result<Vec<_>, Error>>()
                })
                .collect::<Result<Vec<_>, Error>>()?
        };

        let (auxiliaries, challenges) = {
            let (auxiliaries, challenges) = protocol
                .num_auxiliary
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
                auxiliaries.into_iter().flatten().collect::<Vec<_>>(),
                challenges.into_iter().flatten().collect::<Vec<_>>(),
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
            statements,
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
                let auxiliary_offset = protocol.preprocessed.len() + protocol.num_statement;
                self.auxiliaries
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(move |(i, auxiliary)| (auxiliary_offset + i, MSM::base(auxiliary)))
            })
            .chain(iter::once((
                protocol.vanishing_poly(),
                common_poly_eval
                    .zn()
                    .powers(self.quotients.len())
                    .into_iter()
                    .zip(self.quotients.iter().cloned().map(MSM::base))
                    .map(|(coeff, piece)| piece * coeff)
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
        let statement_evaluations = self.statements.iter().map(|statements| {
            L::LoadedScalar::sum(
                &statements
                    .iter()
                    .enumerate()
                    .map(|(i, statement)| {
                        statement.clone()
                            * common_poly_eval.get(CommonPolynomial::Lagrange(i as i32))
                    })
                    .collect::<Vec<_>>(),
            )
        });
        let mut evaluations = HashMap::<Query, L::LoadedScalar>::from_iter(
            iter::empty()
                .chain(
                    statement_evaluations
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
        let quotient_evaluation = L::LoadedScalar::sum(
            &powers_of_alpha
                .into_iter()
                .rev()
                .zip(protocol.relations.iter())
                .map(|(power_of_alpha, relation)| {
                    relation
                        .evaluate(
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
                        .map(|evaluation| power_of_alpha * evaluation)
                })
                .collect::<Result<Vec<_>, Error>>()?,
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
            .collect::<Vec<_>>();

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
            .collect::<Vec<_>>();

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
                L::LoadedScalar::sum_products_with_coeff_and_constant(
                    &[
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
                    ],
                    &C::Scalar::zero(),
                )
            })
            .map(Fraction::one_over)
            .collect::<Vec<_>>();

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
                .collect::<Vec<_>>()
        } else if self.remainder_coeff.is_none() {
            let barycentric_weights_sum = L::LoadedScalar::sum(
                &self
                    .evaluation_coeffs
                    .iter()
                    .map(Fraction::evaluate)
                    .collect::<Vec<_>>(),
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
            .zip(powers_of_mu.iter().take(self.polys.len()).rev())
            .map(|(poly, power_of_mu)| {
                let commitment = self
                    .commitment_coeff
                    .as_ref()
                    .map(|commitment_coeff| {
                        commitments.get(poly).unwrap().clone() * commitment_coeff.evaluate()
                    })
                    .unwrap_or_else(|| commitments.get(poly).unwrap().clone());
                let remainder = self.remainder_coeff.as_ref().unwrap().evaluate()
                    * L::LoadedScalar::sum(
                        &self
                            .rotations
                            .iter()
                            .zip(self.evaluation_coeffs.iter())
                            .map(|(rotation, coeff)| {
                                coeff.evaluate()
                                    * evaluations
                                        .get(&Query {
                                            poly: *poly,
                                            rotation: *rotation,
                                        })
                                        .unwrap()
                            })
                            .collect::<Vec<_>>(),
                    );
                (commitment - MSM::scalar(remainder)) * power_of_mu.clone()
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
    let mut superset = HashSet::new();
    let poly_rotations = protocol.queries.iter().fold(
        Vec::<(usize, Vec<Rotation>, HashSet<Rotation>)>::new(),
        |mut poly_rotations, query| {
            superset.insert(query.rotation);

            if let Some(pos) = poly_rotations
                .iter()
                .position(|(poly, _, _)| *poly == query.poly)
            {
                let (_, rotations, set) = &mut poly_rotations[pos];
                if !set.contains(&query.rotation) {
                    rotations.push(query.rotation);
                    set.insert(query.rotation);
                }
            } else {
                poly_rotations.push((
                    query.poly,
                    vec![query.rotation],
                    HashSet::from_iter([query.rotation]),
                ));
            }
            poly_rotations
        },
    );

    let size = 2.max(
        (poly_rotations
            .iter()
            .map(|(_, rotations, _)| rotations.len())
            .max()
            .unwrap()
            - 1)
        .next_power_of_two()
        .log2() as usize
            + 1,
    );
    let powers_of_z = z.powers(size);
    let z_prime_minus_z_omega_i = HashMap::from_iter(
        superset
            .into_iter()
            .map(|rotation| {
                (
                    rotation,
                    loader.load_const(&protocol.domain.rotate_scalar(C::Scalar::one(), rotation)),
                )
            })
            .map(|(rotation, omega)| (rotation, z_prime.clone() - z.clone() * omega)),
    );

    let mut z_s_1 = None;
    poly_rotations.into_iter().fold(
        Vec::<IntermediateSet<_, _>>::new(),
        |mut intermediate_sets, (poly, rotations, set)| {
            if let Some(pos) = intermediate_sets.iter().position(|intermediate_set| {
                HashSet::from_iter(intermediate_set.rotations.iter().cloned()) == set
            }) {
                let intermediate_set = &mut intermediate_sets[pos];
                if !intermediate_set.polys.contains(&poly) {
                    intermediate_set.polys.push(poly);
                }
            } else {
                let intermetidate_set = IntermediateSet {
                    polys: vec![poly],
                    ..IntermediateSet::new(
                        &protocol.domain,
                        loader,
                        rotations,
                        &powers_of_z,
                        z_prime,
                        &z_prime_minus_z_omega_i,
                        &z_s_1,
                    )
                };
                if z_s_1.is_none() {
                    z_s_1 = Some(intermetidate_set.z_s.clone());
                }
                intermediate_sets.push(intermetidate_set);
            }
            intermediate_sets
        },
    )
}

#[cfg(test)]
mod test {
    use super::verify_proof;
    use crate::{
        collect_slice,
        protocol::halo2::{
            compile,
            test::{gen_vk_and_proof, read_srs, BigCircuit},
            transcript::native::Blake2bTranscript,
            verifier::kzg::NativeDecider,
        },
        util::loader::native::NativeLoader,
    };
    use halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::BatchVerifier,
            },
        },
    };

    #[test]
    fn test_shplonk_native() {
        use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use std::iter;

        const K: u32 = 9;
        const N: usize = 2;

        let params = read_srs::<_, ParamsKZG<Bn256>>("kzg", K);

        let mut rng = ChaCha20Rng::from_seed(Default::default());
        let circuits = iter::repeat_with(|| BigCircuit::<Fr>::rand(&mut rng))
            .take(N)
            .collect::<Vec<_>>();
        let instances = circuits
            .iter()
            .map(BigCircuit::instances)
            .collect::<Vec<_>>();

        let (vk, proof) = {
            collect_slice!(instances, 2);
            gen_vk_and_proof::<
                KZGCommitmentScheme<_>,
                _,
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                BatchVerifier<_, _>,
                Blake2bWrite<_, _, _>,
                Blake2bRead<_, _, _>,
                Challenge255<_>,
                _,
            >(&params, &circuits, &instances, &mut rng)
        };

        let protocol = compile(&vk, N);
        let loader = NativeLoader;
        let statements = instances.into_iter().flatten().collect::<Vec<_>>();
        let mut transcript = Blake2bTranscript::init(proof.as_slice());
        let mut strategy =
            NativeDecider::<Bn256>::new(params.get_g()[0], params.g2(), params.s_g2());
        let accept = {
            collect_slice!(statements);
            verify_proof(
                &protocol,
                &loader,
                &statements,
                &mut transcript,
                &mut strategy,
            )
            .unwrap()
        };
        assert!(accept);
    }
}
