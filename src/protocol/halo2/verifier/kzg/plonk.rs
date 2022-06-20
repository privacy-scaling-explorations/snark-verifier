use crate::{
    protocol::{
        halo2::verifier::kzg::{langranges, VerificationStrategy, MSM},
        Protocol,
    },
    transcript::Transcript,
    util::{
        loader::{LoadedScalar, Loader},
        CommonPolynomial, CommonPolynomialEvaluation, Curve, Expression, Field, Query, Rotation,
    },
    Error,
};
use std::{collections::HashMap, iter};

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

    let common_poly_eval = {
        let mut common_poly_eval = CommonPolynomialEvaluation::new(
            &protocol.domain,
            loader,
            langranges::<_, L>(protocol, statements),
            &proof.z,
        );

        L::LoadedScalar::batch_invert(common_poly_eval.denoms());

        common_poly_eval
    };

    let commitments = proof.commitments(protocol, loader, &common_poly_eval);
    let evaluations = proof.evaluations(protocol, loader, &common_poly_eval)?;

    let sets = rotation_sets(protocol);
    let powers_of_v = &proof.v.powers(sets.len());
    let f = {
        let powers_of_u = proof
            .u
            .powers(sets.iter().map(|set| set.polys.len()).max().unwrap());
        sets.iter()
            .map(|set| set.msm(&commitments, &evaluations, &powers_of_u))
            .zip(powers_of_v.iter().rev())
            .map(|(msm, power_of_v)| msm * power_of_v.clone())
            .sum::<MSM<_, _>>()
    };
    let z_omegas = sets.iter().map(|set| {
        proof.z.clone()
            * loader.load_const(
                &protocol
                    .domain
                    .rotate_scalar(C::Scalar::one(), set.rotation),
            )
    });

    let rhs = proof
        .ws
        .iter()
        .zip(powers_of_v.iter().rev())
        .map(|(w, power_of_v)| MSM::base(w.clone()) * power_of_v.clone())
        .collect::<Vec<_>>();
    let lhs = f + rhs
        .iter()
        .zip(z_omegas.into_iter())
        .map(|(uw, z_omega)| uw.clone() * z_omega)
        .sum();

    strategy.process(loader, proof, lhs, rhs.into_iter().sum())
}

pub struct Proof<C: Curve, L: Loader<C>> {
    statements: Vec<Vec<L::LoadedScalar>>,
    auxiliaries: Vec<L::LoadedEcPoint>,
    challenges: Vec<L::LoadedScalar>,
    alpha: L::LoadedScalar,
    quotients: Vec<L::LoadedEcPoint>,
    z: L::LoadedScalar,
    evaluations: Vec<L::LoadedScalar>,
    u: L::LoadedScalar,
    ws: Vec<L::LoadedEcPoint>,
    v: L::LoadedScalar,
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

        let u = transcript.squeeze_challenge();
        let ws = transcript.read_n_ec_points(rotation_sets(protocol).len())?;
        let v = transcript.squeeze_challenge();

        Ok(Self {
            statements,
            auxiliaries,
            challenges,
            alpha,
            quotients,
            z,
            evaluations,
            u,
            ws,
            v,
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

struct RotationSet {
    rotation: Rotation,
    polys: Vec<usize>,
}

impl RotationSet {
    fn msm<C: Curve, L: Loader<C>>(
        &self,
        commitments: &HashMap<usize, MSM<C, L>>,
        evaluations: &HashMap<Query, L::LoadedScalar>,
        powers_of_u: &[L::LoadedScalar],
    ) -> MSM<C, L> {
        self.polys
            .iter()
            .map(|poly| {
                let commitment = commitments.get(poly).unwrap().clone();
                let evalaution = evaluations
                    .get(&Query::new(*poly, self.rotation))
                    .unwrap()
                    .clone();
                commitment - MSM::scalar(evalaution)
            })
            .zip(powers_of_u.iter().take(self.polys.len()).rev())
            .map(|(msm, power_of_u)| msm * power_of_u.clone())
            .sum()
    }
}

fn rotation_sets<C: Curve>(protocol: &Protocol<C>) -> Vec<RotationSet> {
    protocol.queries.iter().fold(Vec::new(), |mut sets, query| {
        if let Some(pos) = sets.iter().position(|set| set.rotation == query.rotation) {
            sets[pos].polys.push(query.poly)
        } else {
            sets.push(RotationSet {
                rotation: query.rotation,
                polys: vec![query.poly],
            })
        }
        sets
    })
}

#[cfg(test)]
mod test {
    use super::{verify_proof, Proof};
    use crate::{
        collect_slice,
        protocol::halo2::{
            compile,
            test::{gen_vk_and_proof, read_srs},
        },
    };
    use halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverGWC, VerifierGWC},
                strategy::BatchVerifier,
            },
        },
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::iter;

    #[test]
    fn test_plonk_native() {
        use crate::{
            protocol::halo2::{
                test::BigCircuit, transcript::native::Blake2bTranscript,
                verifier::kzg::NativeDecider,
            },
            util::loader::native::NativeLoader,
        };
        use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

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
                ProverGWC<_>,
                VerifierGWC<_>,
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

    #[test]
    #[cfg(feature = "evm")]
    fn test_plonk_evm() {
        use crate::{
            protocol::halo2::{
                test::BigCircuit,
                transcript::evm::EvmTranscript,
                verifier::kzg::{NativeDecider, VerificationStrategy, MSM},
            },
            util::{
                loader::{
                    evm::{modulus, test::execute, EvmLoader},
                    native::NativeLoader,
                    EcPointLoader,
                },
                PrimeCurveAffine,
            },
            Error,
        };
        use ethereum_types::U256;
        use halo2_proofs::{
            arithmetic::CurveAffine,
            halo2curves::bn256::{Fq, G1Affine, G2Affine, G1},
            transcript::{ChallengeEvm, EvmRead, EvmWrite},
        };
        use std::{ops::Neg, rc::Rc};

        pub struct EvmDecider {
            g1: G1Affine,
            g2: G2Affine,
            s_g2: G2Affine,
        }

        impl EvmDecider {
            pub fn new(g1: G1Affine, g2: G2Affine, s_g2: G2Affine) -> Self {
                EvmDecider { g1, g2, s_g2 }
            }
        }

        impl VerificationStrategy<G1, Rc<EvmLoader>, Proof<G1, Rc<EvmLoader>>> for EvmDecider {
            type Output = Vec<u8>;

            fn process(
                &mut self,
                loader: &Rc<EvmLoader>,
                _: Proof<G1, Rc<EvmLoader>>,
                lhs: MSM<G1, Rc<EvmLoader>>,
                rhs: MSM<G1, Rc<EvmLoader>>,
            ) -> Result<Self::Output, Error> {
                let [g2, minus_s_g2] = [self.g2, self.s_g2.neg()].map(|ec_point| {
                    let coordinates = ec_point.coordinates().unwrap();
                    (
                        U256::from_little_endian(&coordinates.x().c1.to_bytes()),
                        U256::from_little_endian(&coordinates.x().c0.to_bytes()),
                        U256::from_little_endian(&coordinates.y().c1.to_bytes()),
                        U256::from_little_endian(&coordinates.y().c0.to_bytes()),
                    )
                });
                let g1 = loader.ec_point_load_const(&self.g1.to_curve());
                let lhs = lhs.evaluate(g1.clone());
                let rhs = rhs.evaluate(g1);
                loader.pairing(&lhs, g2, &rhs, minus_s_g2);
                Ok(loader.code())
            }

            fn finalize(self) -> bool {
                unreachable!()
            }
        }

        const K: u32 = 9;
        const N: usize = 1;

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
                ProverGWC<_>,
                VerifierGWC<_>,
                BatchVerifier<_, _>,
                EvmWrite<_, _, _>,
                EvmRead<_, _, _>,
                ChallengeEvm<_>,
                _,
            >(&params, &circuits, &instances, &mut rng)
        };

        let protocol = compile(&vk, N);
        {
            let loader = NativeLoader;
            let statements = instances.clone().into_iter().flatten().collect::<Vec<_>>();
            let mut transcript = EvmTranscript::<_, NativeLoader, _, _>::new(proof.as_slice());
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
        {
            let loader = EvmLoader::new(modulus::<Fq>(), modulus::<Fr>());
            let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());
            let statements = instances
                .iter()
                .flat_map(|instances| {
                    instances
                        .iter()
                        .map(|instance| {
                            iter::repeat_with(|| loader.calldataload_scalar())
                                .take(instance.len())
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mut strategy = EvmDecider::new(params.get_g()[0], params.g2(), params.s_g2());
            let code = {
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
            let calldata = iter::empty()
                .chain(instances.into_iter().flatten().flatten().flat_map(|value| {
                    let mut bytes = value.to_bytes();
                    bytes.reverse();
                    bytes
                }))
                .chain(proof)
                .collect();
            let (accept, gas) = execute(code, calldata);
            dbg!(gas);
            assert!(accept);
        }
    }
}
