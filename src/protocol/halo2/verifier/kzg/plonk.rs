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
    use super::verify_proof;
    use crate::{
        protocol::halo2::verifier::kzg::SingleProofVerifier, util::loader::native::NativeLoader,
    };
    use halo2_proofs::poly::kzg::{
        multiopen::{ProverGWC, VerifierGWC},
        strategy::BatchVerifier,
    };

    #[test]
    fn test_plonk_native() {
        use crate::protocol::halo2::{
            compile,
            test::{gen_vk_and_proof, read_srs},
            transcript::native::Blake2bTranscript,
        };
        use halo2_proofs::{
            halo2curves::bn256::Bn256,
            poly::{
                commitment::ParamsProver,
                kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
            },
        };
        use rand::rngs::OsRng;

        const N: usize = 2;

        let params = read_srs::<_, ParamsKZG<Bn256>>("test_plonk_native", 9);
        let (vk, instance, proof) = gen_vk_and_proof::<
            KZGCommitmentScheme<_>,
            ProverGWC<_>,
            VerifierGWC<_>,
            BatchVerifier<_, _>,
            _,
        >(&params, N, OsRng);

        let protocol = compile(&vk, N);
        let loader = NativeLoader;
        let statements = instance
            .iter()
            .flat_map(|instance| instance.iter().map(|instance| instance.as_slice()))
            .collect::<Vec<_>>();
        let mut transcript = Blake2bTranscript::init(proof.as_slice());
        let mut strategy =
            SingleProofVerifier::<Bn256>::new(params.get_g()[0], params.g2(), params.s_g2());
        assert!(verify_proof(
            &protocol,
            &loader,
            &statements,
            &mut transcript,
            &mut strategy,
        )
        .unwrap());
    }
}
