use crate::{
    protocol::halo2::{compile, Config},
    scheme::kzg::{Cost, CostEstimation, PlonkAccumulationScheme},
    util::{CommonPolynomial, Expression, Query},
};
use halo2_curves::bn256::{Bn256, Fr, G1};
use halo2_proofs::{
    arithmetic::FieldExt,
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey},
    poly::{
        commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        kzg::commitment::KZGCommitmentScheme,
        Rotation, VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use std::assert_matches::assert_matches;

mod circuit;
mod kzg;

pub use circuit::{
    maingate::{
        MainGateWithPlookup, MainGateWithPlookupConfig, MainGateWithRange, MainGateWithRangeConfig,
    },
    standard::StandardPlonk,
};

pub fn create_proof_checked<'a, S, C, P, V, VS, TW, TR, EC, R, const ZK: bool>(
    params: &'a S::ParamsProver,
    pk: &ProvingKey<S::Curve>,
    circuits: &[C],
    instances: &[&[&[S::Scalar]]],
    mut rng: R,
) -> Vec<u8>
where
    S: CommitmentScheme,
    S::ParamsVerifier: 'a,
    C: Circuit<S::Scalar>,
    P: Prover<'a, S>,
    V: Verifier<'a, S>,
    VS: VerificationStrategy<'a, S, V, Output = VS>,
    TW: TranscriptWriterBuffer<Vec<u8>, S::Curve, EC>,
    TR: TranscriptReadBuffer<&'static [u8], S::Curve, EC>,
    EC: EncodedChallenge<S::Curve>,
    R: RngCore,
{
    for (circuit, instances) in circuits.iter().zip(instances.iter()) {
        MockProver::run::<_, ZK>(
            params.k(),
            circuit,
            instances.iter().map(|instance| instance.to_vec()).collect(),
        )
        .unwrap()
        .assert_satisfied();
    }

    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<S, P, _, _, _, _, ZK>(
            params,
            pk,
            circuits,
            instances,
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let params = params.verifier_params();
        let strategy = VS::new(params);
        let mut transcript = TR::init(Box::leak(Box::new(proof.clone())));
        verify_proof::<_, _, _, _, _, ZK>(params, pk.get_vk(), strategy, instances, &mut transcript)
            .unwrap()
            .finalize()
    };
    assert!(accept);

    proof
}

#[test]
fn test_compile_standard_plonk() {
    let circuit = StandardPlonk::rand(ChaCha20Rng::from_seed(Default::default()));

    let params = kzg::read_or_create_srs::<Bn256>(9);
    let vk = keygen_vk::<KZGCommitmentScheme<_>, _, false>(&params, &circuit).unwrap();
    let pk = keygen_pk::<KZGCommitmentScheme<_>, _, false>(&params, vk, &circuit).unwrap();

    let protocol = compile::<G1>(
        pk.get_vk(),
        Config {
            zk: false,
            query_instance: false,
            num_instance: vec![1],
            num_proof: 1,
            accumulator_indices: None,
        },
    );

    let [q_a, q_b, q_c, q_ab, constant, sigma_a, sigma_b, sigma_c, instance, a, b, c, z] =
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].map(|poly| Query::new(poly, Rotation::cur()));
    let z_w = Query::new(12, Rotation::next());
    let t = Query::new(13, Rotation::cur());

    assert_eq!(protocol.preprocessed.len(), 8);
    assert_eq!(protocol.num_statement, vec![1]);
    assert_eq!(protocol.num_auxiliary, vec![3, 0, 1]);
    assert_eq!(protocol.num_challenge, vec![1, 2, 0]);
    assert_eq!(
        protocol.evaluations,
        vec![a, b, c, q_a, q_b, q_c, q_ab, constant, sigma_a, sigma_b, sigma_c, z, z_w]
    );
    assert_eq!(
        protocol.queries,
        vec![a, b, c, z, z_w, q_a, q_b, q_c, q_ab, constant, sigma_a, sigma_b, sigma_c, t]
    );
    assert_eq!(
        format!("{:?}", protocol.relations),
        format!("{:?}", {
            let [q_a, q_b, q_c, q_ab, constant, sigma_a, sigma_b, sigma_c, instance, a, b, c, z, z_w, beta, gamma, l_0, identity, one, k_1, k_2] =
                &[
                    Expression::Polynomial(q_a),
                    Expression::Polynomial(q_b),
                    Expression::Polynomial(q_c),
                    Expression::Polynomial(q_ab),
                    Expression::Polynomial(constant),
                    Expression::Polynomial(sigma_a),
                    Expression::Polynomial(sigma_b),
                    Expression::Polynomial(sigma_c),
                    Expression::Polynomial(instance),
                    Expression::Polynomial(a),
                    Expression::Polynomial(b),
                    Expression::Polynomial(c),
                    Expression::Polynomial(z),
                    Expression::Polynomial(z_w),
                    Expression::Challenge(1), // beta
                    Expression::Challenge(2), // gamma
                    Expression::CommonPolynomial(CommonPolynomial::Lagrange(0)), // l_0
                    Expression::CommonPolynomial(CommonPolynomial::Identity), // identity
                    Expression::Constant(Fr::one()), // one
                    Expression::Constant(Fr::DELTA), // k_1
                    Expression::Constant(Fr::DELTA * Fr::DELTA), // k_2
                ];

            vec![
                q_a * a + q_b * b + q_c * c + q_ab * a * b + constant + instance,
                l_0 * (one - z),
                z_w * ((a + beta * sigma_a + gamma)
                    * (b + beta * sigma_b + gamma)
                    * (c + beta * sigma_c + gamma))
                    - z * ((a + beta * one * identity + gamma)
                        * (b + beta * k_1 * identity + gamma)
                        * (c + beta * k_2 * identity + gamma)),
            ]
        })
    );

    assert_matches!(
        PlonkAccumulationScheme::estimate_cost(&protocol),
        Cost {
            num_commitment: 9,
            num_evaluation: 13,
            num_msm: 20,
            ..
        }
    );
}
