use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, verify_proof, Circuit, ProvingKey},
    poly::{
        commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand_chacha::rand_core::RngCore;

mod circuit;
mod kzg;

pub use circuit::{
    maingate::{MainGateWithRange, MainGateWithRangeConfig},
    standard::StandardPlonk,
};

pub fn create_proof_checked<'a, S, C, P, V, VS, TW, TR, EC, R>(
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
        MockProver::run(
            params.k(),
            circuit,
            instances.iter().map(|instance| instance.to_vec()).collect(),
        )
        .unwrap()
        .assert_satisfied();
    }

    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<S, P, _, _, _, _>(
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
        verify_proof(params, pk.get_vk(), strategy, instances, &mut transcript)
            .unwrap()
            .finalize()
    };
    assert!(accept);

    proof
}
