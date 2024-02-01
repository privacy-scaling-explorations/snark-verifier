use crate::{GWC, SHPLONK};

use super::{CircuitExt, PlonkVerifier};
#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{ParamsProver, Prover, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            msm::DualMSM,
            multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
            strategy::{AccumulatorStrategy, GuardKZG},
        },
        VerificationStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use rand::{rngs::StdRng, SeedableRng};
pub use snark_verifier::loader::evm::encode_calldata;
use snark_verifier::{
    loader::evm::{compile_solidity, deploy_and_call, EvmLoader},
    pcs::{
        kzg::{KzgAccumulator, KzgAsVerifyingKey, KzgDecidingKey, KzgSuccinctVerifyingKey},
        AccumulationDecider, AccumulationScheme, PolynomialCommitmentScheme,
    },
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::SnarkVerifier,
};
use std::{fs, io, path::Path, rc::Rc};

/// Generates a proof for evm verification using either SHPLONK or GWC proving method. Uses Keccak for Fiat-Shamir.
pub fn gen_evm_proof<'params, C, P, V>(
    params: &'params ParamsKZG<Bn256>,
    pk: &'params ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8>
where
    C: Circuit<Fr>,
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();

    #[cfg(feature = "display")]
    let proof_time = start_timer!(|| "Create EVM proof");
    let rng = StdRng::from_entropy();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, P, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };
    #[cfg(feature = "display")]
    end_timer!(proof_time);

    let accept = {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, V>::finalize(
            verify_proof::<_, V, _, EvmTranscript<_, _, _, _>, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

pub fn gen_evm_proof_gwc<'params, C: Circuit<Fr>>(
    params: &'params ParamsKZG<Bn256>,
    pk: &'params ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    gen_evm_proof::<C, ProverGWC<_>, VerifierGWC<_>>(params, pk, circuit, instances)
}

pub fn gen_evm_proof_shplonk<'params, C: Circuit<Fr>>(
    params: &'params ParamsKZG<Bn256>,
    pk: &'params ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    gen_evm_proof::<C, ProverSHPLONK<_>, VerifierSHPLONK<_>>(params, pk, circuit, instances)
}

pub fn gen_evm_verifier<C, AS>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    path: Option<&Path>,
) -> Vec<u8>
where
    C: CircuitExt<Fr>,
    AS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<EvmLoader>,
            VerifyingKey = KzgSuccinctVerifyingKey<G1Affine>,
            Output = KzgAccumulator<G1Affine, Rc<EvmLoader>>,
        > + AccumulationScheme<
            G1Affine,
            Rc<EvmLoader>,
            VerifyingKey = KzgAsVerifyingKey,
            Accumulator = KzgAccumulator<G1Affine, Rc<EvmLoader>>,
        > + AccumulationDecider<G1Affine, Rc<EvmLoader>, DecidingKey = KzgDecidingKey<Bn256>>,
{
    let protocol = compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(C::accumulator_indices()),
    );
    // deciding key
    let dk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof =
        PlonkVerifier::<AS>::read_proof(&dk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::<AS>::verify(&dk, &protocol, &instances, &proof).unwrap();

    let sol_code = loader.solidity_code();
    let byte_code = compile_solidity(&sol_code);
    if let Some(path) = path {
        path.parent()
            .and_then(|dir| fs::create_dir_all(dir).ok())
            .unwrap();
        fs::write(path, sol_code).unwrap();
    }
    byte_code
}

pub fn gen_evm_verifier_gwc<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    path: Option<&Path>,
) -> Vec<u8> {
    gen_evm_verifier::<C, GWC>(params, vk, num_instance, path)
}

pub fn gen_evm_verifier_shplonk<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    path: Option<&Path>,
) -> Vec<u8> {
    gen_evm_verifier::<C, SHPLONK>(params, vk, num_instance, path)
}

pub fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> u64 {
    let calldata = encode_calldata(&instances, &proof);
    let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
    dbg!(gas_cost);
    gas_cost
}

pub fn write_calldata(instances: &[Vec<Fr>], proof: &[u8], path: &Path) -> io::Result<String> {
    let calldata = encode_calldata(instances, proof);
    let calldata = hex::encode(calldata);
    fs::write(path, &calldata)?;
    Ok(calldata)
}
