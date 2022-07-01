use crate::{
    collect_slice, halo2_create_snark, halo2_native_verify, halo2_prepare,
    loader::evm::EvmTranscript,
    protocol::halo2::{
        test::{halo2::Accumulation, read_or_create_srs, MainGateWithRange, StandardPlonk, LIMBS},
        util::evm::ChallengeEvm,
    },
    scheme::kzg::PlonkAccumulationScheme,
};
use halo2_curves::bn256::Bn256;
use halo2_proofs::poly::{
    commitment::ParamsProver,
    kzg::{
        commitment::KZGCommitmentScheme,
        multiopen::{ProverGWC, VerifierGWC},
        strategy::BatchVerifier,
    },
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

macro_rules! halo2_evm_verify {
    ($params:expr, $protocol:expr, $statements:expr, $proof:expr, $scheme:ty) => {{
        use halo2_curves::bn256::{Fq, Fr};
        use halo2_proofs::poly::commitment::ParamsProver;
        use std::{iter, rc::Rc};
        use $crate::{
            loader::evm::{encode_calldata, execute, EvmLoader, EvmTranscript},
            protocol::halo2::test::{BITS, LIMBS},
            scheme::kzg::{AccumulationScheme, SameCurveAccumulation},
            util::TranscriptRead,
        };

        let loader = EvmLoader::new::<Fq, Fr>();
        let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());
        let statements = $statements
            .iter()
            .map(|instance| {
                iter::repeat_with(|| transcript.read_scalar().unwrap())
                    .take(instance.len())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut strategy = SameCurveAccumulation::<_, _, LIMBS, BITS>::default();
        <$scheme>::accumulate(
            $protocol,
            &loader,
            statements,
            &mut transcript,
            &mut strategy,
        )
        .unwrap();
        let code = strategy.code($params.get_g()[0], $params.g2(), $params.s_g2());
        let (accept, total_cost, costs) = execute(code, encode_calldata($statements, $proof));
        loader.print_gas_metering(costs);
        println!("Total: {}", total_cost);
        assert!(accept);
    }};
}

#[test]
fn test_plonk_evm_standard_plonk() {
    const K: u32 = 9;
    const N: usize = 1;

    let (params, pk, protocol, circuits) = halo2_prepare!(
        [kzg],
        K,
        N,
        None,
        StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
    );
    let snark = halo2_create_snark!(
        [kzg],
        &params,
        &pk,
        &protocol,
        &circuits,
        ProverGWC<_>,
        VerifierGWC<_>,
        BatchVerifier<_, _>,
        EvmTranscript<_, _, _, _>,
        EvmTranscript<_, _, _, _>,
        ChallengeEvm<_>
    );
    halo2_native_verify!(
        [kzg],
        params,
        &snark.protocol,
        snark.statements.clone(),
        PlonkAccumulationScheme,
        &mut EvmTranscript::<_, NativeLoader, _, _>::new(snark.proof.as_slice())
    );
    halo2_evm_verify!(
        params,
        &snark.protocol,
        snark.statements,
        snark.proof,
        PlonkAccumulationScheme
    );
}

#[test]
fn test_plonk_evm_main_gate_with_range_with_mock_accumulator() {
    const K: u32 = 9;
    const N: usize = 1;

    let accumulator_indices = (0..4 * LIMBS).map(|idx| (0, idx + 1)).collect();
    let params = read_or_create_srs::<KZGCommitmentScheme<Bn256>>("kzg", K);
    let (_, pk, protocol, circuits) = halo2_prepare!(
        [kzg],
        K,
        N,
        Some(accumulator_indices),
        MainGateWithRange::<_>::with_mock_accumulator(params.get_g()[0], params.get_g()[1])
    );
    let snark = halo2_create_snark!(
        [kzg],
        &params,
        &pk,
        &protocol,
        &circuits,
        ProverGWC<_>,
        VerifierGWC<_>,
        BatchVerifier<_, _>,
        EvmTranscript<_, _, _, _>,
        EvmTranscript<_, _, _, _>,
        ChallengeEvm<_>
    );
    halo2_native_verify!(
        [kzg],
        params,
        &snark.protocol,
        snark.statements.clone(),
        PlonkAccumulationScheme,
        &mut EvmTranscript::<_, NativeLoader, _, _>::new(snark.proof.as_slice())
    );
    halo2_evm_verify!(
        params,
        &snark.protocol,
        snark.statements,
        snark.proof,
        PlonkAccumulationScheme
    );
}

#[test]
#[ignore = "cause it requires 64GB ram to run"]
fn test_plonk_evm_accumulation_two_snark() {
    const K: u32 = 21;
    const N: usize = 1;

    let accumulator_indices = (0..4 * LIMBS).map(|idx| (0, idx)).collect();
    let (params, pk, protocol, circuits) = halo2_prepare!(
        [kzg],
        K,
        N,
        Some(accumulator_indices),
        Accumulation::two_snark()
    );
    let snark = halo2_create_snark!(
        [kzg],
        &params,
        &pk,
        &protocol,
        &circuits,
        ProverGWC<_>,
        VerifierGWC<_>,
        BatchVerifier<_, _>,
        EvmTranscript<_, _, _, _>,
        EvmTranscript<_, _, _, _>,
        ChallengeEvm<_>
    );
    halo2_native_verify!(
        [kzg],
        params,
        &snark.protocol,
        snark.statements.clone(),
        PlonkAccumulationScheme,
        &mut EvmTranscript::<_, NativeLoader, _, _>::new(snark.proof.as_slice())
    );
    halo2_evm_verify!(
        params,
        &snark.protocol,
        snark.statements,
        snark.proof,
        PlonkAccumulationScheme
    );
}

#[test]
#[ignore = "cause it requires 128GB ram to run"]
fn test_plonk_evm_accumulation_two_snark_with_accumulator() {
    const K: u32 = 22;
    const N: usize = 1;

    let accumulator_indices = (0..4 * LIMBS).map(|idx| (0, idx)).collect();
    let (params, pk, protocol, circuits) = halo2_prepare!(
        [kzg],
        K,
        N,
        Some(accumulator_indices),
        Accumulation::two_snark_with_accumulator()
    );
    let snark = halo2_create_snark!(
        [kzg],
        &params,
        &pk,
        &protocol,
        &circuits,
        ProverGWC<_>,
        VerifierGWC<_>,
        BatchVerifier<_, _>,
        EvmTranscript<_, _, _, _>,
        EvmTranscript<_, _, _, _>,
        ChallengeEvm<_>
    );
    halo2_native_verify!(
        [kzg],
        params,
        &snark.protocol,
        snark.statements.clone(),
        PlonkAccumulationScheme,
        &mut EvmTranscript::<_, NativeLoader, _, _>::new(snark.proof.as_slice())
    );
    halo2_evm_verify!(
        params,
        &snark.protocol,
        snark.statements,
        snark.proof,
        PlonkAccumulationScheme
    );
}
