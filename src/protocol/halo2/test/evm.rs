use crate::{
    collect_slice, halo2_native_verify, halo2_prepare,
    loader::evm::EvmTranscript,
    protocol::halo2::{
        test::{halo2::OneLayerAccumulation, MainGateWithRange, StandardPlonk, LIMBS},
        util::evm::ChallengeEvm,
    },
    scheme::kzg::PlonkAccumulator,
};
use halo2_proofs::poly::kzg::{
    multiopen::{ProverGWC, VerifierGWC},
    strategy::BatchVerifier,
};

macro_rules! halo2_evm_verify {
    ($params:expr, $protocol:expr, $instances:expr, $proof:expr, $accumulator:expr) => {{
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
        let statements = $instances
            .iter()
            .map(|instance| {
                iter::repeat_with(|| transcript.read_scalar().unwrap())
                    .take(instance.len())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut strategy = SameCurveAccumulation::<_, _, BITS, LIMBS>::default();
        $accumulator
            .accumulate(
                &$protocol,
                &loader,
                statements,
                &mut transcript,
                &mut strategy,
            )
            .unwrap();
        let code = strategy.code($params.get_g()[0], $params.g2(), $params.s_g2());
        let (accept, gas) = execute(code, encode_calldata($instances, $proof));
        dbg!(gas);
        assert!(accept);
    }};
}

#[test]
fn test_plonk_evm_main_gate_with_range() {
    const K: u32 = 9;
    const N: usize = 1;

    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg],
        K, N, None, MainGateWithRange::<_>,
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
        protocol,
        instances.clone(),
        PlonkAccumulator::new(),
        EvmTranscript::<_, NativeLoader, _, _>::new(proof.as_slice())
    );

    halo2_evm_verify!(params, protocol, instances, proof, PlonkAccumulator::new());
}

#[test]
fn test_plonk_evm_standard_plonk() {
    const K: u32 = 9;
    const N: usize = 1;

    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg],
        K, N, None, StandardPlonk::<_>,
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
        protocol,
        instances.clone(),
        PlonkAccumulator::new(),
        EvmTranscript::<_, NativeLoader, _, _>::new(proof.as_slice())
    );

    halo2_evm_verify!(params, protocol, instances, proof, PlonkAccumulator::new());
}

#[test]
#[ignore]
fn test_plonk_evm_one_layer_accumulation() {
    const K: u32 = 21;
    const N: usize = 1;

    let accumulator_indices = (0..4 * LIMBS).map(|idx| (0, idx)).collect();
    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg],
        K, N, Some(accumulator_indices), OneLayerAccumulation,
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
        protocol,
        instances.clone(),
        PlonkAccumulator::new(),
        EvmTranscript::<_, NativeLoader, _, _>::new(proof.as_slice())
    );

    halo2_evm_verify!(params, protocol, instances, proof, PlonkAccumulator::new());
}
