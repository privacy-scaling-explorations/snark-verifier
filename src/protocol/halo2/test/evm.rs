use crate::{
    collect_slice, halo2_native_verify, halo2_prepare,
    loader::evm::EvmTranscript,
    protocol::halo2::{
        test::{MainGateWithRange, StandardPlonk},
        util::evm::ChallengeEvm,
    },
    scheme::kzg::PlonkAccumulator,
};
use halo2_curves::bn256::Fr;
use halo2_proofs::poly::kzg::{
    multiopen::{ProverGWC, VerifierGWC},
    strategy::BatchVerifier,
};

macro_rules! halo2_evm_verify {
    ($params:expr, $protocol:expr, $instances:expr, $proof:expr, $accumulator:expr) => {{
        use halo2_curves::bn256::{Bn256, Fq, Fr};
        use halo2_proofs::poly::commitment::ParamsProver;
        use std::{iter, rc::Rc};
        use $crate::{
            collect_slice,
            loader::evm::{encode_calldata, execute, EvmDecider, EvmLoader, EvmTranscript},
            scheme::kzg::Accumulator,
            util::TranscriptRead,
        };

        let loader = EvmLoader::new::<Fq, Fr>();
        let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());
        let statements = $instances
            .iter()
            .flatten()
            .map(|instance| {
                iter::repeat_with(|| transcript.read_scalar().unwrap())
                    .take(instance.len())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut strategy =
            EvmDecider::<Bn256>::new($params.get_g()[0], $params.g2(), $params.s_g2());
        let code = {
            collect_slice!(statements);
            $accumulator
                .accumulate(
                    &$protocol,
                    &loader,
                    &statements,
                    &mut transcript,
                    &mut strategy,
                )
                .unwrap()
        };
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
        K, N, MainGateWithRange::<Fr>,
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
        instances,
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
        K, N, StandardPlonk::<Fr>,
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
        instances,
        PlonkAccumulator::new(),
        EvmTranscript::<_, NativeLoader, _, _>::new(proof.as_slice())
    );

    halo2_evm_verify!(params, protocol, instances, proof, PlonkAccumulator::new());
}
