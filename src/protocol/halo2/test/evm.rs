use crate::{
    collect_slice, halo2_native_verify, halo2_prepare,
    loader::evm::EvmTranscript,
    protocol::halo2::test::{BigCircuit, SmallCircuit},
    scheme::kzg::PlonkAccumulator,
};
use halo2_proofs::{
    halo2curves::bn256::Fr,
    poly::kzg::{
        multiopen::{ProverGWC, VerifierGWC},
        strategy::BatchVerifier,
    },
    transcript::{ChallengeEvm, EvmRead, EvmWrite},
};

macro_rules! halo2_evm_verify {
    ($params:expr, $protocol:expr, $instances:expr, $proof:expr, $accumulator:expr) => {{
        use halo2_proofs::{
            halo2curves::bn256::{Bn256, Fq, Fr},
            poly::commitment::ParamsProver,
        };
        use std::{iter, rc::Rc};
        use $crate::{
            collect_slice,
            loader::evm::{execute, EvmDecider, EvmLoader, EvmTranscript},
            scheme::kzg::Accumulator,
        };

        let loader = EvmLoader::new::<Fq, Fr>();
        let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());
        let statements = $instances
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
        let calldata = iter::empty()
            .chain(
                $instances
                    .into_iter()
                    .flatten()
                    .flatten()
                    .flat_map(|value| {
                        let mut bytes = value.to_bytes();
                        bytes.reverse();
                        bytes
                    }),
            )
            .chain($proof)
            .collect();
        let (accept, gas) = execute(code, calldata);
        dbg!(gas);
        assert!(accept);
    }};
}

#[test]
fn test_plonk_evm_big() {
    const K: u32 = 9;
    const N: usize = 1;

    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg] K, N, BigCircuit::<Fr>,
        ProverGWC<_>,
        VerifierGWC<_>,
        BatchVerifier<_, _>,
        EvmWrite<_, _, _>,
        EvmRead<_, _, _>,
        ChallengeEvm<_>
    );

    halo2_native_verify!(
        params,
        protocol,
        instances,
        PlonkAccumulator::new(),
        EvmTranscript::<_, NativeLoader, _, _>::new(proof.as_slice())
    );

    halo2_evm_verify!(params, protocol, instances, proof, PlonkAccumulator::new());
}

#[test]
fn test_plonk_evm_small() {
    const K: u32 = 9;
    const N: usize = 1;

    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg] K, N, SmallCircuit::<Fr>,
        ProverGWC<_>,
        VerifierGWC<_>,
        BatchVerifier<_, _>,
        EvmWrite<_, _, _>,
        EvmRead<_, _, _>,
        ChallengeEvm<_>
    );

    halo2_native_verify!(
        params,
        protocol,
        instances,
        PlonkAccumulator::new(),
        EvmTranscript::<_, NativeLoader, _, _>::new(proof.as_slice())
    );

    halo2_evm_verify!(params, protocol, instances, proof, PlonkAccumulator::new());
}
