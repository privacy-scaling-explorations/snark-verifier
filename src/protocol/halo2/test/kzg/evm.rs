use crate::{
    halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_evm_verify, halo2_kzg_native_verify,
    halo2_kzg_prepare,
    loader::evm::EvmTranscript,
    protocol::halo2::{
        test::{
            kzg::{halo2::Accumulation, main_gate_with_range_with_mock_kzg_accumulator, LIMBS},
            StandardPlonk,
        },
        util::evm::ChallengeEvm,
    },
    scheme::kzg::PlonkAccumulationScheme,
};
use halo2_proofs::poly::kzg::{
    multiopen::{ProverGWC, VerifierGWC},
    strategy::AccumulatorStrategy,
};
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

#[macro_export]
macro_rules! halo2_kzg_evm_verify {
    ($params:expr, $protocol:expr, $instances:expr, $proof:expr, $scheme:ty) => {{
        use halo2_curves::bn256::{Fq, Fr};
        use halo2_proofs::poly::commitment::ParamsProver;
        use std::{iter, rc::Rc};
        use $crate::{
            loader::evm::{encode_calldata, execute, EvmLoader, EvmTranscript},
            protocol::halo2::test::kzg::{BITS, LIMBS},
            scheme::kzg::{AccumulationScheme, SameCurveAccumulation},
            util::{Itertools, TranscriptRead},
        };

        let loader = EvmLoader::new::<Fq, Fr>();
        let code = {
            let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());
            let instances = $instances
                .iter()
                .map(|instance| {
                    iter::repeat_with(|| transcript.read_scalar().unwrap())
                        .take(instance.len())
                        .collect_vec()
                })
                .collect_vec();
            let mut strategy = SameCurveAccumulation::<_, _, LIMBS, BITS>::default();
            <$scheme>::accumulate(
                $protocol,
                &loader,
                instances,
                &mut transcript,
                &mut strategy,
            )
            .unwrap();
            strategy.finalize($params.get_g()[0], $params.g2(), $params.s_g2());

            loader.code()
        };
        let (accept, total_cost, costs) = execute(code, encode_calldata($instances, $proof));
        loader.print_gas_metering(costs);
        println!("Total gas cost: {}", total_cost);
        assert!(accept);
    }};
}

macro_rules! test {
    (@ #[$($attr:meta),*], $prefix:ident, $name:ident, $k:expr, $config:expr, $create_circuit:expr, $prover:ty, $verifier:ty, $scheme:ty) => {
        paste! {
            $(#[$attr])*
            fn [<test_kzg_ $prefix _ $name>]() {
                let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                    $k,
                    $config,
                    $create_circuit
                );
                let snark = halo2_kzg_create_snark!(
                    &params,
                    &pk,
                    &protocol,
                    &circuits,
                    $prover,
                    $verifier,
                    AccumulatorStrategy<_>,
                    EvmTranscript<_, _, _, _>,
                    EvmTranscript<_, _, _, _>,
                    ChallengeEvm<_>
                );
                halo2_kzg_native_verify!(
                    params,
                    &snark.protocol,
                    snark.instances.clone(),
                    $scheme,
                    &mut EvmTranscript::<_, NativeLoader, _, _>::new(snark.proof.as_slice())
                );
                halo2_kzg_evm_verify!(
                    params,
                    &snark.protocol,
                    snark.instances,
                    snark.proof,
                    $scheme
                );
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        // TODO: Reduce the size of generated evm verifier
        // test!(@ #[test], shplonk, $name, $k, $config, $create_circuit, ProverSHPLONK<_>, VerifierSHPLONK<_>, ShplonkAccumulationScheme);
        test!(@ #[test], plonk, $name, $k, $config, $create_circuit, ProverGWC<_>, VerifierGWC<_>, PlonkAccumulationScheme);
    };
    (#[ignore = $reason:literal], $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test, ignore = $reason], plonk, $name, $k, $config, $create_circuit, ProverGWC<_>, VerifierGWC<_>, PlonkAccumulationScheme);
    };
}

test!(
    zk_standard_plonk_rand,
    9,
    halo2_kzg_config!(true, 1),
    StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
);
test!(
    zk_main_gate_with_range_with_mock_kzg_accumulator,
    9,
    halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    main_gate_with_range_with_mock_kzg_accumulator::<Bn256>()
);
test!(
    #[ignore = "cause it requires 16GB memory to run"],
    zk_accumulation_two_snark,
    21,
    halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    Accumulation::two_snark()
);
test!(
    #[ignore = "cause it requires 32GB memory to run"],
    zk_accumulation_two_snark_with_accumulator,
    22,
    halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    Accumulation::two_snark_with_accumulator()
);
