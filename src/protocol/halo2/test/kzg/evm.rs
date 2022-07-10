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
    ($params:expr, $protocol:expr, $statements:expr, $proof:expr, $scheme:ty) => {{
        use halo2_curves::bn256::{Fq, Fr};
        use halo2_proofs::poly::commitment::ParamsProver;
        use std::{iter, rc::Rc};
        use $crate::{
            loader::evm::{encode_calldata, execute, EvmLoader, EvmTranscript},
            protocol::halo2::test::kzg::{BITS, LIMBS},
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

macro_rules! test {
    (@ #[$($attr:meta),*], $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        paste! {
            $(#[$attr])*
            fn [<test_kzg_plonk_ $name>]() {
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
                    ProverGWC<_>,
                    VerifierGWC<_>,
                    AccumulatorStrategy<_>,
                    EvmTranscript<_, _, _, _>,
                    EvmTranscript<_, _, _, _>,
                    ChallengeEvm<_>
                );
                halo2_kzg_native_verify!(
                    params,
                    &snark.protocol,
                    snark.statements.clone(),
                    PlonkAccumulationScheme,
                    &mut EvmTranscript::<_, NativeLoader, _, _>::new(snark.proof.as_slice())
                );
                halo2_kzg_evm_verify!(
                    params,
                    &snark.protocol,
                    snark.statements,
                    snark.proof,
                    PlonkAccumulationScheme
                );
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test], $name, $k, $config, $create_circuit);
    };
    (#[ignore = $reason:literal], $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test, ignore = $reason], $name, $k, $config, $create_circuit);
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
    halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx + 1)).collect()),
    main_gate_with_range_with_mock_kzg_accumulator::<Bn256>()
);
test!(
    #[ignore = "cause it requires 64GB memory to run"],
    zk_accumulation_two_snark,
    21,
    halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    Accumulation::two_snark(true)
);
test!(
    #[ignore = "cause it requires 128GB memory to run"],
    zk_accumulation_two_snark_with_accumulator,
    22,
    halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    Accumulation::two_snark_with_accumulator(true)
);
test!(
    standard_plonk_rand,
    9,
    halo2_kzg_config!(false, 1),
    StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
);
test!(
    main_gate_with_range_with_mock_kzg_accumulator,
    9,
    halo2_kzg_config!(false, 1, (0..4 * LIMBS).map(|idx| (0, idx + 1)).collect()),
    main_gate_with_range_with_mock_kzg_accumulator::<Bn256>()
);
test!(
    #[ignore = "cause it requires 64GB memory to run"],
    accumulation_two_snark,
    21,
    halo2_kzg_config!(false, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    Accumulation::two_snark(false)
);
test!(
    #[ignore = "cause it requires 128GB memory to run"],
    accumulation_two_snark_with_accumulator,
    22,
    halo2_kzg_config!(false, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    Accumulation::two_snark_with_accumulator(false)
);
