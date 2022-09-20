use crate::{
    loader::{halo2::test::StandardPlonk, native::NativeLoader},
    pcs::kzg::{Bdfg21, Gwc19, KzgOnSameCurve},
    system::halo2::{
        test::kzg::{
            self, halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_verify,
            halo2_kzg_prepare, main_gate_with_range_with_mock_kzg_accumulator, BITS, LIMBS,
        },
        transcript::evm::{ChallengeEvm, EvmTranscript},
    },
    verifier::Plonk,
};
use halo2_curves::bn256::{Bn256, G1Affine};
use halo2_proofs::poly::kzg::{
    multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
    strategy::AccumulatorStrategy,
};
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

macro_rules! halo2_kzg_evm_verify {
    ($plonk_verifier:ty, $params:expr, $protocol:expr, $instances:expr, $proof:expr) => {{
        use halo2_curves::bn256::{Bn256, Fq, Fr};
        use halo2_proofs::poly::commitment::ParamsProver;
        use std::rc::Rc;
        use $crate::{
            loader::evm::{encode_calldata, execute, EvmLoader},
            system::halo2::{
                test::kzg::{BITS, LIMBS},
                transcript::evm::EvmTranscript,
            },
            util::Itertools,
            verifier::PlonkVerifier,
        };

        let loader = EvmLoader::new::<Fq, Fr>();
        let runtime_code = {
            let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());
            let instances = transcript.load_instances(
                $instances
                    .iter()
                    .map(|instances| instances.len())
                    .collect_vec(),
            );
            let proof =
                <$plonk_verifier>::read_proof($protocol, &instances, &mut transcript).unwrap();
            <$plonk_verifier>::verify(
                &$params.get_g()[0],
                &($params.g2(), $params.s_g2()),
                $protocol,
                &instances,
                &proof,
            )
            .unwrap();

            loader.runtime_code()
        };

        let (accept, total_cost, costs) =
            execute(runtime_code, encode_calldata($instances, &$proof));

        loader.print_gas_metering(costs);
        println!("Total gas cost: {}", total_cost);

        assert!(accept);
    }};
}

macro_rules! test {
    (@ $(#[$attr:meta],)* $prefix:ident, $name:ident, $k:expr, $config:expr, $create_circuit:expr, $prover:ty, $verifier:ty, $plonk_verifier:ty) => {
        paste! {
            $(#[$attr])*
            fn [<test_ $prefix _ $name>]() {
                let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                    $k,
                    $config,
                    $create_circuit
                );
                let snark = halo2_kzg_create_snark!(
                    $prover,
                    $verifier,
                    AccumulatorStrategy<_>,
                    EvmTranscript<G1Affine, _, _, _>,
                    EvmTranscript<G1Affine, _, _, _>,
                    ChallengeEvm<_>,
                    &params,
                    &pk,
                    &protocol,
                    &circuits
                );
                halo2_kzg_native_verify!(
                    $plonk_verifier,
                    params,
                    &snark.protocol,
                    &snark.instances,
                    &mut EvmTranscript::<_, NativeLoader, _, _>::new(snark.proof.as_slice())
                );
                halo2_kzg_evm_verify!(
                    $plonk_verifier,
                    params,
                    &snark.protocol,
                    &snark.instances,
                    snark.proof
                );
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test], shplonk, $name, $k, $config, $create_circuit, ProverSHPLONK<_>, VerifierSHPLONK<_>, Plonk::<KzgOnSameCurve<Bn256, Bdfg21<Bn256>, LIMBS, BITS>>);
        test!(@ #[test], plonk, $name, $k, $config, $create_circuit, ProverGWC<_>, VerifierGWC<_>, Plonk::<KzgOnSameCurve<Bn256, Gwc19<Bn256>, LIMBS, BITS>>);
    };
    ($(#[$attr:meta],)* $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test] $(,#[$attr])*, plonk, $name, $k, $config, $create_circuit, ProverGWC<_>, VerifierGWC<_>, Plonk::<KzgOnSameCurve<Bn256, Gwc19<Bn256>, LIMBS, BITS>>);
    };
}

test!(
    zk_standard_plonk_rand,
    9,
    halo2_kzg_config!(true, 1),
    StandardPlonk::rand(ChaCha20Rng::from_seed(Default::default()))
);
test!(
    zk_main_gate_with_range_with_mock_kzg_accumulator,
    9,
    halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    main_gate_with_range_with_mock_kzg_accumulator::<Bn256>()
);
test!(
    #[cfg(feature = "loader_halo2")],
    #[ignore = "cause it requires 16GB memory to run"],
    zk_accumulation_two_snark,
    21,
    halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    kzg::halo2::Accumulation::two_snark()
);
test!(
    #[cfg(feature = "loader_halo2")],
    #[ignore = "cause it requires 32GB memory to run"],
    zk_accumulation_two_snark_with_accumulator,
    22,
    halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    kzg::halo2::Accumulation::two_snark_with_accumulator()
);
