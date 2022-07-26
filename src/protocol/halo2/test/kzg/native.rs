use crate::{
    collect_slice, halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_verify,
    halo2_kzg_prepare,
    protocol::halo2::test::{
        kzg::{
            main_gate_with_plookup_with_mock_kzg_accumulator,
            main_gate_with_range_with_mock_kzg_accumulator, LIMBS,
        },
        StandardPlonk,
    },
    scheme::kzg::{PlonkAccumulationScheme, ShplonkAccumulationScheme},
};
use halo2_curves::bn256::G1Affine;
use halo2_proofs::{
    poly::kzg::{
        multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
        strategy::AccumulatorStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

macro_rules! test {
    (@ $prefix:ident, $name:ident, $k:expr, $config:expr, $create_cirucit:expr, $prover:ty, $verifier:ty, $scheme:ty) => {
        paste! {
            #[test]
            fn [<test_kzg_ $prefix _ $name>]() {
                let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                    $k,
                    $config,
                    $create_cirucit
                );
                let snark = halo2_kzg_create_snark!(
                    &params,
                    &pk,
                    &protocol,
                    &circuits,
                    $prover,
                    $verifier,
                    AccumulatorStrategy<_>,
                    Blake2bWrite<_, _, _>,
                    Blake2bRead<_, _, _>,
                    Challenge255<_>
                );
                halo2_kzg_native_verify!(
                    params,
                    &snark.protocol,
                    snark.statements,
                    $scheme,
                    &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
                );
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_cirucit:expr) => {
        test!(@ shplonk, $name, $k, $config, $create_cirucit, ProverSHPLONK<_>, VerifierSHPLONK<_>, ShplonkAccumulationScheme);
        test!(@ plonk, $name, $k, $config, $create_cirucit, ProverGWC<_>, VerifierGWC<_>, PlonkAccumulationScheme);
    }
}

test!(
    zk_standard_plonk_rand,
    9,
    halo2_kzg_config!(true, 2),
    StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
);
test!(
    zk_main_gate_with_range_with_mock_kzg_accumulator,
    9,
    halo2_kzg_config!(true, 2, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    main_gate_with_range_with_mock_kzg_accumulator::<Bn256>()
);
// TODO: Enable when `PlookupConfig` supports zk
// test!(
//     zk_main_gate_with_plookup_with_mock_kzg_accumulator,
//     9,
//     halo2_kzg_config!(true, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
//     main_gate_with_plookup_with_mock_kzg_accumulator::<Bn256, true>(9)
// );
test!(
    standard_plonk_rand,
    9,
    halo2_kzg_config!(false, 2),
    StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
);
test!(
    main_gate_with_range_with_mock_kzg_accumulator,
    9,
    halo2_kzg_config!(false, 2, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    main_gate_with_range_with_mock_kzg_accumulator::<Bn256>()
);
test!(
    main_gate_with_plookup_with_mock_kzg_accumulator,
    9,
    halo2_kzg_config!(false, 1, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    main_gate_with_plookup_with_mock_kzg_accumulator::<Bn256, false>(9)
);
