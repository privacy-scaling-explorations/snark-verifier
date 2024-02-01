use crate::{
    pcs::kzg::{Bdfg21, Gwc19, KzgAs, LimbsEncoding},
    system::halo2::test::{
        kzg::{
            halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_verify, halo2_kzg_prepare,
            main_gate_with_range_with_mock_kzg_accumulator, BITS, LIMBS,
        },
        StandardPlonk,
    },
    verifier::plonk::PlonkVerifier,
};
use halo2_curves::bn256::{Bn256, G1Affine};
use halo2_proofs::{
    poly::kzg::multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

macro_rules! test {
    (@ $prefix:ident, $name:ident, $k:expr, $config:expr, $create_cirucit:expr, $prover:ty, $verifier:ty, $plonk_verifier:ty) => {
        paste! {
            #[test]
            fn [<test_ $prefix _ $name>]() {
                let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                    $k,
                    $config,
                    $create_cirucit
                );
                let snark = halo2_kzg_create_snark!(
                    $prover,
                    $verifier,
                    Blake2bWrite<_, _, _>,
                    Blake2bRead<_, _, _>,
                    Challenge255<_>,
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
                    &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
                );
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_cirucit:expr) => {
        test!(@ shplonk, $name, $k, $config, $create_cirucit, ProverSHPLONK<_>, VerifierSHPLONK<_>, PlonkVerifier<KzgAs<Bn256, Bdfg21>, LimbsEncoding<LIMBS, BITS>>);
        test!(@ plonk, $name, $k, $config, $create_cirucit, ProverGWC<_>, VerifierGWC<_>, PlonkVerifier<KzgAs<Bn256, Gwc19>, LimbsEncoding<LIMBS, BITS>>);
    }
}

test!(
    zk_standard_plonk_rand,
    9,
    halo2_kzg_config!(true, 2),
    StandardPlonk::rand(ChaCha20Rng::from_seed(Default::default()))
);
test!(
    zk_main_gate_with_range_with_mock_kzg_accumulator,
    9,
    halo2_kzg_config!(true, 2, (0..4 * LIMBS).map(|idx| (0, idx)).collect()),
    main_gate_with_range_with_mock_kzg_accumulator::<Bn256>()
);
