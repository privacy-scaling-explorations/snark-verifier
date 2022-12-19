use crate::{
    pcs::ipa::{Bgh19, IpaAs},
    system::halo2::test::ipa::{
        halo2_ipa_config, halo2_ipa_create_snark, halo2_ipa_native_verify, halo2_ipa_prepare,
    },
    system::halo2::test::StandardPlonk,
    verifier::plonk::PlonkVerifier,
};
use halo2_curves::pasta::pallas;
use halo2_proofs::{
    poly::ipa::multiopen::{ProverIPA, VerifierIPA},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

macro_rules! test {
    (@ $name:ident, $k:expr, $config:expr, $create_cirucit:expr, $prover:ty, $verifier:ty, $plonk_verifier:ty) => {
        paste! {
            #[test]
            fn [<test_ $name>]() {
                let (params, pk, protocol, circuits) = halo2_ipa_prepare!(
                    pallas::Affine,
                    $k,
                    $config,
                    $create_cirucit
                );
                let snark = halo2_ipa_create_snark!(
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
                halo2_ipa_native_verify!(
                    $plonk_verifier,
                    params,
                    &snark.protocol,
                    &snark.instances,
                    &mut Blake2bRead::<_, pallas::Affine, _>::init(snark.proof.as_slice())
                );
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_cirucit:expr) => {
        test!(@ $name, $k, $config, $create_cirucit, ProverIPA<pallas::Affine>, VerifierIPA<pallas::Affine>, PlonkVerifier::<IpaAs<pallas::Affine, Bgh19>>);
    }
}

test!(
    zk_standard_plonk_rand,
    9,
    halo2_ipa_config!(true, 1),
    StandardPlonk::rand(ChaCha20Rng::from_seed(Default::default()))
);
