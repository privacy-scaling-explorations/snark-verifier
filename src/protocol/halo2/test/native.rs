use crate::{
    collect_slice, halo2_create_snark, halo2_native_verify, halo2_prepare,
    protocol::halo2::test::MainGateWithRange,
    scheme::kzg::{PlonkAccumulationScheme, ShplonkAccumulationScheme},
};
use halo2_curves::bn256::G1Affine;
use halo2_proofs::{
    poly::kzg::{
        multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
        strategy::BatchVerifier,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

#[test]
fn test_shplonk_native_main_gate_with_range() {
    const K: u32 = 9;
    const N: usize = 2;

    let (params, pk, protocol, circuits) = halo2_prepare!(
        [kzg],
        K,
        N,
        None,
        MainGateWithRange::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
    );
    let snark = halo2_create_snark!(
        [kzg],
        &params,
        &pk,
        &protocol,
        &circuits,
        ProverSHPLONK<_>,
        VerifierSHPLONK<_>,
        BatchVerifier<_, _>,
        Blake2bWrite<_, _, _>,
        Blake2bRead<_, _, _>,
        Challenge255<_>
    );
    halo2_native_verify!(
        [kzg],
        params,
        &snark.protocol,
        snark.statements,
        ShplonkAccumulationScheme,
        &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
    );
}

#[test]
fn test_plonk_native_main_gate_with_range() {
    const K: u32 = 9;
    const N: usize = 2;

    let (params, pk, protocol, circuits) = halo2_prepare!(
        [kzg],
        K,
        N,
        None,
        MainGateWithRange::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
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
        Blake2bWrite<_, _, _>,
        Blake2bRead<_, _, _>,
        Challenge255<_>
    );
    halo2_native_verify!(
        [kzg],
        params,
        &snark.protocol,
        snark.statements,
        PlonkAccumulationScheme,
        &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
    );
}
