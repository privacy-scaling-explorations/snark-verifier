use crate::{
    collect_slice, halo2_native_verify, halo2_prepare,
    protocol::halo2::test::MainGateWithRange,
    scheme::kzg::{PlonkAccumulator, ShplonkAccumulator},
};
use halo2_curves::bn256::G1Affine;
use halo2_proofs::{
    poly::kzg::{
        multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
        strategy::BatchVerifier,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};

#[test]
fn test_shplonk_native_main_gate_with_range() {
    const K: u32 = 9;
    const N: usize = 2;

    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg],
        K, N, None, MainGateWithRange::<_>,
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
        protocol,
        instances,
        ShplonkAccumulator::default(),
        Blake2bRead::<_, G1Affine, _>::init(proof.as_slice())
    );
}

#[test]
fn test_plonk_native_main_gate_with_range() {
    const K: u32 = 9;
    const N: usize = 2;

    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg],
        K, N, None, MainGateWithRange::<_>,
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
        protocol,
        instances,
        PlonkAccumulator::default(),
        Blake2bRead::<_, G1Affine, _>::init(proof.as_slice())
    );
}
