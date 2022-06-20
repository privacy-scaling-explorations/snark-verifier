use crate::{
    collect_slice, halo2_native_verify, halo2_prepare,
    protocol::halo2::{test::BigCircuit, transcript::Blake2bTranscript},
    scheme::kzg::{PlonkAccumulator, ShplonkAccumulator},
};
use halo2_proofs::{
    halo2curves::bn256::Fr,
    poly::kzg::strategy::BatchVerifier,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};

#[test]
fn test_shplonk_native() {
    use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};

    const K: u32 = 9;
    const N: usize = 2;

    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg] K, N, BigCircuit::<Fr>,
        ProverSHPLONK<_>,
        VerifierSHPLONK<_>,
        BatchVerifier<_, _>,
        Blake2bWrite<_, _, _>,
        Blake2bRead<_, _, _>,
        Challenge255<_>
    );

    halo2_native_verify!(
        params,
        protocol,
        instances,
        ShplonkAccumulator::new(),
        Blake2bTranscript::new(proof.as_slice())
    );
}

#[test]
fn test_plonk_native() {
    use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};

    const K: u32 = 9;
    const N: usize = 2;

    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg] K, N, BigCircuit::<Fr>,
        ProverGWC<_>,
        VerifierGWC<_>,
        BatchVerifier<_, _>,
        Blake2bWrite<_, _, _>,
        Blake2bRead<_, _, _>,
        Challenge255<_>
    );

    halo2_native_verify!(
        params,
        protocol,
        instances,
        PlonkAccumulator::new(),
        Blake2bTranscript::new(proof.as_slice())
    );
}
