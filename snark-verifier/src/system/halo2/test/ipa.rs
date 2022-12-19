use crate::util::arithmetic::CurveAffine;
use halo2_proofs::poly::{
    commitment::{Params, ParamsProver},
    ipa::commitment::ParamsIPA,
};
use std::mem::size_of;

mod native;

pub const TESTDATA_DIR: &str = "./src/system/halo2/test/ipa/testdata";

pub fn setup<C: CurveAffine>(k: u32) -> ParamsIPA<C> {
    ParamsIPA::new(k)
}

pub fn w_u<C: CurveAffine>() -> (C, C) {
    let mut buf = Vec::new();
    setup::<C>(1).write(&mut buf).unwrap();

    let repr = C::Repr::default();
    let repr_len = repr.as_ref().len();
    let offset = size_of::<u32>() + 4 * repr_len;

    let [w, u] = [offset, offset + repr_len].map(|offset| {
        let mut repr = C::Repr::default();
        repr.as_mut()
            .copy_from_slice(&buf[offset..offset + repr_len]);
        C::from_bytes(&repr).unwrap()
    });

    (w, u)
}

macro_rules! halo2_ipa_config {
    ($zk:expr, $num_proof:expr) => {
        $crate::system::halo2::Config::ipa()
            .set_zk($zk)
            .with_num_proof($num_proof)
    };
    ($zk:expr, $num_proof:expr, $accumulator_indices:expr) => {
        $crate::system::halo2::Config::ipa()
            .set_zk($zk)
            .with_num_proof($num_proof)
            .with_accumulator_indices($accumulator_indices)
    };
}

macro_rules! halo2_ipa_prepare {
    ($dir:expr, $curve:path, $k:expr, $config:expr, $create_circuit:expr) => {{
        use $crate::system::halo2::test::{halo2_prepare, ipa::setup};

        halo2_prepare!($dir, $k, setup::<$curve>, $config, $create_circuit)
    }};
    (pallas::Affine, $k:expr, $config:expr, $create_circuit:expr) => {{
        use halo2_curves::pasta::pallas;
        use $crate::system::halo2::test::ipa::TESTDATA_DIR;

        halo2_ipa_prepare!(
            &format!("{TESTDATA_DIR}/pallas"),
            pallas::Affine,
            $k,
            $config,
            $create_circuit
        )
    }};
    (vesta::Affine, $k:expr, $config:expr, $create_circuit:expr) => {{
        use halo2_curves::pasta::vesta;
        use $crate::system::halo2::test::ipa::TESTDATA_DIR;

        halo2_ipa_prepare!(
            &format!("{TESTDATA_DIR}/vesta"),
            vesta::Affine,
            $k,
            $config,
            $create_circuit
        )
    }};
}

macro_rules! halo2_ipa_create_snark {
    (
        $prover:ty,
        $verifier:ty,
        $transcript_read:ty,
        $transcript_write:ty,
        $encoded_challenge:ty,
        $params:expr,
        $pk:expr,
        $protocol:expr,
        $circuits:expr
    ) => {{
        use halo2_proofs::poly::ipa::commitment::IPACommitmentScheme;
        use $crate::{
            system::halo2::{strategy::ipa::SingleStrategy, test::halo2_create_snark},
            util::arithmetic::GroupEncoding,
        };

        halo2_create_snark!(
            IPACommitmentScheme<_>,
            $prover,
            $verifier,
            SingleStrategy<_>,
            $transcript_read,
            $transcript_write,
            $encoded_challenge,
            |proof, g| { [proof, g.to_bytes().as_ref().to_vec()].concat() },
            $params,
            $pk,
            $protocol,
            $circuits
        )
    }};
}

macro_rules! halo2_ipa_native_verify {
    (
        $plonk_verifier:ty,
        $params:expr,
        $protocol:expr,
        $instances:expr,
        $transcript:expr
    ) => {{
        use $crate::{
            pcs::ipa::{IpaDecidingKey, IpaSuccinctVerifyingKey},
            system::halo2::test::{halo2_native_verify, ipa::w_u},
        };

        let (w, u) = w_u();
        halo2_native_verify!(
            $plonk_verifier,
            $params,
            $protocol,
            $instances,
            $transcript,
            &IpaDecidingKey::new(
                IpaSuccinctVerifyingKey::new(
                    $protocol.domain.clone(),
                    $params.get_g()[0],
                    u,
                    Some(w)
                ),
                $params.get_g().to_vec()
            )
        )
    }};
}

pub(crate) use {
    halo2_ipa_config, halo2_ipa_create_snark, halo2_ipa_native_verify, halo2_ipa_prepare,
};
