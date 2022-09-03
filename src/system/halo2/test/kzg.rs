use crate::{
    system::halo2::test::MainGateWithRange,
    util::arithmetic::{fe_to_limbs, CurveAffine, MultiMillerLoop},
};
use halo2_proofs::poly::{
    commitment::{Params, ParamsProver},
    kzg::commitment::ParamsKZG,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::fs;

mod native;

#[cfg(feature = "loader_evm")]
mod evm;

#[cfg(feature = "loader_halo2")]
mod halo2;

pub const LIMBS: usize = 4;
pub const BITS: usize = 68;

pub fn read_or_create_srs<M: MultiMillerLoop>(k: u32) -> ParamsKZG<M> {
    const DIR: &str = "./src/system/halo2/test/kzg/testdata";
    let path = format!("{}/k-{}.srs", DIR, k);
    match fs::File::open(path.as_str()) {
        Ok(mut file) => ParamsKZG::<M>::read(&mut file).unwrap(),
        Err(_) => {
            fs::create_dir_all(DIR).unwrap();
            let params = ParamsKZG::<M>::setup(k, ChaCha20Rng::from_seed(Default::default()));
            params.write(&mut fs::File::create(path).unwrap()).unwrap();
            params
        }
    }
}

pub fn main_gate_with_range_with_mock_kzg_accumulator<M: MultiMillerLoop>(
) -> MainGateWithRange<M::Scalar> {
    let srs = read_or_create_srs::<M>(1);
    let [g1, s_g1] = [srs.get_g()[0], srs.get_g()[1]].map(|point| point.coordinates().unwrap());
    MainGateWithRange::new(
        [*s_g1.x(), *s_g1.y(), *g1.x(), *g1.y()]
            .iter()
            .cloned()
            .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .collect(),
    )
}

#[macro_export]
macro_rules! halo2_kzg_config {
    ($zk:expr, $num_proof:expr) => {
        $crate::system::halo2::Config {
            zk: $zk,
            query_instance: false,
            num_instance: Vec::new(),
            num_proof: $num_proof,
            accumulator_indices: None,
        }
    };
    ($zk:expr, $num_proof:expr, $accumulator_indices:expr) => {
        $crate::system::halo2::Config {
            zk: $zk,
            query_instance: false,
            num_instance: Vec::new(),
            num_proof: $num_proof,
            accumulator_indices: Some($accumulator_indices),
        }
    };
}

#[macro_export]
macro_rules! halo2_kzg_prepare {
    ($k:expr, $config:expr, $create_circuit:expr) => {{
        use $crate::{
            system::halo2::{compile, test::kzg::read_or_create_srs},
            util::{arithmetic::GroupEncoding, Itertools},
        };
        use halo2_curves::bn256::{Bn256, G1Affine};
        use halo2_proofs::{
            plonk::{keygen_pk, keygen_vk},
        };
        use std::{iter};

        let circuits = iter::repeat_with(|| $create_circuit)
            .take($config.num_proof)
            .collect_vec();

        let params = read_or_create_srs::<Bn256>($k);
        let pk = if $config.zk {
            let vk = keygen_vk(&params, &circuits[0]).unwrap();
            let pk = keygen_pk(&params, vk, &circuits[0]).unwrap();
            pk
        } else {
            // TODO: Re-enable optional-zk when it's merged in pse/halo2.
            unimplemented!()
        };

        let mut config = $config;
        config.num_instance = circuits[0].instances().iter().map(|instances| instances.len()).collect();
        let protocol = compile::<G1Affine>(pk.get_vk(), config);
        assert_eq!(
            protocol.preprocessed.len(),
            protocol.preprocessed
                .iter()
                .map(|ec_point| <[u8; 32]>::try_from(ec_point.to_bytes().as_ref().to_vec()).unwrap())
                .unique()
                .count()
        );

        (params, pk, protocol, circuits)
    }};
}

#[macro_export]
macro_rules! halo2_kzg_create_snark {
    ($prover:ty, $verifier:ty, $verification_strategy:ty, $transcript_read:ty, $transcript_write:ty, $encoded_challenge:ty, $params:expr, $pk:expr, $protocol:expr, $circuits:expr) => {{
        use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        use $crate::{
            collect_slice,
            system::halo2::test::{create_proof_checked, Snark},
            util::Itertools,
        };

        let instances = $circuits
            .iter()
            .map(|circuit| circuit.instances())
            .collect_vec();
        let proof = {
            collect_slice!(instances, 2);
            #[allow(clippy::needless_borrow)]
            if $protocol.zk {
                create_proof_checked::<
                    KZGCommitmentScheme<_>,
                    _,
                    $prover,
                    $verifier,
                    $verification_strategy,
                    $transcript_read,
                    $transcript_write,
                    $encoded_challenge,
                    _,
                >(
                    $params,
                    $pk,
                    $circuits,
                    &instances,
                    &mut ChaCha20Rng::from_seed(Default::default()),
                )
            } else {
                unimplemented!()
            }
        };

        Snark::new(
            $protocol.clone(),
            instances.into_iter().flatten().collect_vec(),
            proof,
        )
    }};
}

#[macro_export]
macro_rules! halo2_kzg_native_accumulate {
    ($plonk_verifier:ty, $params:expr, $protocol:expr, $instances:expr, $transcript:expr) => {{
        use $crate::verifier::PlonkVerifier;

        let proof = <$plonk_verifier>::read_proof($protocol, $instances, $transcript).unwrap();
        <$plonk_verifier>::succint_verify(
            &$params.get_g()[0],
            $protocol,
            $instances,
            $transcript,
            &proof,
        )
        .unwrap()
    }};
    ($plonk_verifier:ty, $params:expr, $protocol:expr, $instances:expr, $transcript:expr, $curr_accumulator:expr) => {{
        use $crate::{util::transcript::Transcript, verifier::PlonkVerifier};

        let proof = <$plonk_verifier>::read_proof($protocol, $instances, $transcript).unwrap();
        let accumulator = <$plonk_verifier>::succint_verify(
            &$params.get_g()[0],
            $protocol,
            $instances,
            $transcript,
            &proof,
        )
        .unwrap();
        accumulator + $curr_accumulator * $transcript.squeeze_challenge()
    }};
}

#[macro_export]
macro_rules! halo2_kzg_native_verify {
    ($plonk_verifier:ty, $params:expr, $protocol:expr, $instances:expr, $transcript:expr) => {{
        use halo2_proofs::poly::commitment::ParamsProver;
        use $crate::verifier::PlonkVerifier;

        assert!(<$plonk_verifier>::verify(
            &$params.get_g()[0],
            &($params.g2(), $params.s_g2()),
            $protocol,
            $instances,
            $transcript,
        )
        .unwrap())
    }};
}
