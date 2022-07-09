use crate::{
    protocol::halo2::test::MainGateWithRange,
    util::{fe_to_limbs, Field},
};
use halo2_curves::{pairing::Engine, CurveAffine};
use halo2_proofs::poly::{
    commitment::{CommitmentScheme, Params, ParamsProver},
    kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{fmt::Debug, fs, iter};

mod halo2;
mod native;

#[cfg(feature = "evm")]
mod evm;

pub const LIMBS: usize = 4;
pub const BITS: usize = 68;

pub fn read_or_create_srs<E: Engine + Debug>(k: u32) -> ParamsKZG<E> {
    const DIR: &str = "./src/protocol/halo2/test/kzg/fixture";
    let path = format!("{}/k-{}.srs", DIR, k);
    match fs::File::open(path.as_str()) {
        Ok(mut file) => ParamsKZG::<E>::read(&mut file).unwrap(),
        Err(_) => {
            fs::create_dir_all(DIR).unwrap();
            let params =
                KZGCommitmentScheme::<E>::new_params(k, ChaCha20Rng::from_seed(Default::default()));
            let mut file = fs::File::create(path.as_str()).unwrap();
            params.write(&mut file).unwrap();
            params
        }
    }
}

pub fn main_gate_with_range_with_kzg_accumulator<E: Engine + Debug>() -> MainGateWithRange<E::Scalar>
{
    let g = read_or_create_srs::<E>(3).get_g();
    let (g1, s_g1) = (g[0], g[1]);
    MainGateWithRange::new(
        iter::once(E::Scalar::zero())
            .chain({
                let g1 = g1.coordinates().unwrap();
                let s_g1 = s_g1.coordinates().unwrap();
                [*s_g1.x(), *s_g1.y(), *g1.x(), *g1.y()]
                    .iter()
                    .cloned()
                    .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
            })
            .collect(),
    )
}

#[macro_export]
macro_rules! halo2_kzg_config {
    ($zk:expr, $num_proof:expr) => {
        $crate::protocol::halo2::Config {
            zk: $zk,
            query_instance: false,
            num_proof: $num_proof,
            accumulator_indices: None,
        }
    };
    ($zk:expr, $num_proof:expr, $accumulator_indices:expr) => {
        $crate::protocol::halo2::Config {
            zk: $zk,
            query_instance: false,
            num_proof: $num_proof,
            accumulator_indices: Some($accumulator_indices),
        }
    };
}

#[macro_export]
macro_rules! halo2_kzg_prepare {
    ($k:expr, $config:expr, $create_circuit:expr) => {{
        use halo2_curves::bn256::{Bn256, G1};
        use halo2_proofs::{
            plonk::{keygen_pk, keygen_vk},
            poly::kzg::commitment::KZGCommitmentScheme,
        };
        use std::{collections::BTreeSet, iter};
        use $crate::{
            protocol::halo2::{compile, test::kzg::read_or_create_srs},
            util::GroupEncoding,
        };

        let circuits = iter::repeat_with(|| $create_circuit)
            .take($config.num_proof)
            .collect::<Vec<_>>();

        let params = read_or_create_srs::<Bn256>($k);
        let vk = keygen_vk::<KZGCommitmentScheme<_>, _>(&params, &circuits[0]).unwrap();
        let pk = keygen_pk::<KZGCommitmentScheme<_>, _>(&params, vk, &circuits[0]).unwrap();

        let protocol = compile::<G1>(pk.get_vk(), $config);

        assert_eq!(
            protocol.preprocessed.len(),
            BTreeSet::<[u8; 32]>::from_iter(
                protocol.preprocessed.iter().map(|ec_point| ec_point
                    .to_bytes()
                    .as_ref()
                    .to_vec()
                    .try_into()
                    .unwrap())
            )
            .len()
        );

        (params, pk, protocol, circuits)
    }};
}

#[macro_export]
macro_rules! halo2_kzg_create_snark {
    ($params:expr, $pk:expr, $protocol:expr, $circuits:expr, $prover:ty, $verifier:ty, $verification_strategy:ty, $transcript_read:ty, $transcript_write:ty, $encoded_challenge:ty) => {{
        use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        use $crate::{
            collect_slice,
            protocol::halo2::test::{create_proof_checked, Snark},
        };

        let instances = $circuits
            .iter()
            .map(|circuit| circuit.instances())
            .collect::<Vec<_>>();
        let proof = {
            collect_slice!(instances, 2);
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
        };

        Snark::new(
            $protocol.clone(),
            instances.into_iter().flatten().collect::<Vec<_>>(),
            proof,
        )
    }};
}

#[macro_export]
macro_rules! halo2_kzg_native_accumulate {
    ($protocol:expr, $statements:expr, $scheme:ty, $transcript:expr, $stretagy:expr) => {{
        use $crate::{loader::native::NativeLoader, scheme::kzg::AccumulationScheme};

        <$scheme>::accumulate(
            $protocol,
            &NativeLoader,
            $statements,
            $transcript,
            $stretagy,
        )
        .unwrap();
    }};
}

#[macro_export]
macro_rules! halo2_kzg_native_verify {
    ($params:ident, $protocol:expr, $statements:expr, $scheme:ty, $transcript:expr) => {{
        use halo2_curves::bn256::Bn256;
        use halo2_proofs::poly::commitment::ParamsProver;
        use $crate::{
            halo2_kzg_native_accumulate,
            protocol::halo2::test::kzg::{BITS, LIMBS},
            scheme::kzg::SameCurveAccumulation,
        };

        let mut stretagy = SameCurveAccumulation::<_, _, LIMBS, BITS>::default();
        halo2_kzg_native_accumulate!($protocol, $statements, $scheme, $transcript, &mut stretagy);

        assert!(stretagy.decide::<Bn256>($params.get_g()[0], $params.g2(), $params.s_g2()));
    }};
}
