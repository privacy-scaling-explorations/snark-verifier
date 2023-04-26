use crate::util::arithmetic::{CurveAffine, FromUniformBytes, WithSmallOrderMulGroup};
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, verify_proof, Circuit, ProvingKey},
    poly::{
        commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand_chacha::rand_core::RngCore;
use std::{fs, io::Cursor};

mod circuit;
mod ipa;
mod kzg;

pub use circuit::{
    maingate::{MainGateWithRange, MainGateWithRangeConfig},
    standard::StandardPlonk,
};

pub fn read_or_create_srs<'a, C: CurveAffine, P: ParamsProver<'a, C>>(
    dir: &str,
    k: u32,
    setup: impl Fn(u32) -> P,
) -> P {
    let path = format!("{}/k-{}.srs", dir, k);
    match fs::File::open(path.as_str()) {
        Ok(mut file) => P::read(&mut file).unwrap(),
        Err(_) => {
            fs::create_dir_all(dir).unwrap();
            let params = setup(k);
            params.write(&mut fs::File::create(path).unwrap()).unwrap();
            params
        }
    }
}

pub fn create_proof_checked<'a, S, C, P, V, VS, TW, TR, EC, R>(
    params: &'a S::ParamsProver,
    pk: &ProvingKey<S::Curve>,
    circuits: &[C],
    instances: &[&[&[S::Scalar]]],
    mut rng: R,
    finalize: impl Fn(Vec<u8>, VS::Output) -> Vec<u8>,
) -> Vec<u8>
where
    S: CommitmentScheme,
    S::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64> + Ord,
    S::ParamsVerifier: 'a,
    C: Circuit<S::Scalar>,
    P: Prover<'a, S>,
    V: Verifier<'a, S>,
    VS: VerificationStrategy<'a, S, V>,
    TW: TranscriptWriterBuffer<Vec<u8>, S::Curve, EC>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, S::Curve, EC>,
    EC: EncodedChallenge<S::Curve>,
    R: RngCore,
{
    for (circuit, instances) in circuits.iter().zip(instances.iter()) {
        MockProver::run(
            params.k(),
            circuit,
            instances.iter().map(|instance| instance.to_vec()).collect(),
        )
        .unwrap()
        .assert_satisfied();
    }

    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<S, P, _, _, _, _>(
            params,
            pk,
            circuits,
            instances,
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let output = {
        let params = params.verifier_params();
        let strategy = VS::new(params);
        let mut transcript = TR::init(Cursor::new(proof.clone()));
        verify_proof(params, pk.get_vk(), strategy, instances, &mut transcript).unwrap()
    };

    finalize(proof, output)
}

macro_rules! halo2_prepare {
    ($dir:expr, $k:expr, $setup:expr, $config:expr, $create_circuit:expr) => {{
        use halo2_proofs::plonk::{keygen_pk, keygen_vk};
        use std::iter;
        use $crate::{
            system::halo2::{compile, test::read_or_create_srs},
            util::{arithmetic::GroupEncoding, Itertools},
        };

        let params = read_or_create_srs($dir, $k, $setup);

        let circuits = iter::repeat_with(|| $create_circuit)
            .take($config.num_proof)
            .collect_vec();

        let pk = if $config.zk {
            let vk = keygen_vk(&params, &circuits[0]).unwrap();
            let pk = keygen_pk(&params, vk, &circuits[0]).unwrap();
            pk
        } else {
            // TODO: Re-enable optional-zk when it's merged in pse/halo2.
            unimplemented!()
        };

        let num_instance = circuits[0]
            .instances()
            .iter()
            .map(|instances| instances.len())
            .collect();
        let protocol = compile(
            &params,
            pk.get_vk(),
            $config.with_num_instance(num_instance),
        );
        assert_eq!(
            protocol.preprocessed.len(),
            protocol
                .preprocessed
                .iter()
                .map(
                    |ec_point| <[u8; 32]>::try_from(ec_point.to_bytes().as_ref().to_vec()).unwrap()
                )
                .unique()
                .count()
        );

        (params, pk, protocol, circuits)
    }};
}

macro_rules! halo2_create_snark {
    (
        $commitment_scheme:ty,
        $prover:ty,
        $verifier:ty,
        $verification_strategy:ty,
        $transcript_read:ty,
        $transcript_write:ty,
        $encoded_challenge:ty,
        $finalize:expr,
        $params:expr,
        $pk:expr,
        $protocol:expr,
        $circuits:expr
    ) => {{
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        use $crate::{
            loader::halo2::test::Snark, system::halo2::test::create_proof_checked, util::Itertools,
        };

        let instances = $circuits
            .iter()
            .map(|circuit| circuit.instances())
            .collect_vec();
        let proof = {
            #[allow(clippy::needless_borrow)]
            let instances = instances
                .iter()
                .map(|instances| instances.iter().map(Vec::as_slice).collect_vec())
                .collect_vec();
            let instances = instances.iter().map(Vec::as_slice).collect_vec();
            create_proof_checked::<
                $commitment_scheme,
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
                $finalize,
            )
        };

        Snark::new(
            $protocol.clone(),
            instances.into_iter().flatten().collect_vec(),
            proof,
        )
    }};
}

macro_rules! halo2_native_verify {
    (
        $plonk_verifier:ty,
        $params:expr,
        $protocol:expr,
        $instances:expr,
        $transcript:expr,
        $vk:expr
    ) => {{
        use halo2_proofs::poly::commitment::ParamsProver;
        use $crate::verifier::SnarkVerifier;

        let proof = <$plonk_verifier>::read_proof($vk, $protocol, $instances, $transcript).unwrap();
        assert!(<$plonk_verifier>::verify($vk, $protocol, $instances, &proof).is_ok())
    }};
}

pub(crate) use {halo2_create_snark, halo2_native_verify, halo2_prepare};
