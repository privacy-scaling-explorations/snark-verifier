#![allow(unused_imports)]
use super::{read_instances, write_instances, CircuitExt, PlonkSuccinctVerifier, Snark};
use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::Layouter,
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        group::ff::Field,
    },
    plonk::{
        create_proof, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error, ProvingKey,
        VerifyingKey,
    },
    poly::{
        commitment::{ParamsProver, Prover, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            msm::DualMSM,
            multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
            strategy::{AccumulatorStrategy, GuardKZG},
        },
        VerificationStrategy,
    },
};
use halo2curves::CurveAffine;
use itertools::Itertools;
use lazy_static::lazy_static;
use poseidon::Spec as PoseidonSpec;
use rand::{rngs::StdRng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use snark_verifier::{
    cost::CostEstimation,
    loader::native::NativeLoader,
    pcs::{
        kzg::{KzgAccumulator, KzgAsVerifyingKey, KzgSuccinctVerifyingKey},
        AccumulationScheme, PolynomialCommitmentScheme, Query,
    },
    system::halo2::{compile, Config},
    util::transcript::TranscriptWrite,
    verifier::plonk::PlonkProof,
};
use std::{
    env::var,
    fs::{self, File},
    io::{BufReader, BufWriter},
    marker::PhantomData,
    path::Path,
};

pub mod aggregation;

// Different Poseidon parameters can be set based on usage and security level
const T: usize = 5; // 3;
const RATE: usize = T - 1;
const R_F: usize = 8;
const R_P: usize = 60; // 57;

pub type PoseidonTranscript<L, S> =
    snark_verifier::system::halo2::transcript::halo2::PoseidonTranscript<
        G1Affine,
        L,
        S,
        T,
        RATE,
        R_F,
        R_P,
    >;

lazy_static! {
    /// Poseidon spec recomputed matrix round constants each time so it is expensive to create.
    /// We use lazy_static to create it only once and then clone as needed.
    pub static ref POSEIDON_SPEC: PoseidonSpec<Fr, T, RATE> = PoseidonSpec::new(R_F, R_P);
}

/// Attempts to read the srs from a file found in `./params/kzg_bn254_{k}.srs` or `{dir}/kzg_bn254_{k}.srs` if `PARAMS_DIR` env var is specified, creates a file it if it does not exist.
/// * `k`: degree that expresses the size of circuit (i.e., 2^<sup>k</sup> is the number of rows in the circuit)
/// * `setup`: a function that creates the srs
pub fn read_or_create_srs<'a, C: CurveAffine, P: ParamsProver<'a, C>>(
    k: u32,
    setup: impl Fn(u32) -> P,
) -> P {
    let dir = var("PARAMS_DIR").unwrap_or_else(|_| "./params".to_string());
    let path = format!("{dir}/kzg_bn254_{k}.srs");
    match File::open(path.as_str()) {
        Ok(f) => {
            #[cfg(feature = "display")]
            println!("read params from {path}");
            let mut reader = BufReader::new(f);
            P::read(&mut reader).unwrap()
        }
        Err(_) => {
            #[cfg(feature = "display")]
            println!("creating params for {k}");
            fs::create_dir_all(dir).unwrap();
            let params = setup(k);
            params
                .write(&mut BufWriter::new(File::create(path).unwrap()))
                .unwrap();
            params
        }
    }
}

/// Generates the SRS for the KZG scheme and writes it to a file found in "./params/kzg_bn2_{k}.srs` or `{dir}/kzg_bn254_{k}.srs` if `PARAMS_DIR` env var is specified, creates a file it if it does not exist"
/// * `k`: degree that expresses the size of circuit (i.e., 2^<sup>k</sup> is the number of rows in the circuit)
pub fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    read_or_create_srs::<G1Affine, _>(k, |k| {
        ParamsKZG::<Bn256>::setup(k, ChaCha20Rng::from_seed(Default::default()))
    })
}

/// Generates a native proof using either SHPLONK or GWC proving method. Uses Poseidon for Fiat-Shamir.
///
/// Caches the instances and proof if `path = Some(instance_path, proof_path)` is specified.
pub fn gen_proof<'params, C, P, V>(
    // TODO: pass Option<&'params ParamsKZG<Bn256>> but hard to get lifetimes to work with `Cow`
    params: &'params ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
    path: Option<(impl AsRef<Path>, impl AsRef<Path>)>,
) -> Vec<u8>
where
    C: Circuit<Fr>,
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    if let Some((instance_path, proof_path)) = &path {
        let proof_path = proof_path.as_ref();
        let cached_instances = read_instances(instance_path.as_ref());
        if matches!(cached_instances, Ok(tmp) if tmp == instances) && proof_path.exists() {
            #[cfg(feature = "display")]
            let read_time = start_timer!(|| format!("Reading proof from {proof_path:?}"));

            let proof = fs::read(proof_path).unwrap();

            #[cfg(feature = "display")]
            end_timer!(read_time);
            return proof;
        }
    }

    let instances = instances.iter().map(Vec::as_slice).collect_vec();

    #[cfg(feature = "display")]
    let proof_time = start_timer!(|| "Create proof");

    let mut transcript =
        PoseidonTranscript::<NativeLoader, _>::from_spec(vec![], POSEIDON_SPEC.clone());
    let rng = StdRng::from_entropy();
    create_proof::<_, P, _, _, _, _>(params, pk, &[circuit], &[&instances], rng, &mut transcript)
        .unwrap();
    let proof = transcript.finalize();

    #[cfg(feature = "display")]
    end_timer!(proof_time);

    // validate proof before caching
    assert!({
        let mut transcript_read =
            PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&proof[..], POSEIDON_SPEC.clone());
        VerificationStrategy::<_, V>::finalize(
            verify_proof::<_, V, _, _, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript_read,
            )
            .unwrap(),
        )
    });

    if let Some((instance_path, proof_path)) = path {
        write_instances(&instances, instance_path);
        fs::write(proof_path, &proof).unwrap();
    }

    proof
}

/// Generates a native proof using original Plonk (GWC '19) multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Caches the instances and proof if `path = Some(instance_path, proof_path)` is specified.
pub fn gen_proof_gwc<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
    path: Option<(&Path, &Path)>,
) -> Vec<u8> {
    gen_proof::<C, ProverGWC<_>, VerifierGWC<_>>(params, pk, circuit, instances, path)
}

/// Generates a native proof using SHPLONK multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Caches the instances and proof if `path` is specified.
pub fn gen_proof_shplonk<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
    path: Option<(&Path, &Path)>,
) -> Vec<u8> {
    gen_proof::<C, ProverSHPLONK<_>, VerifierSHPLONK<_>>(params, pk, circuit, instances, path)
}

/// Generates a SNARK using either SHPLONK or GWC multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Tries to first deserialize from / later serialize the entire SNARK into `path` if specified.
/// Serialization is done using `bincode`.
pub fn gen_snark<'params, ConcreteCircuit, P, V>(
    params: &'params ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    path: Option<impl AsRef<Path>>,
) -> Snark
where
    ConcreteCircuit: CircuitExt<Fr>,
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    #[cfg(feature = "derive_serde")]
    if let Some(path) = &path {
        if let Ok(snark) = read_snark(path) {
            return snark;
        }
    }
    let protocol = compile(
        params,
        pk.get_vk(),
        Config::kzg()
            .with_num_instance(circuit.num_instance())
            .with_accumulator_indices(ConcreteCircuit::accumulator_indices()),
    );

    let instances = circuit.instances();
    #[cfg(feature = "derive_serde")]
    let proof = gen_proof::<ConcreteCircuit, P, V>(
        params,
        pk,
        circuit,
        instances.clone(),
        None::<(&str, &str)>,
    );
    // If we can't serialize the entire snark, at least serialize the proof
    #[cfg(not(feature = "derive_serde"))]
    let proof = {
        let path = path.map(|path| {
            let path = path.as_ref().to_str().unwrap();
            (format!("{path}.instances"), format!("{path}.proof"))
        });
        let paths = path
            .as_ref()
            .map(|path| (Path::new(&path.0), Path::new(&path.1)));
        gen_proof::<ConcreteCircuit, P, V>(params, pk, circuit, instances.clone(), paths)
    };

    let snark = Snark::new(protocol, instances, proof);
    #[cfg(feature = "derive_serde")]
    if let Some(path) = &path {
        let f = File::create(path).unwrap();
        #[cfg(feature = "display")]
        let write_time = start_timer!(|| "Write SNARK");
        bincode::serialize_into(f, &snark).unwrap();
        #[cfg(feature = "display")]
        end_timer!(write_time);
    }
    #[allow(clippy::let_and_return)]
    snark
}

/// Generates a SNARK using GWC multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Tries to first deserialize from / later serialize the entire SNARK into `path` if specified.
/// Serialization is done using `bincode`.
pub fn gen_snark_gwc<ConcreteCircuit: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    path: Option<impl AsRef<Path>>,
) -> Snark {
    gen_snark::<ConcreteCircuit, ProverGWC<_>, VerifierGWC<_>>(params, pk, circuit, path)
}

/// Generates a SNARK using SHPLONK multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Tries to first deserialize from / later serialize the entire SNARK into `path` if specified.
/// Serialization is done using `bincode`.
pub fn gen_snark_shplonk<ConcreteCircuit: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    path: Option<impl AsRef<Path>>,
) -> Snark {
    gen_snark::<ConcreteCircuit, ProverSHPLONK<_>, VerifierSHPLONK<_>>(params, pk, circuit, path)
}

/// Tries to deserialize a SNARK from the specified `path` using `bincode`.
///
/// WARNING: The user must keep track of whether the SNARK was generated using the GWC or SHPLONK multi-open scheme.
#[cfg(feature = "derive_serde")]
pub fn read_snark(path: impl AsRef<Path>) -> Result<Snark, bincode::Error> {
    let f = File::open(path).map_err(Box::<bincode::ErrorKind>::from)?;
    bincode::deserialize_from(f)
}
