use crate::{
    loader::{
        self,
        halo2::test::{Snark, SnarkWitness},
        native::NativeLoader,
    },
    pcs::{
        kzg::{
            Bdfg21, KzgAccumulator, KzgAs, KzgAsProvingKey, KzgAsVerifyingKey,
            KzgSuccinctVerifyingKey, LimbsEncoding, LimbsEncodingInstructions,
        },
        AccumulationScheme, AccumulationSchemeProver,
    },
    system::{
        self,
        halo2::{
            test::{
                kzg::{
                    halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_verify,
                    halo2_kzg_prepare, BITS, LIMBS,
                },
                MainGateWithRange, MainGateWithRangeConfig, StandardPlonk,
            },
            transcript::halo2::ChallengeScalar,
        },
    },
    util::{arithmetic::fe_to_limbs, Itertools},
    verifier::{self, SnarkVerifier},
};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::ParamsKZG,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use halo2_wrong_ecc::{
    self,
    integer::rns::Rns,
    maingate::{MainGateInstructions, RangeInstructions, RegionCtx},
};
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::rc::Rc;

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 60;

type BaseFieldEccChip = halo2_wrong_ecc::BaseFieldEccChip<G1Affine, LIMBS, BITS>;
type Halo2Loader<'a> = loader::halo2::Halo2Loader<'a, G1Affine, BaseFieldEccChip>;
type PoseidonTranscript<L, S> =
    system::halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;

type Svk = KzgSuccinctVerifyingKey<G1Affine>;
type As = KzgAs<Bn256, Bdfg21>;
type AsPk = KzgAsProvingKey<G1Affine>;
type AsVk = KzgAsVerifyingKey;
type PlonkSuccinctVerifier = verifier::plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;

pub fn accumulate<'a>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    snarks: &[SnarkWitness<G1Affine>],
    as_vk: &AsVk,
    as_proof: Value<&'_ [u8]>,
) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
    let assign_instances = |instances: &[Vec<Value<Fr>>]| {
        instances
            .iter()
            .map(|instances| {
                instances
                    .iter()
                    .map(|instance| loader.assign_scalar(*instance))
                    .collect_vec()
            })
            .collect_vec()
    };

    let mut accumulators = snarks
        .iter()
        .flat_map(|snark| {
            let protocol = snark.protocol.loaded(loader);
            let instances = assign_instances(&snark.instances);
            let mut transcript =
                PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, snark.proof());
            let proof =
                PlonkSuccinctVerifier::read_proof(svk, &protocol, &instances, &mut transcript)
                    .unwrap();
            PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof).unwrap()
        })
        .collect_vec();

    let acccumulator = if accumulators.len() > 1 {
        let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, as_proof);
        let proof = As::read_proof(as_vk, &accumulators, &mut transcript).unwrap();
        As::verify(as_vk, &accumulators, &proof).unwrap()
    } else {
        accumulators.pop().unwrap()
    };

    acccumulator
}

pub struct Accumulation {
    svk: Svk,
    snarks: Vec<SnarkWitness<G1Affine>>,
    instances: Vec<Fr>,
    as_vk: AsVk,
    as_proof: Value<Vec<u8>>,
}

impl Accumulation {
    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
    }

    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: impl IntoIterator<Item = Snark<G1Affine>>,
    ) -> Self {
        let svk = params.get_g()[0].into();
        let snarks = snarks.into_iter().collect_vec();

        let mut accumulators = snarks
            .iter()
            .flat_map(|snark| {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _>::new(snark.proof.as_slice());
                let proof = PlonkSuccinctVerifier::read_proof(
                    &svk,
                    &snark.protocol,
                    &snark.instances,
                    &mut transcript,
                )
                .unwrap();
                PlonkSuccinctVerifier::verify(&svk, &snark.protocol, &snark.instances, &proof)
                    .unwrap()
            })
            .collect_vec();

        let as_pk = AsPk::new(Some((params.get_g()[0], params.get_g()[1])));
        let (accumulator, as_proof) = if accumulators.len() > 1 {
            let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
            let accumulator = As::create_proof(
                &as_pk,
                &accumulators,
                &mut transcript,
                ChaCha20Rng::from_seed(Default::default()),
            )
            .unwrap();
            (accumulator, Value::known(transcript.finalize()))
        } else {
            (accumulators.pop().unwrap(), Value::unknown())
        };

        let KzgAccumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .concat();

        Self {
            svk,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
            as_vk: as_pk.vk(),
            as_proof,
        }
    }

    pub fn two_snark() -> Self {
        let (params, snark1) = {
            const K: u32 = 9;
            let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(true, 1),
                StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
            );
            let snark = halo2_kzg_create_snark!(
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                PoseidonTranscript<_, _>,
                PoseidonTranscript<_, _>,
                ChallengeScalar<_>,
                &params,
                &pk,
                &protocol,
                &circuits
            );
            (params, snark)
        };
        let snark2 = {
            const K: u32 = 9;
            let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(true, 1),
                MainGateWithRange::rand(ChaCha20Rng::from_seed(Default::default()))
            );
            halo2_kzg_create_snark!(
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                PoseidonTranscript<_, _>,
                PoseidonTranscript<_, _>,
                ChallengeScalar<_>,
                &params,
                &pk,
                &protocol,
                &circuits
            )
        };
        Self::new(&params, [snark1, snark2])
    }

    pub fn two_snark_with_accumulator() -> Self {
        let (params, pk, protocol, circuits) = {
            const K: u32 = 22;
            halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(true, 2, Self::accumulator_indices()),
                Self::two_snark()
            )
        };
        let snark = halo2_kzg_create_snark!(
            ProverSHPLONK<_>,
            VerifierSHPLONK<_>,
            PoseidonTranscript<_, _>,
            PoseidonTranscript<_, _>,
            ChallengeScalar<_>,
            &params,
            &pk,
            &protocol,
            &circuits
        );
        Self::new(&params, [snark])
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl Circuit<Fr> for Accumulation {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;
    #[cfg(feature = "halo2_circuit_params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: Vec::new(),
            as_vk: self.as_vk,
            as_proof: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        MainGateWithRangeConfig::configure(
            meta,
            vec![BITS / LIMBS],
            Rns::<Fq, Fr, LIMBS, BITS>::construct().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let main_gate = config.main_gate();
        let range_chip = config.range_chip();

        range_chip.load_table(&mut layouter)?;

        let accumulator_limbs = layouter.assign_region(
            || "",
            |region| {
                let ctx = RegionCtx::new(region, 0);

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::new(ecc_chip, ctx);
                let accumulator = accumulate(
                    &self.svk,
                    &loader,
                    &self.snarks,
                    &self.as_vk,
                    self.as_proof(),
                );

                let accumulator_limbs = [accumulator.lhs, accumulator.rhs]
                    .iter()
                    .map(|ec_point| {
                        loader
                            .ecc_chip()
                            .assign_ec_point_to_limbs(&mut loader.ctx_mut(), ec_point.assigned())
                    })
                    .collect::<Result<Vec<_>, Error>>()?
                    .into_iter()
                    .flatten();

                loader.print_row_metering();
                println!("Total row cost: {}", loader.ctx().offset());

                Ok(accumulator_limbs)
            },
        )?;

        for (row, limb) in accumulator_limbs.enumerate() {
            main_gate.expose_public(layouter.namespace(|| ""), limb, row)?;
        }

        Ok(())
    }
}

macro_rules! test {
    (@ $(#[$attr:meta],)* $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        paste! {
            $(#[$attr])*
            fn [<test_shplonk_ $name>]() {
                let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                    $k,
                    $config,
                    $create_circuit
                );
                let snark = halo2_kzg_create_snark!(
                    ProverSHPLONK<_>,
                    VerifierSHPLONK<_>,
                    Blake2bWrite<_, _, _>,
                    Blake2bRead<_, _, _>,
                    Challenge255<_>,
                    &params,
                    &pk,
                    &protocol,
                    &circuits
                );
                halo2_kzg_native_verify!(
                    PlonkVerifier,
                    params,
                    &snark.protocol,
                    &snark.instances,
                    &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
                );
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test], $name, $k, $config, $create_circuit);
    };
    ($(#[$attr:meta],)* $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test] $(,#[$attr])*, $name, $k, $config, $create_circuit);
    };
}

test!(
    #[ignore = "cause it requires 32GB memory to run"],
    zk_accumulation_two_snark,
    22,
    halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark()
);
test!(
    #[ignore = "cause it requires 32GB memory to run"],
    zk_accumulation_two_snark_with_accumulator,
    22,
    halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark_with_accumulator()
);
