use crate::{
    loader,
    loader::halo2::test::{
        MainGateWithRange, MainGateWithRangeConfig, Snark, SnarkWitness, StandardPlonk,
    },
    pcs::{
        kzg::{Accumulator, Bdfg21, KzgOnSameCurve, PreAccumulator},
        PreAccumulator as _,
    },
    system::{
        self,
        halo2::{
            test::kzg::{
                halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_verify,
                halo2_kzg_prepare, BITS, LIMBS,
            },
            transcript::halo2::ChallengeScalar,
        },
    },
    util::{arithmetic::fe_to_limbs, transcript::Transcript, Itertools},
    verifier::{self, PlonkVerifier},
};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    plonk,
    plonk::Circuit,
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::ParamsKZG,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use halo2_wrong_ecc::{
    self,
    integer::rns::Rns,
    maingate::{MainGateInstructions, RangeInstructions, RegionCtx},
};
use halo2_wrong_transcript::NativeRepresentation;
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{iter, rc::Rc};

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 57;

type BaseFieldEccChip = halo2_wrong_ecc::BaseFieldEccChip<G1Affine, LIMBS, BITS>;
type Halo2Loader<'a> = loader::halo2::Halo2Loader<'a, G1Affine, Fr, BaseFieldEccChip>;
type PoseidonTranscript<G1Affine, L, S, B> = system::halo2::transcript::halo2::PoseidonTranscript<
    G1Affine,
    Fr,
    NativeRepresentation,
    L,
    S,
    B,
    LIMBS,
    BITS,
    T,
    RATE,
    R_F,
    R_P,
>;
type Shplonk = verifier::Plonk<KzgOnSameCurve<Bn256, Bdfg21<Bn256>, LIMBS, BITS>>;

pub fn accumulate<'a>(
    g1: &G1Affine,
    loader: &Rc<Halo2Loader<'a>>,
    snark: &SnarkWitness<G1Affine>,
    curr_accumulator: Option<PreAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>,
) -> PreAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
    let mut transcript = PoseidonTranscript::<_, Rc<Halo2Loader>, _, _>::new(
        loader,
        snark.proof.as_ref().map(|proof| proof.as_slice()),
    );
    let instances = snark
        .instances
        .iter()
        .map(|instances| {
            instances
                .iter()
                .map(|instance| loader.assign_scalar(*instance))
                .collect_vec()
        })
        .collect_vec();
    let proof = Shplonk::read_proof(&snark.protocol, &instances, &mut transcript).unwrap();
    let mut accumulator = Shplonk::succint_verify(g1, &snark.protocol, &instances, &proof).unwrap();
    if let Some(curr_accumulator) = curr_accumulator {
        accumulator += curr_accumulator * transcript.squeeze_challenge();
    }
    accumulator
}

pub struct Accumulation {
    g1: G1Affine,
    snarks: Vec<SnarkWitness<G1Affine>>,
    instances: Vec<Fr>,
}

impl Accumulation {
    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
    }

    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: impl IntoIterator<Item = Snark<G1Affine>>,
    ) -> Self {
        let g1 = params.get_g()[0];
        let snarks = snarks.into_iter().collect_vec();

        let accumulator = snarks
            .iter()
            .fold(None, |curr_accumulator, snark| {
                let mut transcript = PoseidonTranscript::init(snark.proof.as_slice());
                let proof = Shplonk::read_proof(&snark.protocol, &snark.instances, &mut transcript)
                    .unwrap();
                let mut accumulator =
                    Shplonk::succint_verify(&g1, &snark.protocol, &snark.instances, &proof)
                        .unwrap();
                if let Some(curr_accumulator) = curr_accumulator {
                    accumulator += curr_accumulator * transcript.squeeze_challenge();
                }
                Some(accumulator)
            })
            .unwrap();

        let Accumulator { lhs, rhs } = accumulator.evaluate();
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .concat();

        Self {
            g1,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
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
                AccumulatorStrategy<_>,
                PoseidonTranscript<_, _, _, _>,
                PoseidonTranscript<_, _, _, _>,
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
                AccumulatorStrategy<_>,
                PoseidonTranscript<_, _, _, _>,
                PoseidonTranscript<_, _, _, _>,
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
            const K: u32 = 21;
            halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(true, 2, Self::accumulator_indices()),
                Self::two_snark()
            )
        };
        let snark = halo2_kzg_create_snark!(
            ProverSHPLONK<_>,
            VerifierSHPLONK<_>,
            AccumulatorStrategy<_>,
            PoseidonTranscript<_, _, _, _>,
            PoseidonTranscript<_, _, _, _>,
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
}

impl Circuit<Fr> for Accumulation {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            g1: self.g1,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: Vec::new(),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
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
    ) -> Result<(), plonk::Error> {
        let main_gate = config.main_gate();
        let range_chip = config.range_chip();

        range_chip.load_table(&mut layouter)?;

        let (lhs, rhs) = layouter.assign_region(
            || "",
            |region| {
                let ctx = RegionCtx::new(region, 0);

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::new(ecc_chip, ctx);
                let accumulator = self
                    .snarks
                    .iter()
                    .fold(None, |accumulator, snark| {
                        Some(accumulate(&self.g1, &loader, snark, accumulator))
                    })
                    .unwrap();
                let Accumulator { lhs, rhs } = accumulator.evaluate();
                let (lhs, rhs) = (lhs.into_normalized(), rhs.into_normalized());

                loader.print_row_metering();
                println!("Total row cost: {}", loader.ctx().offset());

                Ok((lhs, rhs))
            },
        )?;

        for (limb, row) in iter::empty()
            .chain(lhs.x().limbs())
            .chain(lhs.y().limbs())
            .chain(rhs.x().limbs())
            .chain(rhs.y().limbs())
            .zip(0..)
        {
            main_gate.expose_public(layouter.namespace(|| ""), limb.into(), row)?;
        }

        Ok(())
    }
}

macro_rules! test {
    (@ $(#[$attr:meta],)* $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        paste! {
            $(#[$attr])*
            fn [<test_kzg_shplonk_ $name>]() {
                let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                    $k,
                    $config,
                    $create_circuit
                );
                let snark = halo2_kzg_create_snark!(
                    ProverSHPLONK<_>,
                    VerifierSHPLONK<_>,
                    AccumulatorStrategy<_>,
                    Blake2bWrite<_, _, _>,
                    Blake2bRead<_, _, _>,
                    Challenge255<_>,
                    &params,
                    &pk,
                    &protocol,
                    &circuits
                );
                halo2_kzg_native_verify!(
                    Shplonk,
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
    #[ignore = "cause it requires 16GB memory to run"],
    zk_accumulation_two_snark,
    21,
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
