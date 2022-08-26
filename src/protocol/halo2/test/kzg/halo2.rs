use crate::{
    collect_slice, halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_accumulate,
    halo2_kzg_native_verify, halo2_kzg_prepare,
    loader::{halo2, native::NativeLoader},
    protocol::{
        halo2::{
            test::{
                kzg::{BITS, LIMBS},
                MainGateWithRange, MainGateWithRangeConfig, StandardPlonk,
            },
            util::halo2::ChallengeScalar,
        },
        Protocol, Snark,
    },
    scheme::kzg::{self, AccumulationScheme, ShplonkAccumulationScheme},
    util::{fe_to_limbs, Curve, Group, Itertools, PrimeCurveAffine},
};
use halo2_curves::{
    bn256::{Fq, Fr, G1Affine, G1},
    CurveAffine,
};
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk,
    plonk::Circuit,
    poly::{
        commitment::ParamsProver,
        kzg::{
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

type BaseFieldEccChip<C> = halo2_wrong_ecc::BaseFieldEccChip<C, LIMBS, BITS>;
type Halo2Loader<'a, C> =
    halo2::Halo2Loader<'a, C, <C as CurveAffine>::ScalarExt, BaseFieldEccChip<C>>;
type PoseidonTranscript<C, L, S, B> = halo2::PoseidonTranscript<
    C,
    <C as CurveAffine>::ScalarExt,
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
type SameCurveAccumulation<C, L> = kzg::SameCurveAccumulation<C, L, LIMBS, BITS>;

pub struct SnarkWitness<C: Curve> {
    protocol: Protocol<C>,
    instances: Vec<Vec<Value<<C as Group>::Scalar>>>,
    proof: Value<Vec<u8>>,
}

impl<C: Curve> From<Snark<C>> for SnarkWitness<C> {
    fn from(snark: Snark<C>) -> Self {
        Self {
            protocol: snark.protocol,
            instances: snark
                .instances
                .into_iter()
                .map(|instances| instances.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

impl<C: Curve> SnarkWitness<C> {
    pub fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            instances: self
                .instances
                .iter()
                .map(|instances| vec![Value::unknown(); instances.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }
}

pub fn accumulate<'a>(
    loader: &Rc<Halo2Loader<'a, G1Affine>>,
    stretagy: &mut SameCurveAccumulation<G1, Rc<Halo2Loader<'a, G1Affine>>>,
    snark: &SnarkWitness<G1>,
) -> Result<(), plonk::Error> {
    let mut transcript = PoseidonTranscript::<_, Rc<Halo2Loader<G1Affine>>, _, _>::new(
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
    ShplonkAccumulationScheme::accumulate(
        &snark.protocol,
        loader,
        instances,
        &mut transcript,
        stretagy,
    )
    .map_err(|_| plonk::Error::Synthesis)?;
    Ok(())
}

pub struct Accumulation {
    g1: G1Affine,
    snarks: Vec<SnarkWitness<G1>>,
    instances: Vec<Fr>,
}

impl Accumulation {
    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
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
                &params,
                &pk,
                &protocol,
                &circuits,
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                AccumulatorStrategy<_>,
                PoseidonTranscript<_, _, _, _>,
                PoseidonTranscript<_, _, _, _>,
                ChallengeScalar<_>
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
                &params,
                &pk,
                &protocol,
                &circuits,
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                AccumulatorStrategy<_>,
                PoseidonTranscript<_, _, _, _>,
                PoseidonTranscript<_, _, _, _>,
                ChallengeScalar<_>
            )
        };

        let mut strategy = SameCurveAccumulation::<G1, NativeLoader>::default();
        halo2_kzg_native_accumulate!(
            &snark1.protocol,
            snark1.instances.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark1.proof.as_slice()),
            &mut strategy
        );
        halo2_kzg_native_accumulate!(
            &snark2.protocol,
            snark2.instances.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark2.proof.as_slice()),
            &mut strategy
        );

        let g1 = params.get_g()[0];
        let accumulator = strategy.finalize(g1.to_curve());
        let instances = [
            accumulator.0.to_affine().x,
            accumulator.0.to_affine().y,
            accumulator.1.to_affine().x,
            accumulator.1.to_affine().y,
        ]
        .map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .concat();

        Self {
            g1,
            snarks: vec![snark1.into(), snark2.into()],
            instances,
        }
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
            &params,
            &pk,
            &protocol,
            &circuits,
            ProverSHPLONK<_>,
            VerifierSHPLONK<_>,
            AccumulatorStrategy<_>,
            PoseidonTranscript<_, _, _, _>,
            PoseidonTranscript<_, _, _, _>,
            ChallengeScalar<_>
        );

        let mut strategy = SameCurveAccumulation::<G1, NativeLoader>::default();
        halo2_kzg_native_accumulate!(
            &snark.protocol,
            snark.instances.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark.proof.as_slice()),
            &mut strategy
        );

        let g1 = params.get_g()[0];
        let accumulator = strategy.finalize(g1.to_curve());
        let instances = [
            accumulator.0.to_affine().x,
            accumulator.0.to_affine().y,
            accumulator.1.to_affine().x,
            accumulator.1.to_affine().y,
        ]
        .map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .concat();

        Self {
            g1,
            snarks: vec![snark.into()],
            instances,
        }
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
                let loader = Halo2Loader::<G1Affine>::new(ecc_chip, ctx);
                let mut stretagy = SameCurveAccumulation::default();
                for snark in self.snarks.iter() {
                    accumulate(&loader, &mut stretagy, snark)?;
                }
                let (lhs, rhs) = stretagy.finalize(self.g1);

                loader.print_row_metering();
                println!("Total row cost: {}", loader.ctx().offset());

                Ok((lhs, rhs))
            },
        )?;

        for (limb, row) in iter::empty()
            .chain(lhs.get_x().limbs())
            .chain(lhs.get_y().limbs())
            .chain(rhs.get_x().limbs())
            .chain(rhs.get_y().limbs())
            .zip(0..)
        {
            main_gate.expose_public(layouter.namespace(|| ""), limb.into(), row)?;
        }

        Ok(())
    }
}

macro_rules! test {
    (@ #[$($attr:meta),*], $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        paste! {
            $(#[$attr])*
            fn [<test_kzg_shplonk_ $name>]() {
                let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                    $k,
                    $config,
                    $create_circuit
                );
                let snark = halo2_kzg_create_snark!(
                    &params,
                    &pk,
                    &protocol,
                    &circuits,
                    ProverSHPLONK<_>,
                    VerifierSHPLONK<_>,
                    AccumulatorStrategy<_>,
                    Blake2bWrite<_, _, _>,
                    Blake2bRead<_, _, _>,
                    Challenge255<_>
                );
                halo2_kzg_native_verify!(
                    params,
                    &snark.protocol,
                    snark.instances,
                    ShplonkAccumulationScheme,
                    &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
                );
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test], $name, $k, $config, $create_circuit);
    };
    (#[ignore = $reason:literal], $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test, ignore = $reason], $name, $k, $config, $create_circuit);
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
