use crate::{
    collect_slice, halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_accumulate,
    halo2_kzg_native_verify, halo2_kzg_prepare,
    loader::{halo2, native::NativeLoader},
    protocol::{
        halo2::{
            test::{
                circuit::maingate::PlookupRangeChip,
                kzg::{BITS, LIMBS},
                MainGateWithPlookupRange, MainGateWithPlookupRangeConfig, StandardPlonk,
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
    integer::{rns::Rns, IntegerChip},
    maingate::{MainGate, MainGateInstructions, RangeInstructions, RegionCtx},
};
use halo2_wrong_transcript::NativeRepresentation;
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{iter, rc::Rc};

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 57;

type BaseFieldEccChip<C> = halo2_wrong_ecc::BaseFieldEccChip<
    C,
    IntegerChip<
        <C as CurveAffine>::Base,
        <C as CurveAffine>::ScalarExt,
        MainGate<<C as CurveAffine>::ScalarExt>,
        PlookupRangeChip<<C as CurveAffine>::ScalarExt, false>,
        LIMBS,
        BITS,
    >,
>;
type Halo2Loader<'a, C> =
    halo2::Halo2Loader<'a, C, <C as CurveAffine>::ScalarExt, BaseFieldEccChip<C>>;
type PoseidonTranscript<C, L, S, B> = halo2::PoseidonTranscript<
    C,
    <C as CurveAffine>::ScalarExt,
    NativeRepresentation<C, <C as CurveAffine>::ScalarExt, BaseFieldEccChip<C>, LIMBS, BITS>,
    L,
    S,
    B,
    T,
    RATE,
    R_F,
    R_P,
>;
type SameCurveAccumulation<C, L> = kzg::SameCurveAccumulation<C, L, LIMBS, BITS>;

pub struct SnarkWitness<C: Curve> {
    protocol: Protocol<C>,
    statements: Vec<Vec<Value<<C as Group>::Scalar>>>,
    proof: Value<Vec<u8>>,
}

impl<C: Curve> From<Snark<C>> for SnarkWitness<C> {
    fn from(snark: Snark<C>) -> Self {
        Self {
            protocol: snark.protocol,
            statements: snark
                .statements
                .into_iter()
                .map(|statements| statements.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

impl<C: Curve> SnarkWitness<C> {
    pub fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            statements: self
                .statements
                .iter()
                .map(|statements| vec![Value::unknown(); statements.len()])
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
    let statements = snark
        .statements
        .iter()
        .map(|statements| {
            statements
                .iter()
                .map(|statement| loader.assign_scalar(*statement))
                .collect_vec()
        })
        .collect_vec();
    ShplonkAccumulationScheme::accumulate(
        &snark.protocol,
        loader,
        statements,
        &mut transcript,
        stretagy,
    )
    .map_err(|_| plonk::Error::Synthesis)?;
    Ok(())
}

pub struct Accumulation {
    n: usize,
    g1: G1Affine,
    snarks: Vec<SnarkWitness<G1>>,
    instances: Vec<Fr>,
}

impl Accumulation {
    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
    }

    pub fn two_snark(k: u32) -> Self {
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
                halo2_kzg_config!(false, 1),
                MainGateWithPlookupRange::<_, false>::rand(
                    K,
                    ChaCha20Rng::from_seed(Default::default())
                )
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
            snark1.statements.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark1.proof.as_slice()),
            &mut strategy
        );
        halo2_kzg_native_accumulate!(
            &snark2.protocol,
            snark2.statements.clone(),
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
            n: 1 << k,
            g1,
            snarks: vec![snark1.into(), snark2.into()],
            instances,
        }
    }

    pub fn two_snark_with_accumulator(k: u32) -> Self {
        let (params, pk, protocol, circuits) = {
            const K: u32 = 21;
            halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(false, 2, Self::accumulator_indices()),
                Self::two_snark(K)
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
            snark.statements.clone(),
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
            n: 1 << k,
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
    type Config = MainGateWithPlookupRangeConfig<Fr, false>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            n: self.n,
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
        MainGateWithPlookupRangeConfig::configure(
            meta,
            Rns::<Fq, Fr, LIMBS, BITS>::construct()
                .overflow_lengths()
                .into_iter()
                .chain(Some(BITS / LIMBS)),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        let main_gate = config.main_gate();
        let range_chip = config.range_chip(self.n);

        range_chip.load_table(&mut layouter)?;
        range_chip.assign_inner(layouter.namespace(|| ""), self.n)?;

        let (lhs, rhs) = layouter.assign_region(
            || "",
            |region| {
                let ctx = RegionCtx::new(region, 0);

                let base_field_chip = IntegerChip::new(
                    main_gate.clone(),
                    range_chip.clone(),
                    Rc::new(Rns::construct()),
                );
                let ecc_chip = BaseFieldEccChip::new(base_field_chip);
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
                    snark.statements,
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
    accumulation_two_snark,
    21,
    halo2_kzg_config!(false, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark(21)
);
test!(
    #[ignore = "cause it requires 32GB memory to run"],
    accumulation_two_snark_with_accumulator,
    22,
    halo2_kzg_config!(false, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark_with_accumulator(22)
);
