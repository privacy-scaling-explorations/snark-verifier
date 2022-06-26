use crate::{
    collect_slice, halo2_native_verify, halo2_prepare,
    loader::halo2::{self, SameCurveRecursion},
    protocol::{
        halo2::{test::MainGateWithRange, util::halo2::ChallengeScalar},
        Protocol,
    },
    scheme::kzg::{AccumulationScheme, ShplonkAccumulator},
    util::Group,
};
use halo2_curves::{
    bn256::{Bn256, G1Affine, G2Prepared},
    pairing::{MillerLoopResult, MultiMillerLoop},
    CurveAffine, FieldExt,
};
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    dev::MockProver,
    plonk,
    plonk::Circuit,
    poly::{
        commitment::ParamsProver,
        kzg::{
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::BatchVerifier,
        },
    },
    transcript::TranscriptReadBuffer,
};
use halo2_wrong::utils::big_to_fe;
use halo2_wrong_ecc::{integer::rns::Common, BaseFieldEccChip, EccConfig};
use halo2_wrong_maingate::{
    MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};
use halo2_wrong_transcript::NativeRepresentation;
use std::{cell::RefCell, rc::Rc};

const LIMBS: usize = 4;
const BITS: usize = 68;
const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 57;

type Halo2Loader<'a, 'b, C> = halo2::Halo2Loader<'a, 'b, C, LIMBS, BITS>;
type PoseidonTranscript<C, L, S, B> =
    halo2::PoseidonTranscript<C, L, S, B, NativeRepresentation, LIMBS, BITS, T, RATE, R_F, R_P>;

#[derive(Clone)]
struct TestCircuitConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl TestCircuitConfig {
    fn ecc_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    fn configure<C: CurveAffine>(meta: &mut plonk::ConstraintSystem<C::Scalar>) -> Self {
        let rns = BaseFieldEccChip::<C, LIMBS, BITS>::rns();
        let main_gate_config = MainGate::<C::Scalar>::configure(meta);
        let range_config =
            RangeChip::<C::Scalar>::configure(meta, &main_gate_config, rns.overflow_lengths());
        TestCircuitConfig {
            main_gate_config,
            range_config,
        }
    }

    fn load_table<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Result<(), plonk::Error> {
        let bit_len_lookup = BITS / LIMBS;
        let range_chip = RangeChip::<F>::new(self.range_config.clone(), bit_len_lookup);
        range_chip.load_limb_range_table(layouter)?;
        range_chip.load_overflow_range_tables(layouter)?;
        Ok(())
    }
}

struct TestCircuit<C: CurveAffine> {
    g1: C,
    protocol: Protocol<C::CurveExt>,
    statements: Vec<Vec<Value<C::Scalar>>>,
    proof: Value<Vec<u8>>,
    accumulated: RefCell<(C, C)>,
}

impl<C: CurveAffine> Circuit<C::Scalar> for TestCircuit<C> {
    type Config = TestCircuitConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            g1: self.g1,
            protocol: self.protocol.clone(),
            statements: self.statements.clone(),
            proof: Value::unknown(),
            accumulated: RefCell::new((C::default(), C::default())),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<C::Scalar>) -> Self::Config {
        TestCircuitConfig::configure::<C>(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::Scalar>,
    ) -> Result<(), plonk::Error> {
        config.load_table(&mut layouter)?;

        layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;
                let ctx = RegionCtx::new(&mut region, &mut offset);

                let loader = Rc::new(Halo2Loader::<C>::new(config.ecc_config(), ctx));
                let mut stretagy = SameCurveRecursion::default();
                let mut transcript = PoseidonTranscript::<_, Rc<Halo2Loader<C>>, _, _>::new(
                    &loader,
                    self.proof.as_ref().map(|proof| proof.as_slice()),
                );
                let statements = self
                    .statements
                    .iter()
                    .map(|statements| {
                        statements
                            .iter()
                            .map(|statement| loader.assign_scalar(*statement))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                collect_slice!(statements);
                ShplonkAccumulator::new()
                    .accumulate(
                        &self.protocol,
                        &loader,
                        &statements,
                        &mut transcript,
                        &mut stretagy,
                    )
                    .map_err(|_| plonk::Error::Synthesis)?;

                let (lhs, rhs) = stretagy.finalize(self.g1);
                lhs.get_x()
                    .integer()
                    .zip(lhs.get_y().integer())
                    .zip(rhs.get_x().integer().zip(rhs.get_y().integer()))
                    .map(|((lhs_x, lhs_y), (rhs_x, rhs_y))| {
                        let lhs =
                            C::from_xy(big_to_fe(lhs_x.value()), big_to_fe(lhs_y.value())).unwrap();
                        let rhs =
                            C::from_xy(big_to_fe(rhs_x.value()), big_to_fe(rhs_y.value())).unwrap();
                        *self.accumulated.borrow_mut() = (lhs, rhs);
                    });

                dbg!(offset);

                Ok(())
            },
        )?;
        Ok(())
    }
}

#[test]
fn test_shplonk_halo2_main_gate_with_range() {
    const K: u32 = 9;
    const N: usize = 1;

    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg],
        K, N, MainGateWithRange::<_>,
        ProverSHPLONK<_>,
        VerifierSHPLONK<_>,
        BatchVerifier<_, _>,
        PoseidonTranscript<_, _, _, _>,
        PoseidonTranscript<_, _, _, _>,
        ChallengeScalar<_>
    );

    halo2_native_verify!(
        [kzg],
        params,
        protocol,
        instances,
        ShplonkAccumulator::new(),
        PoseidonTranscript::<G1Affine, _, _, _>::init(proof.as_slice())
    );

    let circuit = TestCircuit {
        g1: params.get_g()[0],
        protocol,
        statements: instances
            .into_iter()
            .map(|instances| instances.into_iter().map(Value::known).collect::<Vec<_>>())
            .collect(),
        proof: Value::known(proof),
        accumulated: RefCell::new((G1Affine::default(), G1Affine::default())),
    };

    MockProver::run(21, &circuit, vec![vec![]])
        .unwrap()
        .assert_satisfied();

    let (lhs, rhs) = *circuit.accumulated.borrow();
    let g2 = G2Prepared::from(params.g2());
    let minus_s_g2 = G2Prepared::from(-params.s_g2());
    let terms = [(&lhs, &g2), (&rhs, &minus_s_g2)];
    assert!(bool::from(
        Bn256::multi_miller_loop(&terms)
            .final_exponentiation()
            .is_identity()
    ));
}
