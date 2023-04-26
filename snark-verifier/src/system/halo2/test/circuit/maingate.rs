use crate::util::arithmetic::{CurveAffine, PrimeField};
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2_wrong_ecc::{
    maingate::{
        MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
        RegionCtx,
    },
    BaseFieldEccChip, EccConfig,
};
use rand::RngCore;

#[derive(Clone)]
pub struct MainGateWithRangeConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl MainGateWithRangeConfig {
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        composition_bits: Vec<usize>,
        overflow_bits: Vec<usize>,
    ) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        let range_config =
            RangeChip::<F>::configure(meta, &main_gate_config, composition_bits, overflow_bits);
        MainGateWithRangeConfig {
            main_gate_config,
            range_config,
        }
    }

    pub fn main_gate<F: PrimeField>(&self) -> MainGate<F> {
        MainGate::new(self.main_gate_config.clone())
    }

    pub fn range_chip<F: PrimeField>(&self) -> RangeChip<F> {
        RangeChip::new(self.range_config.clone())
    }

    pub fn ecc_chip<C: CurveAffine, const LIMBS: usize, const BITS: usize>(
        &self,
    ) -> BaseFieldEccChip<C, LIMBS, BITS> {
        BaseFieldEccChip::new(EccConfig::new(
            self.range_config.clone(),
            self.main_gate_config.clone(),
        ))
    }
}

#[derive(Clone, Default)]
pub struct MainGateWithRange<F>(Vec<F>);

impl<F: PrimeField> MainGateWithRange<F> {
    pub fn new(inner: Vec<F>) -> Self {
        Self(inner)
    }

    pub fn rand<R: RngCore>(mut rng: R) -> Self {
        Self::new(vec![F::from(rng.next_u32() as u64)])
    }

    pub fn instances(&self) -> Vec<Vec<F>> {
        vec![self.0.clone()]
    }
}

impl<F: PrimeField> Circuit<F> for MainGateWithRange<F> {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;
    #[cfg(feature = "halo2_circuit_params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self(vec![F::ZERO])
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MainGateWithRangeConfig::configure(meta, vec![8], vec![4, 7])
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let main_gate = config.main_gate();
        let range_chip = config.range_chip();
        range_chip.load_table(&mut layouter)?;

        let a = layouter.assign_region(
            || "",
            |region| {
                let mut ctx = RegionCtx::new(region, 0);
                range_chip.decompose(&mut ctx, Value::known(F::from(u64::MAX)), 8, 64)?;
                range_chip.decompose(&mut ctx, Value::known(F::from(u32::MAX as u64)), 8, 39)?;
                let a = range_chip.assign(&mut ctx, Value::known(self.0[0]), 8, 68)?;
                let b = main_gate.sub_sub_with_constant(&mut ctx, &a, &a, &a, F::from(2))?;
                let cond = main_gate.assign_bit(&mut ctx, Value::known(F::ONE))?;
                main_gate.select(&mut ctx, &a, &b, &cond)?;

                Ok(a)
            },
        )?;

        main_gate.expose_public(layouter, a, 0)?;

        Ok(())
    }
}
