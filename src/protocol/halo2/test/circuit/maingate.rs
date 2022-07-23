use crate::protocol::halo2::test::circuit::plookup::PlookupConfig;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, Chip, Layouter, Value},
    plonk::{Any, Circuit, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};
use halo2_wrong_ecc::{
    maingate::{
        decompose, AssignedValue, MainGate, MainGateConfig, MainGateInstructions, RangeChip,
        RangeConfig, RangeInstructions, RegionCtx, Term,
    },
    EccConfig,
};
use rand::RngCore;
use std::{
    collections::{BTreeMap, BTreeSet},
    iter,
};

#[derive(Clone)]
pub struct MainGateWithRangeConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl MainGateWithRangeConfig {
    pub fn configure<F: FieldExt>(
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

    pub fn ecc_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    pub fn load_table<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let range_chip = RangeChip::<F>::new(self.range_config.clone());
        range_chip.load_table(layouter)?;
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MainGateWithRange<F>(Vec<F>);

impl<F: FieldExt> MainGateWithRange<F> {
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

impl<F: FieldExt> Circuit<F> for MainGateWithRange<F> {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self(vec![F::zero()])
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MainGateWithRangeConfig::configure(meta, vec![8], vec![4, 7])
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::new(config.main_gate_config);
        let range_chip = RangeChip::new(config.range_config);
        range_chip.load_table(&mut layouter)?;

        let a = layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;
                let mut ctx = RegionCtx::new(&mut region, &mut offset);
                range_chip.decompose(&mut ctx, Value::known(F::from(u64::MAX)), 8, 64)?;
                range_chip.decompose(&mut ctx, Value::known(F::from(u32::MAX as u64)), 8, 39)?;
                let a = range_chip.assign(&mut ctx, Value::known(self.0[0]), 8, 68)?;
                let b = main_gate.sub_sub_with_constant(&mut ctx, &a, &a, &a, F::from(2))?;
                let cond = main_gate.assign_bit(&mut ctx, Value::known(F::one()))?;
                main_gate.select(&mut ctx, &a, &b, &cond)?;

                Ok(a)
            },
        )?;

        main_gate.expose_public(layouter, a, 0)?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PlookupRangeConfig<F: FieldExt> {
    main_gate_config: MainGateConfig,
    plookup_config: PlookupConfig<F, 2, false>,
    table: [Column<Fixed>; 2],
    q_limb: [Column<Fixed>; 2],
    q_overflow: [Column<Fixed>; 2],
    bits: BTreeMap<usize, usize>,
}

pub struct PlookupRangeChip<F: FieldExt> {
    n: usize,
    config: PlookupRangeConfig<F>,
    main_gate: MainGate<F>,
}

impl<F: FieldExt> PlookupRangeChip<F> {
    pub fn new(config: PlookupRangeConfig<F>, n: usize) -> Self {
        let main_gate = MainGate::new(config.main_gate_config.clone());
        Self {
            n,
            config,
            main_gate,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        main_gate_config: MainGateConfig,
        bits: impl IntoIterator<Item = usize>,
    ) -> PlookupRangeConfig<F> {
        let table = [(); 2].map(|_| meta.fixed_column());
        let q_limb = [(); 2].map(|_| meta.fixed_column());
        let q_overflow = [(); 2].map(|_| meta.fixed_column());
        let plookup_config = PlookupConfig::configure(
            meta,
            |meta| {
                let [a, b, c, d, _] = main_gate_config.advices();
                let limbs = [a, b, c, d].map(|column| meta.query_advice(column, Rotation::cur()));
                let overflow = meta.query_advice(a, Rotation::cur());
                let q_limb = q_limb.map(|column| meta.query_fixed(column, Rotation::cur()));
                let q_overflow = q_overflow.map(|column| meta.query_fixed(column, Rotation::cur()));
                iter::empty()
                    .chain(limbs.into_iter().zip(iter::repeat(q_limb)))
                    .chain(Some((overflow, q_overflow)))
                    .map(|(value, [selector, tag])| [tag, selector * value])
                    .collect()
            },
            table.map(Column::<Any>::from),
            None,
            None,
            None,
            None,
        );
        let bits = bits
            .into_iter()
            .collect::<BTreeSet<usize>>()
            .into_iter()
            .enumerate()
            .map(|(tag, bit)| (bit, tag))
            .collect();
        PlookupRangeConfig {
            main_gate_config,
            plookup_config,
            table,
            q_limb,
            q_overflow,
            bits,
        }
    }

    pub fn assign_inner(&self, layouter: impl Layouter<F>, n: usize) -> Result<(), Error> {
        self.config.plookup_config.assign(layouter, n)
    }
}

impl<F: FieldExt> Chip<F> for PlookupRangeChip<F> {
    type Config = PlookupRangeConfig<F>;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> RangeInstructions<F> for PlookupRangeChip<F> {
    fn assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        value: Value<F>,
        limb_bit: usize,
        bit: usize,
    ) -> Result<AssignedValue<F>, Error> {
        let (assigned, _) = self.decompose(ctx, value, limb_bit, bit)?;
        Ok(assigned)
    }

    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        value: Value<F>,
        limb_bit: usize,
        bit: usize,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        let (num_limbs, overflow) = (bit / limb_bit, bit % limb_bit);

        let num_limbs = num_limbs + if overflow > 0 { 1 } else { 0 };
        let terms = value
            .map(|value| decompose(value, num_limbs, limb_bit))
            .transpose_vec(num_limbs)
            .into_iter()
            .zip((0..num_limbs).map(|i| F::from(2).pow(&[(limb_bit * i) as u64, 0, 0, 0])))
            .map(|(limb, base)| Term::Unassigned(limb, base))
            .collect::<Vec<_>>();

        self.main_gate
            .decompose(ctx, &terms, F::zero(), |ctx, is_last| {
                ctx.assign_fixed(|| "", self.config.q_limb[0], F::one())?;
                ctx.assign_fixed(
                    || "",
                    self.config.q_limb[1],
                    F::from(*self.config.bits.get(&limb_bit).unwrap() as u64),
                )?;
                if is_last && overflow != 0 {
                    ctx.assign_fixed(|| "", self.config.q_overflow[0], F::one())?;
                    ctx.assign_fixed(
                        || "",
                        self.config.q_overflow[1],
                        F::from(*self.config.bits.get(&limb_bit).unwrap() as u64),
                    )?;
                }
                Ok(())
            })
    }

    fn load_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;

                for (bit, tag) in self.config.bits.iter() {
                    let tag = F::from(*tag as u64);
                    let table_values: Vec<F> = (0..1 << bit).map(|e| F::from(e)).collect();
                    for value in table_values.iter() {
                        region.assign_fixed(
                            || "table tag",
                            self.config.table[0],
                            offset,
                            || Value::known(tag),
                        )?;
                        region.assign_fixed(
                            || "table value",
                            self.config.table[1],
                            offset,
                            || Value::known(*value),
                        )?;
                        offset += 1;
                    }
                }

                for offset in offset..self.n {
                    region.assign_fixed(
                        || "table tag",
                        self.config.table[0],
                        offset,
                        || Value::known(F::zero()),
                    )?;
                    region.assign_fixed(
                        || "table value",
                        self.config.table[1],
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct MainGateWithPlookupConfig<F: FieldExt> {
    main_gate_config: MainGateConfig,
    plookup_range_config: PlookupRangeConfig<F>,
}

impl<F: FieldExt> MainGateWithPlookupConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bits: impl IntoIterator<Item = usize>,
    ) -> Self {
        let main_gate_config = MainGate::configure(meta);
        let plookup_range_config =
            PlookupRangeChip::configure(meta, main_gate_config.clone(), bits);

        assert_eq!(meta.degree::<false>(), 3);

        MainGateWithPlookupConfig {
            main_gate_config,
            plookup_range_config,
        }
    }
}

#[derive(Clone, Default)]
pub struct MainGateWithPlookup<F> {
    n: usize,
    inner: Vec<F>,
}

impl<F: FieldExt> MainGateWithPlookup<F> {
    pub fn new(k: u32, inner: Vec<F>) -> Self {
        Self { n: 1 << k, inner }
    }

    pub fn instances(&self) -> Vec<Vec<F>> {
        vec![self.inner.clone()]
    }
}

impl<F: FieldExt> Circuit<F> for MainGateWithPlookup<F> {
    type Config = MainGateWithPlookupConfig<F>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            n: self.n,
            inner: vec![F::zero()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MainGateWithPlookupConfig::configure(meta, [1, 7, 8])
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::<F>::new(config.main_gate_config.clone());
        let range_chip = PlookupRangeChip::new(config.plookup_range_config, self.n);

        range_chip.load_table(&mut layouter)?;
        range_chip.assign_inner(layouter.namespace(|| ""), self.n)?;

        let a = layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;
                let mut ctx = RegionCtx::new(&mut region, &mut offset);
                range_chip.decompose(&mut ctx, Value::known(F::from(u64::MAX)), 8, 64)?;
                range_chip.decompose(&mut ctx, Value::known(F::from(u32::MAX as u64)), 8, 39)?;
                let a = range_chip.assign(&mut ctx, Value::known(self.inner[0]), 8, 68)?;
                let b = main_gate.sub_sub_with_constant(&mut ctx, &a, &a, &a, F::from(2))?;
                let cond = main_gate.assign_bit(&mut ctx, Value::known(F::one()))?;
                main_gate.select(&mut ctx, &a, &b, &cond)?;

                Ok(a)
            },
        )?;

        main_gate.expose_public(layouter, a, 0)?;

        Ok(())
    }
}
