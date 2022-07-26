use crate::{protocol::halo2::test::circuit::plookup::PlookupConfig, util::Itertools};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, Chip, Layouter, Value},
    plonk::{Any, Circuit, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};
use halo2_wrong_ecc::maingate::{
    decompose, AssignedValue, MainGate, MainGateConfig, MainGateInstructions, RangeChip,
    RangeConfig, RangeInstructions, RegionCtx, Term,
};
use rand::RngCore;
use std::{collections::BTreeMap, iter};

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

    pub fn main_gate<F: FieldExt>(&self) -> MainGate<F> {
        MainGate::new(self.main_gate_config.clone())
    }

    pub fn range_chip<F: FieldExt>(&self) -> RangeChip<F> {
        RangeChip::new(self.range_config.clone())
    }
}

#[derive(Clone, Default)]
pub struct MainGateWithRange<F>(Vec<F>);

impl<F: FieldExt> MainGateWithRange<F> {
    pub fn new(inner: Vec<F>) -> Self {
        Self(inner)
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
pub struct PlookupRangeConfig<F: FieldExt, const ZK: bool> {
    main_gate_config: MainGateConfig,
    plookup_config: PlookupConfig<F, 2, ZK>,
    table: [Column<Fixed>; 2],
    q_limb: [Column<Fixed>; 2],
    q_overflow: [Column<Fixed>; 2],
    bits: BTreeMap<usize, usize>,
}

#[derive(Clone, Debug)]
pub struct PlookupRangeChip<F: FieldExt, const ZK: bool> {
    n: usize,
    config: PlookupRangeConfig<F, ZK>,
    main_gate: MainGate<F>,
}

impl<F: FieldExt, const ZK: bool> PlookupRangeChip<F, ZK> {
    pub fn new(n: usize, config: PlookupRangeConfig<F, ZK>) -> Self {
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
    ) -> PlookupRangeConfig<F, ZK> {
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
            .sorted()
            .dedup()
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

impl<F: FieldExt, const ZK: bool> Chip<F> for PlookupRangeChip<F, ZK> {
    type Config = PlookupRangeConfig<F, ZK>;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt, const ZK: bool> RangeInstructions<F> for PlookupRangeChip<F, ZK> {
    fn assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        value: Value<F>,
        limb_bit: usize,
        bit: usize,
    ) -> Result<AssignedValue<F>, Error> {
        let (assigned, _) = self.decompose(ctx, value, limb_bit, bit)?;
        Ok(assigned)
    }

    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, F>,
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
            .collect_vec();

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
pub struct MainGateWithPlookupRangeConfig<F: FieldExt, const ZK: bool> {
    main_gate_config: MainGateConfig,
    plookup_range_config: PlookupRangeConfig<F, ZK>,
}

impl<F: FieldExt, const ZK: bool> MainGateWithPlookupRangeConfig<F, ZK> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bits: impl IntoIterator<Item = usize>,
    ) -> Self {
        let main_gate_config = MainGate::configure(meta);
        let plookup_range_config =
            PlookupRangeChip::configure(meta, main_gate_config.clone(), bits);

        assert_eq!(meta.degree::<false>(), 3);

        MainGateWithPlookupRangeConfig {
            main_gate_config,
            plookup_range_config,
        }
    }

    pub fn main_gate(&self) -> MainGate<F> {
        MainGate::new(self.main_gate_config.clone())
    }

    pub fn range_chip(&self, n: usize) -> PlookupRangeChip<F, ZK> {
        PlookupRangeChip::new(n, self.plookup_range_config.clone())
    }
}

#[derive(Clone, Default)]
pub struct MainGateWithPlookupRange<F: FieldExt, const ZK: bool> {
    n: usize,
    inner: Vec<F>,
}

impl<F: FieldExt, const ZK: bool> MainGateWithPlookupRange<F, ZK> {
    pub fn new(k: u32, inner: Vec<F>) -> Self {
        Self { n: 1 << k, inner }
    }

    pub fn rand<R: RngCore>(k: u32, mut rng: R) -> Self {
        Self::new(k, vec![F::from(rng.next_u32() as u64)])
    }

    pub fn instances(&self) -> Vec<Vec<F>> {
        vec![self.inner.clone()]
    }
}

impl<F: FieldExt, const ZK: bool> Circuit<F> for MainGateWithPlookupRange<F, ZK> {
    type Config = MainGateWithPlookupRangeConfig<F, ZK>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            n: self.n,
            inner: vec![F::zero()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MainGateWithPlookupRangeConfig::configure(meta, [1, 7, 8])
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::<F>::new(config.main_gate_config.clone());
        let range_chip = PlookupRangeChip::new(self.n, config.plookup_range_config);

        range_chip.load_table(&mut layouter)?;
        range_chip.assign_inner(layouter.namespace(|| ""), self.n)?;

        let a = layouter.assign_region(
            || "",
            |region| {
                let mut ctx = RegionCtx::new(region, 0);
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
