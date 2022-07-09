use crate::{
    protocol::{
        halo2::{compile, Config},
        Protocol,
    },
    util::{CommonPolynomial, Curve, Expression, Group, Query},
};
use halo2_curves::bn256::{Bn256, Fr, G1};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, Layouter, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Any, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, ProvingKey,
    },
    poly::{
        commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        kzg::commitment::KZGCommitmentScheme,
        Rotation, VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2_wrong_ecc::EccConfig;
use halo2_wrong_maingate::{
    MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
    RegionCtx,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

mod kzg;

#[allow(dead_code)]
#[derive(Clone)]
pub struct StandardPlonkConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    q_a: Column<Fixed>,
    q_b: Column<Fixed>,
    q_c: Column<Fixed>,
    q_ab: Column<Fixed>,
    constant: Column<Fixed>,
    instance: Column<Instance>,
}

impl StandardPlonkConfig {
    pub fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();

        let q_a = meta.fixed_column();
        let q_b = meta.fixed_column();
        let q_c = meta.fixed_column();

        let q_ab = meta.fixed_column();

        let constant = meta.fixed_column();
        let instance = meta.instance_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);

        meta.create_gate("", |meta| {
            let [a, b, c, q_a, q_b, q_c, q_ab, constant, instance] = [
                a.into(),
                b.into(),
                c.into(),
                q_a.into(),
                q_b.into(),
                q_c.into(),
                q_ab.into(),
                constant.into(),
                instance.into(),
            ]
            .map(|column: Column<Any>| meta.query_any(column, Rotation::cur()));

            vec![q_a * a.clone() + q_b * b.clone() + q_c * c + q_ab * a * b + constant + instance]
        });

        StandardPlonkConfig {
            a,
            b,
            c,
            q_a,
            q_b,
            q_c,
            q_ab,
            constant,
            instance,
        }
    }
}

#[derive(Clone, Default)]
pub struct StandardPlonk<F>(F);

impl<F: FieldExt> StandardPlonk<F> {
    pub fn rand<R: RngCore>(mut rng: R) -> Self {
        Self(F::from(rng.next_u32() as u64))
    }

    pub fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![self.0]]
    }
}

impl<F: FieldExt> Circuit<F> for StandardPlonk<F> {
    type Config = StandardPlonkConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        meta.set_minimum_degree(4);
        StandardPlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "",
            |mut region| {
                region.assign_advice(|| "", config.a, 0, || Value::known(self.0))?;
                region.assign_fixed(|| "", config.q_a, 0, || Value::known(-F::one()))?;

                region.assign_advice(|| "", config.a, 1, || Value::known(-F::from(5)))?;
                for (column, idx) in [
                    config.q_a,
                    config.q_b,
                    config.q_c,
                    config.q_ab,
                    config.constant,
                ]
                .iter()
                .zip(1..)
                {
                    region.assign_fixed(|| "", *column, 1, || Value::known(F::from(idx)))?;
                }

                let a = region.assign_advice(|| "", config.a, 2, || Value::known(F::one()))?;
                a.copy_advice(|| "", &mut region, config.b, 3)?;
                a.copy_advice(|| "", &mut region, config.c, 4)?;

                Ok(())
            },
        )
    }
}

#[derive(Clone)]
pub struct MainGateWithRangeConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl MainGateWithRangeConfig {
    fn ecc_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    fn configure<F: FieldExt>(
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

    fn load_table<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
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
        MainGateWithRangeConfig::configure(meta, vec![8], vec![1, 7])
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
                range_chip.decompose(&mut ctx, Value::known(self.0[0]), 8, 33)?;
                let (a, _) = range_chip.decompose(&mut ctx, Value::known(self.0[0]), 8, 39)?;
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

pub struct Snark<C: Curve> {
    protocol: Protocol<C>,
    statements: Vec<Vec<<C as Group>::Scalar>>,
    proof: Vec<u8>,
}

impl<C: Curve> Snark<C> {
    pub fn new(
        protocol: Protocol<C>,
        statements: Vec<Vec<<C as Group>::Scalar>>,
        proof: Vec<u8>,
    ) -> Self {
        Snark {
            protocol,
            statements,
            proof,
        }
    }
}

pub fn create_proof_checked<'a, S, C, P, V, VS, TW, TR, EC, R, const ZK: bool>(
    params: &'a S::ParamsProver,
    pk: &ProvingKey<S::Curve>,
    circuits: &[C],
    instances: &[&[&[S::Scalar]]],
    mut rng: R,
) -> Vec<u8>
where
    S: CommitmentScheme,
    S::ParamsVerifier: 'a,
    C: Circuit<S::Scalar>,
    P: Prover<'a, S>,
    V: Verifier<'a, S>,
    VS: VerificationStrategy<'a, S, V, Output = VS>,
    TW: TranscriptWriterBuffer<Vec<u8>, S::Curve, EC>,
    TR: TranscriptReadBuffer<&'static [u8], S::Curve, EC>,
    EC: EncodedChallenge<S::Curve>,
    R: RngCore,
{
    for (circuit, instances) in circuits.iter().zip(instances.iter()) {
        MockProver::run::<_, ZK>(
            params.k(),
            circuit,
            instances.iter().map(|instance| instance.to_vec()).collect(),
        )
        .unwrap()
        .assert_satisfied();
    }

    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<S, P, _, _, _, _, ZK>(
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

    let accept = {
        let params = params.verifier_params();
        let strategy = VS::new(params);
        let mut transcript = TR::init(Box::leak(Box::new(proof.clone())));
        verify_proof::<_, _, _, _, _, ZK>(params, pk.get_vk(), strategy, instances, &mut transcript)
            .unwrap()
            .finalize()
    };
    assert!(accept);

    proof
}

#[test]
fn test_compile_standard_plonk() {
    let circuit = StandardPlonk::rand(ChaCha20Rng::from_seed(Default::default()));

    let params = kzg::read_or_create_srs::<Bn256>(9);
    let vk = keygen_vk::<KZGCommitmentScheme<_>, _, false>(&params, &circuit).unwrap();
    let pk = keygen_pk::<KZGCommitmentScheme<_>, _, false>(&params, vk, &circuit).unwrap();

    let protocol = compile::<G1>(
        pk.get_vk(),
        Config {
            zk: false,
            query_instance: false,
            num_proof: 1,
            accumulator_indices: None,
        },
    );

    let [q_a, q_b, q_c, q_ab, constant, sigma_a, sigma_b, sigma_c, instance, a, b, c, z] =
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].map(|poly| Query::new(poly, Rotation::cur()));
    let z_w = Query::new(12, Rotation::next());
    let t = Query::new(13, Rotation::cur());

    assert_eq!(protocol.preprocessed.len(), 8);
    assert_eq!(protocol.num_statement, 1);
    assert_eq!(protocol.num_auxiliary, vec![3, 0, 1]);
    assert_eq!(protocol.num_challenge, vec![1, 2, 0]);
    assert_eq!(
        protocol.evaluations,
        vec![a, b, c, q_a, q_b, q_c, q_ab, constant, sigma_a, sigma_b, sigma_c, z, z_w]
    );
    assert_eq!(
        protocol.queries,
        vec![a, b, c, z, z_w, q_a, q_b, q_c, q_ab, constant, sigma_a, sigma_b, sigma_c, t]
    );
    assert_eq!(
        format!("{:?}", protocol.relations),
        format!("{:?}", {
            let [q_a, q_b, q_c, q_ab, constant, sigma_a, sigma_b, sigma_c, instance, a, b, c, z, z_w, beta, gamma, l_0, identity, one, k_1, k_2] =
                &[
                    Expression::Polynomial(q_a),
                    Expression::Polynomial(q_b),
                    Expression::Polynomial(q_c),
                    Expression::Polynomial(q_ab),
                    Expression::Polynomial(constant),
                    Expression::Polynomial(sigma_a),
                    Expression::Polynomial(sigma_b),
                    Expression::Polynomial(sigma_c),
                    Expression::Polynomial(instance),
                    Expression::Polynomial(a),
                    Expression::Polynomial(b),
                    Expression::Polynomial(c),
                    Expression::Polynomial(z),
                    Expression::Polynomial(z_w),
                    Expression::Challenge(1), // beta
                    Expression::Challenge(2), // gamma
                    Expression::CommonPolynomial(CommonPolynomial::Lagrange(0)), // l_0
                    Expression::CommonPolynomial(CommonPolynomial::Identity), // identity
                    Expression::Constant(Fr::one()), // one
                    Expression::Constant(Fr::DELTA), // k_1
                    Expression::Constant(Fr::DELTA * Fr::DELTA), // k_2
                ];

            vec![
                q_a * a + q_b * b + q_c * c + q_ab * a * b + constant + instance,
                l_0 * (one - z),
                z_w * ((a + beta * sigma_a + gamma)
                    * (b + beta * sigma_b + gamma)
                    * (c + beta * sigma_c + gamma))
                    - z * ((a + beta * one * identity + gamma)
                        * (b + beta * k_1 * identity + gamma)
                        * (c + beta * k_2 * identity + gamma)),
            ]
        })
    );
}
