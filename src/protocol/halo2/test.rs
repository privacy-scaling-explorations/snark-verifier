use crate::{
    protocol::Protocol,
    util::{Curve, Group},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, Layouter, Value},
    dev::MockProver,
    plonk::{
        create_proof, verify_proof, Advice, Any, Circuit, Column, ConstraintSystem, Error, Fixed,
        Instance, ProvingKey,
    },
    poly::{
        commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        Rotation, VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2_wrong_ecc::EccConfig;
use halo2_wrong_maingate::{
    MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
    RegionCtx, Term,
};
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::fs;

mod halo2;
mod native;

#[cfg(feature = "evm")]
mod evm;

pub const LIMBS: usize = 4;
pub const BITS: usize = 68;

pub fn read_or_create_srs<S: CommitmentScheme>(scheme: &str, k: u32) -> S::ParamsProver {
    const DIR: &str = "./src/protocol/halo2/test/fixture";
    let path = format!("{}/{}_{}.srs", DIR, scheme, k);
    match fs::File::open(path.as_str()) {
        Ok(mut file) => S::ParamsProver::read(&mut file).unwrap(),
        Err(_) => {
            fs::create_dir_all(DIR).unwrap();
            let params = S::new_params(k, ChaCha20Rng::from_seed(Default::default()));
            let mut file = fs::File::create(path.as_str()).unwrap();
            params.write(&mut file).unwrap();
            params
        }
    }
}

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
        meta.set_minimum_degree(5);
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
                region.assign_advice(|| "", config.a, 0, || Value::known(self.0 - F::one()))?;
                region.assign_fixed(|| "", config.constant, 0, || Value::known(-F::one()))?;
                region.assign_fixed(|| "", config.q_a, 0, || Value::known(-F::one()))?;

                for (column, idx) in [config.q_a, config.q_b, config.q_c, config.q_ab]
                    .iter()
                    .zip(1..)
                {
                    region.assign_fixed(|| "", *column, 1, || Value::known(F::from(idx)))?;
                }
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

    fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>, fine_tune_bits: Vec<usize>) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        let range_config = RangeChip::<F>::configure(meta, &main_gate_config, fine_tune_bits);
        MainGateWithRangeConfig {
            main_gate_config,
            range_config,
        }
    }

    fn load_table<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
        dense_limb_bits: usize,
    ) -> Result<(), Error> {
        let range_chip = RangeChip::<F>::new(self.range_config.clone(), dense_limb_bits);
        range_chip.load_table(layouter)?;
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MainGateWithRange<F>(F);

impl<F: FieldExt> MainGateWithRange<F> {
    pub fn rand<R: RngCore>(mut rng: R) -> Self {
        Self(F::from(rng.next_u32() as u64))
    }

    pub fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![self.0]]
    }
}

impl<F: FieldExt> Circuit<F> for MainGateWithRange<F> {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MainGateWithRangeConfig::configure(meta, vec![1])
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::new(config.main_gate_config);
        let range_chip = RangeChip::new(config.range_config, 8);
        range_chip.load_table(&mut layouter)?;

        let a = layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;
                let mut ctx = RegionCtx::new(&mut region, &mut offset);
                let a = range_chip.range_value(&mut ctx, &Value::known(self.0).into(), 33)?;
                let b = main_gate.sub_sub_with_constant(&mut ctx, &a, &a, &a, F::from(2))?;
                let cond = main_gate.assign_value(&mut ctx, &Value::known(F::one()).into())?;
                main_gate.select(&mut ctx, &a, &b, &cond.into())?;
                main_gate.compose(
                    &mut ctx,
                    &[
                        Term::Assigned(a, F::from(3)),
                        Term::Assigned(a, F::from(4)),
                        Term::Assigned(a, F::from(5)),
                        Term::Assigned(a, F::from(6)),
                        Term::Assigned(a, F::from(7)),
                        Term::Assigned(a, F::from(8)),
                        Term::Assigned(a, F::from(9)),
                        Term::Assigned(a, F::from(10)),
                    ],
                    F::from(11),
                )?;
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

pub fn create_proof_checked<'a, S, C, P, V, VS, TW, TR, E, R>(
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
    VS: VerificationStrategy<'a, S, V, R, Output = VS>,
    TW: TranscriptWriterBuffer<Vec<u8>, S::Curve, E>,
    TR: TranscriptReadBuffer<&'static [u8], S::Curve, E>,
    E: EncodedChallenge<S::Curve>,
    R: RngCore,
{
    for (circuit, instances) in circuits.iter().zip(instances.iter()) {
        MockProver::run(
            params.k(),
            circuit,
            instances.iter().map(|instance| instance.to_vec()).collect(),
        )
        .unwrap()
        .assert_satisfied();
    }

    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<S, P, _, _, _, _>(
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
        let strategy = VS::new(params, rng);
        let mut transcript = TR::init(Box::leak(Box::new(proof.clone())));
        verify_proof(params, pk.get_vk(), strategy, instances, &mut transcript)
            .unwrap()
            .finalize()
    };
    assert!(accept);

    proof
}

#[macro_export]
macro_rules! halo2_prepare {
    ([kzg], $k:ident, $n:ident, $accumulator_indices:expr, $create_circuit:expr) => {{
        use halo2_curves::bn256::{Bn256, G1};
        use halo2_proofs::{
            plonk::{keygen_pk, keygen_vk},
            poly::kzg::commitment::KZGCommitmentScheme,
        };
        use std::{collections::BTreeSet, iter};
        use $crate::{
            protocol::halo2::{compile, test::read_or_create_srs},
            util::GroupEncoding,
        };

        let circuits = iter::repeat_with(|| $create_circuit)
            .take($n)
            .collect::<Vec<_>>();

        let params = read_or_create_srs::<KZGCommitmentScheme<Bn256>>("kzg", $k);
        let vk = keygen_vk::<KZGCommitmentScheme<_>, _>(&params, &circuits[0]).unwrap();
        let pk = keygen_pk::<KZGCommitmentScheme<_>, _>(&params, vk, &circuits[0]).unwrap();

        let protocol = compile::<G1>(pk.get_vk(), N, $accumulator_indices);

        assert_eq!(
            protocol.preprocessed.len(),
            BTreeSet::<[u8; 32]>::from_iter(
                protocol.preprocessed.iter().map(|ec_point| ec_point
                    .to_bytes()
                    .as_ref()
                    .to_vec()
                    .try_into()
                    .unwrap())
            )
            .len()
        );

        (params, pk, protocol, circuits)
    }};
}

#[macro_export]
macro_rules! halo2_create_snark {
    ([kzg], $params:expr, $pk:expr, $protocol:expr, $circuits:expr, $prover:ty, $verifier:ty, $verification_strategy:ty, $transcript_read:ty, $transcript_write:ty, $encoded_challenge:ty) => {{
        use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use $crate::protocol::halo2::test::{create_proof_checked, Snark};

        let instances = $circuits
            .iter()
            .map(|circuit| circuit.instances())
            .collect::<Vec<_>>();
        let proof = {
            collect_slice!(instances, 2);
            create_proof_checked::<
                KZGCommitmentScheme<_>,
                _,
                $prover,
                $verifier,
                $verification_strategy,
                $transcript_read,
                $transcript_write,
                $encoded_challenge,
                _,
            >(
                $params,
                $pk,
                $circuits,
                &instances,
                &mut ChaCha20Rng::from_seed(Default::default()),
            )
        };

        Snark::new(
            $protocol.clone(),
            instances.into_iter().flatten().collect::<Vec<_>>(),
            proof,
        )
    }};
}

#[macro_export]
macro_rules! halo2_native_accumulate {
    ([kzg], $protocol:expr, $statements:expr, $scheme:ty, $transcript:expr, $stretagy:expr) => {{
        use $crate::{loader::native::NativeLoader, scheme::kzg::AccumulationScheme};

        <$scheme>::accumulate(
            $protocol,
            &NativeLoader,
            $statements,
            $transcript,
            $stretagy,
        )
        .unwrap();
    }};
}

#[macro_export]
macro_rules! halo2_native_verify {
    ([kzg], $params:ident, $protocol:expr, $statements:expr, $scheme:ty, $transcript:expr) => {{
        use halo2_curves::bn256::Bn256;
        use halo2_proofs::poly::commitment::ParamsProver;
        use $crate::{
            halo2_native_accumulate,
            protocol::halo2::test::{BITS, LIMBS},
            scheme::kzg::SameCurveAccumulation,
        };

        let mut stretagy = SameCurveAccumulation::<_, _, LIMBS, BITS>::default();
        halo2_native_accumulate!(
            [kzg],
            $protocol,
            $statements,
            $scheme,
            $transcript,
            &mut stretagy
        );

        assert!(stretagy.decide::<Bn256>($params.get_g()[0], $params.g2(), $params.s_g2()));
    }};
}
