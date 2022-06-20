use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt},
    circuit::{floor_planner::V1, Layouter, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Any, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, TableColumn, VerifyingKey,
    },
    poly::{
        commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        Rotation, VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand::RngCore;
use std::fs;

#[cfg(feature = "evm")]
mod evm;
mod native;

pub fn read_srs<'a, C, P>(name: &str, k: u32) -> P
where
    C: CurveAffine,
    P: ParamsProver<'a, C>,
{
    const DIR: &str = "./srs/halo2";
    let path = format!("{}/{}-{}", DIR, name, k);
    match fs::File::open(path.as_str()) {
        Ok(mut file) => P::read(&mut file).unwrap(),
        Err(_) => {
            fs::create_dir_all(DIR).unwrap();
            let params = P::new(k);
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
pub struct SmallCircuit<F>(F);

impl<F: FieldExt> SmallCircuit<F> {
    #[allow(dead_code)]
    pub fn rand<R: RngCore>(mut rng: R) -> Self {
        Self(F::from(rng.next_u32() as u64))
    }

    #[allow(dead_code)]
    pub fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![self.0]]
    }
}

impl<F: FieldExt> Circuit<F> for SmallCircuit<F> {
    type Config = StandardPlonkConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
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
                let a = if self.0 == F::zero() {
                    Value::unknown()
                } else {
                    Value::known(self.0)
                };
                let b = a.map(|value| value.invert().unwrap());
                region.assign_fixed(|| "", config.q_a, 0, || Value::known(-F::one()))?;
                region
                    .assign_advice(|| "", config.a, 0, || a)?
                    .copy_advice(|| "", &mut region, config.a, 1)?;
                region.assign_advice(|| "", config.b, 1, || b)?;
                region.assign_fixed(|| "", config.q_ab, 1, || Value::known(F::one()))?;
                region.assign_fixed(|| "", config.constant, 1, || Value::known(-F::one()))?;
                Ok(())
            },
        )
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct ExtendedPlonkConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,
    e: Column<Advice>,
    q_a: Column<Fixed>,
    q_b: Column<Fixed>,
    q_c: Column<Fixed>,
    q_d: Column<Fixed>,
    q_e: Column<Fixed>,
    q_e_w: Column<Fixed>,
    q_ab: Column<Fixed>,
    q_cd: Column<Fixed>,
    q_byte: Column<Fixed>,
    byte: TableColumn,
    constant: Column<Fixed>,
    instance: Column<Instance>,
}

impl ExtendedPlonkConfig {
    pub fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let d = meta.advice_column();
        let e = meta.advice_column();

        let q_a = meta.fixed_column();
        let q_b = meta.fixed_column();
        let q_c = meta.fixed_column();
        let q_d = meta.fixed_column();
        let q_e = meta.fixed_column();
        let q_e_w = meta.fixed_column();
        let q_ab = meta.fixed_column();
        let q_cd = meta.fixed_column();
        let q_byte = meta.fixed_column();

        let byte = meta.lookup_table_column();
        let constant = meta.fixed_column();
        let instance = meta.instance_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(d);
        meta.enable_equality(e);
        meta.enable_equality(instance);

        meta.create_gate("", |meta| {
            let e_next = meta.query_advice(e, Rotation::next());
            let [a, b, c, d, e, q_a, q_b, q_c, q_d, q_e, q_e_w, q_ab, q_cd, constant] = [
                a.into(),
                b.into(),
                c.into(),
                d.into(),
                e.into(),
                q_a.into(),
                q_b.into(),
                q_c.into(),
                q_d.into(),
                q_e.into(),
                q_e_w.into(),
                q_ab.into(),
                q_cd.into(),
                constant.into(),
            ]
            .map(|column: Column<Any>| meta.query_any(column, Rotation::cur()));

            vec![
                q_a * a.clone()
                    + q_b * b.clone()
                    + q_c * c.clone()
                    + q_d * d.clone()
                    + q_e * e
                    + q_ab * a * b
                    + q_cd * c * d
                    + q_e_w * e_next
                    + constant,
            ]
        });

        for column in [b, c, d, e] {
            meta.lookup(|meta| {
                let q_byte = meta.query_fixed(q_byte, Rotation::cur());
                let column = meta.query_advice(column, Rotation::cur());
                vec![(q_byte * column, byte)]
            });
        }

        Self {
            a,
            b,
            c,
            d,
            e,
            q_a,
            q_b,
            q_c,
            q_d,
            q_e,
            q_e_w,
            q_ab,
            q_cd,
            q_byte,
            byte,
            constant,
            instance,
        }
    }

    pub fn load_byte_table<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "",
            |mut table| {
                for byte in 0..256 {
                    table.assign_cell(
                        || "",
                        self.byte,
                        byte,
                        || Value::known(F::from(byte as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[derive(Clone, Default)]
pub struct BigCircuit<F>(F);

impl<F: FieldExt> BigCircuit<F> {
    pub fn rand<R: RngCore>(mut rng: R) -> Self {
        Self(F::from(rng.next_u32() as u64))
    }

    pub fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![self.0]]
    }
}

impl<F: FieldExt> Circuit<F> for BigCircuit<F> {
    type Config = ExtendedPlonkConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ExtendedPlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_byte_table(&mut layouter)?;

        layouter.assign_region(
            || "",
            |mut region| {
                let a =
                    region.assign_advice_from_instance(|| "", config.instance, 0, config.a, 0)?;
                let a_le_byte = |i: usize| {
                    let a = &a;
                    move || {
                        a.value()
                            .map(|a| F::from(((a.get_lower_32() >> (8 * i)) & 0xff) as u64))
                    }
                };
                region.assign_fixed(|| "", config.q_a, 1, || Value::known(-F::one()))?;
                region.assign_fixed(|| "", config.q_b, 1, || Value::known(F::from(1 << 24)))?;
                region.assign_fixed(|| "", config.q_c, 1, || Value::known(F::from(1 << 16)))?;
                region.assign_fixed(|| "", config.q_d, 1, || Value::known(F::from(1 << 8)))?;
                region.assign_fixed(|| "", config.q_e, 1, || Value::known(F::one()))?;
                region.assign_fixed(|| "", config.q_byte, 1, || Value::known(F::one()))?;
                a.copy_advice(|| "", &mut region, config.a, 1)?;
                region.assign_advice(|| "", config.b, 1, a_le_byte(3))?;
                region.assign_advice(|| "", config.c, 1, a_le_byte(2))?;
                region.assign_advice(|| "", config.d, 1, a_le_byte(1))?;
                region.assign_advice(|| "", config.e, 1, a_le_byte(0))?;
                Ok(())
            },
        )
    }
}

pub fn gen_vk_and_proof<'a, S, C, P, V, VS, TW, TR, E, R>(
    params: &'a S::ParamsProver,
    circuits: &[C],
    instances: &[&[&[S::Scalar]]],
    mut rng: R,
) -> (VerifyingKey<S::Curve>, Vec<u8>)
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
    let vk = keygen_vk::<S, _>(params, &circuits[0]).unwrap();
    let pk = keygen_pk::<S, _>(params, vk.clone(), &circuits[0]).unwrap();

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
            &pk,
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
        verify_proof(params, &vk, strategy, instances, &mut transcript)
            .unwrap()
            .finalize()
    };
    assert!(accept);

    (vk, proof)
}

#[macro_export]
macro_rules! halo2_prepare {
    ([kzg] $k:expr, $n:expr, $circuit:ty, $prover:ty, $verifier:ty, $verification_strategy:ty, $transcript_read:ty, $transcript_write:ty, $encoded_challenge:ty) => {{
        use halo2_curves::bn256::{Bn256, G1};
        use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use std::iter;
        use $crate::protocol::halo2::{
            compile,
            test::{gen_vk_and_proof, read_srs},
        };

        let params = read_srs::<_, ParamsKZG<Bn256>>("kzg", $k);

        let mut rng = ChaCha20Rng::from_seed(Default::default());
        let circuits = iter::repeat_with(|| <$circuit>::rand(&mut rng))
            .take($n)
            .collect::<Vec<_>>();
        let instances = circuits
            .iter()
            .map(<$circuit>::instances)
            .collect::<Vec<_>>();

        let (vk, proof) = {
            collect_slice!(instances, 2);
            gen_vk_and_proof::<
                KZGCommitmentScheme<_>,
                _,
                $prover,
                $verifier,
                $verification_strategy,
                $transcript_read,
                $transcript_write,
                $encoded_challenge,
                _,
            >(&params, &circuits, &instances, &mut rng)
        };

        let protocol = compile::<G1>(&vk, N);

        (params, protocol, instances, proof)
    }};
}

#[macro_export]
macro_rules! halo2_native_verify {
    ($params:ident, $protocol:ident, $instances:ident, $accumulator:expr, $transcript:expr) => {{
        use halo2_curves::bn256::Bn256;
        use halo2_proofs::poly::commitment::ParamsProver;
        use $crate::{
            loader::native::NativeLoader,
            scheme::kzg::{Accumulator, NativeDecider},
        };

        let loader = NativeLoader;
        let statements = $instances.clone().into_iter().flatten().collect::<Vec<_>>();
        let accept = {
            collect_slice!(statements);
            $accumulator
                .accumulate(
                    &$protocol,
                    &loader,
                    &statements,
                    &mut $transcript,
                    &mut NativeDecider::<Bn256>::new(
                        $params.get_g()[0],
                        $params.g2(),
                        $params.s_g2(),
                    ),
                )
                .unwrap()
        };
        assert!(accept);
    }};
}
