use ethereum_types::Address;
use foundry_evm::executor::{fork::MultiFork, Backend, ExecutorBuilder};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, Layouter, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Any, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        Rotation, VerificationStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use plonk_verifier::{
    loader::evm::{encode_calldata, EvmLoader, EvmTranscript},
    protocol::halo2::{compile, Config},
    scheme::kzg::{AccumulationScheme, PlonkAccumulationScheme, SameCurveAccumulation},
    util::TranscriptRead,
};
use rand::{rngs::OsRng, RngCore};
use std::{iter, rc::Rc};

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

fn sample_srs() -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(8, OsRng)
}

fn sample_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
}

fn sample_proof<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn evm_verifier_codegen(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    const LIMBS: usize = 4;
    const BITS: usize = 68;

    let protocol = compile(
        vk,
        Config {
            zk: true,
            query_instance: false,
            num_instance: instances
                .iter()
                .map(|instances| instances.len())
                .collect_vec(),
            num_proof: 1,
            accumulator_indices: None,
        },
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());
    let instances = instances
        .iter()
        .map(|instance| {
            iter::repeat_with(|| transcript.read_scalar().unwrap())
                .take(instance.len())
                .collect_vec()
        })
        .collect_vec();

    let mut strategy = SameCurveAccumulation::<_, _, LIMBS, BITS>::default();
    PlonkAccumulationScheme::accumulate(
        &protocol,
        &loader,
        instances,
        &mut transcript,
        &mut strategy,
    )
    .unwrap();
    strategy.finalize(params.get_g()[0], params.g2(), params.s_g2());
    loader.deployment_code()
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(instances, proof);
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build(Backend::new(MultiFork::new().0, None));

        let caller = Address::from_low_u64_be(0xfe);
        let verifier = evm
            .deploy(caller, deployment_code.into(), 0.into(), None)
            .unwrap()
            .address;
        let result = evm
            .call_raw(caller, verifier, calldata.into(), 0.into())
            .unwrap();

        !result.reverted
    };
    assert!(success);
}

fn main() {
    let params = sample_srs();

    let circuit = StandardPlonk::rand(OsRng);
    let pk = sample_pk(&params, &circuit);
    let deployment_code = evm_verifier_codegen(&params, pk.get_vk(), circuit.instances());

    let proof = sample_proof(&params, &pk, circuit.clone(), circuit.instances());
    evm_verify(deployment_code, circuit.instances(), proof);
}
