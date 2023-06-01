use ark_std::{end_timer, start_timer};
use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};
use halo2_proofs::halo2curves as halo2_curves;
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use pprof::criterion::{Output, PProfProfiler};
use rand::rngs::OsRng;
use snark_verifier_sdk::halo2::gen_srs;
use snark_verifier_sdk::SHPLONK;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    Snark,
};
use std::path::Path;

mod application {
    use super::halo2_curves::bn256::Fr;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
        poly::Rotation,
    };
    use rand::RngCore;
    use snark_verifier_sdk::CircuitExt;

    #[derive(Clone, Copy)]
    pub struct StandardPlonkConfig {
        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        q_a: Column<Fixed>,
        q_b: Column<Fixed>,
        q_c: Column<Fixed>,
        q_ab: Column<Fixed>,
        constant: Column<Fixed>,
        #[allow(dead_code)]
        instance: Column<Instance>,
    }

    impl StandardPlonkConfig {
        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
            let [a, b, c] = [(); 3].map(|_| meta.advice_column());
            let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
            let instance = meta.instance_column();

            [a, b, c].map(|column| meta.enable_equality(column));

            meta.create_gate(
                "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
                |meta| {
                    let [a, b, c] =
                        [a, b, c].map(|column| meta.query_advice(column, Rotation::cur()));
                    let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                        .map(|column| meta.query_fixed(column, Rotation::cur()));
                    let instance = meta.query_instance(instance, Rotation::cur());
                    Some(
                        q_a * a.clone()
                            + q_b * b.clone()
                            + q_c * c
                            + q_ab * a * b
                            + constant
                            + instance,
                    )
                },
            );

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
    pub struct StandardPlonk(Fr);

    impl StandardPlonk {
        pub fn rand<R: RngCore>(mut rng: R) -> Self {
            Self(Fr::from(rng.next_u32() as u64))
        }
    }

    impl CircuitExt<Fr> for StandardPlonk {
        fn num_instance(&self) -> Vec<usize> {
            vec![1]
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![vec![self.0]]
        }
    }

    impl Circuit<Fr> for StandardPlonk {
        type Config = StandardPlonkConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "halo2_circuit_params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            meta.set_minimum_degree(4);
            StandardPlonkConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "",
                |mut region| {
                    region.assign_advice(|| "", config.a, 0, || Value::known(self.0))?;
                    region.assign_fixed(|| "", config.q_a, 0, || Value::known(-Fr::one()))?;
                    region.assign_advice(|| "", config.a, 1, || Value::known(-Fr::from(5u64)))?;
                    for (idx, column) in (1..).zip([
                        config.q_a,
                        config.q_b,
                        config.q_c,
                        config.q_ab,
                        config.constant,
                    ]) {
                        region.assign_fixed(
                            || "",
                            column,
                            1,
                            || Value::known(Fr::from(idx as u64)),
                        )?;
                    }
                    let a = region.assign_advice(|| "", config.a, 2, || Value::known(Fr::one()))?;
                    a.copy_advice(|| "", &mut region, config.b, 3)?;
                    a.copy_advice(|| "", &mut region, config.c, 4)?;

                    Ok(())
                },
            )
        }
    }
}

fn gen_application_snark(params: &ParamsKZG<Bn256>) -> Snark {
    let circuit = application::StandardPlonk::rand(OsRng);

    let pk = gen_pk(params, &circuit, Some(Path::new("./benches/app.pk")));
    gen_snark_shplonk(params, &pk, circuit, None::<&str>)
}

fn bench(c: &mut Criterion) {
    let params_app = gen_srs(8);
    let snarks = [(); 3].map(|_| gen_application_snark(&params_app));

    let params = gen_srs(22);
    let agg_circuit = AggregationCircuit::<SHPLONK>::new(&params, snarks.clone());

    let start0 = start_timer!(|| "gen vk & pk");
    let pk = gen_pk(&params, &agg_circuit, Some(Path::new("./benches/agg.pk")));
    end_timer!(start0);

    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("standard-plonk-agg", params.k()),
        &(&params, &pk, &snarks),
        |b, &(params, pk, snarks)| {
            b.iter(|| {
                let agg_circuit = AggregationCircuit::<SHPLONK>::new(params, snarks.clone());
                gen_snark_shplonk(params, pk, agg_circuit, None::<&str>)
            })
        },
    );
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);
