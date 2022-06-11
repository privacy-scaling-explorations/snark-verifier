use crate::{
    protocol::Protocol,
    util::{CommonPolynomial, Domain, Expression, Query, Rotation},
};
use halo2_proofs::{
    arithmetic::{CurveAffine, CurveExt, FieldExt},
    plonk::{self, Advice, Any, ConstraintSystem, Fixed, Instance, VerifyingKey},
    poly,
    transcript::{Challenge255, Transcript},
};
use std::{io, iter};

pub mod transcript;
pub mod verifier;

impl From<poly::Rotation> for Rotation {
    fn from(rotation: poly::Rotation) -> Rotation {
        Rotation(rotation.0)
    }
}

struct Polynomials<'a, F: FieldExt> {
    cs: &'a ConstraintSystem<F>,
    n: usize,
    num_fixed: usize,
    num_permutation_fixed: usize,
    num_instance: usize,
    num_advice: usize,
    num_lookup_permuted: usize,
    num_permutation_z: usize,
    num_lookup_z: usize,
}

impl<'a, F: FieldExt> Polynomials<'a, F> {
    fn new(cs: &'a ConstraintSystem<F>, n: usize) -> Self {
        Self {
            cs,
            n,
            num_fixed: cs.num_fixed_columns(),
            num_permutation_fixed: cs.permutation().get_columns().len(),
            num_instance: cs.num_instance_columns(),
            num_advice: cs.num_advice_columns(),
            num_lookup_permuted: 2 * cs.lookups().len(),
            num_permutation_z: cs
                .permutation()
                .get_columns()
                .len()
                .div_ceil(cs.degree() - 2),
            num_lookup_z: cs.lookups().len(),
        }
    }

    fn num_preprocessed(&self) -> usize {
        self.num_fixed + self.num_permutation_fixed
    }

    fn num_statement(&self) -> usize {
        self.n * self.num_instance
    }

    fn num_auxiliary(&self) -> Vec<usize> {
        vec![
            self.n * self.num_advice,
            self.n * self.num_lookup_permuted,
            self.n * (self.num_permutation_z + self.num_lookup_z) + 1,
        ]
    }

    fn num_challenge(&self) -> Vec<usize> {
        vec![
            1, // theta
            2, // beta, gamma
            0,
        ]
    }

    fn instance_offset(&self) -> usize {
        self.num_preprocessed()
    }

    fn auxiliary_offset(&self) -> usize {
        self.instance_offset() + self.num_statement()
    }

    fn query<C: Into<Any> + Copy, R: Into<Rotation>>(
        &self,
        column_type: C,
        column_index: usize,
        rotation: R,
        t: usize,
    ) -> Query {
        let offset = match column_type.into() {
            Any::Fixed => 0,
            Any::Instance => self.instance_offset() + t * self.num_instance,
            Any::Advice => self.auxiliary_offset() + t * self.num_advice,
        };
        Query::new(offset + column_index, rotation.into())
    }

    // TODO: Enable this when using IPA
    // fn instance_queries(&'a self, t: usize) -> impl IntoIterator<Item = Query> + 'a {
    //     self.cs
    //         .instance_queries()
    //         .iter()
    //         .map(move |(column, rotation)| {
    //             self.query(*column.column_type(), column.index(), *rotation, t)
    //         })
    // }

    fn advice_queries(&'a self, t: usize) -> impl IntoIterator<Item = Query> + 'a {
        self.cs
            .advice_queries()
            .iter()
            .map(move |(column, rotation)| {
                self.query(*column.column_type(), column.index(), *rotation, t)
            })
    }

    fn fixed_queries(&'a self) -> impl IntoIterator<Item = Query> + 'a {
        self.cs
            .fixed_queries()
            .iter()
            .map(move |(column, rotation)| {
                self.query(*column.column_type(), column.index(), *rotation, 0)
            })
    }

    fn permutation_fixed_queries(&'a self) -> impl IntoIterator<Item = Query> + 'a {
        (0..self.num_permutation_fixed).map(|i| Query::new(self.num_fixed + i, 0))
    }

    fn permutation_poly(&'a self, t: usize, i: usize) -> usize {
        let z_offset = self.auxiliary_offset() + self.num_auxiliary().iter().take(2).sum::<usize>();
        z_offset + t * self.num_permutation_z + i
    }

    fn permutation_z_queries<const EVAL: bool>(
        &'a self,
        t: usize,
    ) -> impl IntoIterator<Item = Query> + 'a {
        if EVAL {
            (0..self.num_permutation_z)
                .flat_map(move |i| {
                    let z = self.permutation_poly(t, i);
                    [Query::new(z, 0), Query::new(z, 1)].into_iter().chain(
                        if i == self.num_permutation_z - 1 {
                            None
                        } else {
                            Some(Query::new(z, self.rotation_last()))
                        },
                    )
                })
                .collect::<Vec<_>>()
        } else {
            iter::empty()
                .chain((0..self.num_permutation_z).flat_map(move |i| {
                    let z = self.permutation_poly(t, i);
                    [Query::new(z, 0), Query::new(z, 1)]
                }))
                .chain((0..self.num_permutation_z).rev().skip(1).map(move |i| {
                    let z = self.permutation_poly(t, i);
                    Query::new(z, self.rotation_last())
                }))
                .collect::<Vec<_>>()
        }
    }

    fn lookup_poly(&'a self, t: usize, i: usize) -> (usize, usize, usize) {
        let permuted_offset = self.auxiliary_offset() + self.num_auxiliary()[0];
        let z_offset = permuted_offset + self.num_auxiliary()[1] + self.n * self.num_permutation_z;
        let z = z_offset + t * self.num_lookup_z + i;
        let permuted_input = permuted_offset + 2 * (t * self.num_lookup_z + i);
        let permuted_table = permuted_input + 1;
        (z, permuted_input, permuted_table)
    }

    fn lookup_queries<const EVAL: bool>(
        &'a self,
        t: usize,
    ) -> impl IntoIterator<Item = Query> + 'a {
        (0..self.num_lookup_z).flat_map(move |i| {
            let (z, permuted_input, permuted_table) = self.lookup_poly(t, i);
            if EVAL {
                [
                    Query::new(z, 0),
                    Query::new(z, 1),
                    Query::new(permuted_input, 0),
                    Query::new(permuted_input, -1),
                    Query::new(permuted_table, 0),
                ]
            } else {
                [
                    Query::new(z, 0),
                    Query::new(permuted_input, 0),
                    Query::new(permuted_table, 0),
                    Query::new(permuted_input, -1),
                    Query::new(z, 1),
                ]
            }
        })
    }

    fn vanishing_query(&self) -> Query {
        Query::new(
            self.auxiliary_offset() + self.num_auxiliary().iter().sum::<usize>(),
            0,
        )
    }

    fn random_query(&self) -> Query {
        Query::new(
            self.auxiliary_offset() + self.num_auxiliary().iter().sum::<usize>() - 1,
            0,
        )
    }

    fn convert(&self, expression: &plonk::Expression<F>, t: usize) -> Expression<F> {
        expression.evaluate(
            &|scalar| Expression::Constant(scalar),
            &|_| unreachable!(),
            &|_, index, rotation| self.query(Fixed, index, rotation, t).into(),
            &|_, index, rotation| self.query(Advice, index, rotation, t).into(),
            &|_, index, rotation| self.query(Instance, index, rotation, t).into(),
            &|a| -a,
            &|a, b| a + b,
            &|a, b| a * b,
            &|a, scalar| a * scalar,
        )
    }

    fn gate_relations(&'a self, t: usize) -> impl IntoIterator<Item = Expression<F>> + 'a {
        self.cs.gates().iter().flat_map(move |gate| {
            gate.polynomials()
                .iter()
                .map(move |expression| self.convert(expression, t))
        })
    }

    fn rotation_last(&self) -> Rotation {
        Rotation(-((self.cs.blinding_factors() + 1) as i32))
    }

    fn l_last(&self) -> Expression<F> {
        Expression::CommonPolynomial(CommonPolynomial::Lagrange(self.rotation_last().0))
    }

    fn l_blind(&self) -> Expression<F> {
        (self.rotation_last().0 + 1..0)
            .map(CommonPolynomial::Lagrange)
            .map(Expression::CommonPolynomial)
            .sum()
    }

    fn l_active(&self) -> Expression<F> {
        Expression::Constant(F::one()) - self.l_last() - self.l_blind()
    }

    fn theta(&self) -> Expression<F> {
        Expression::Challenge(0)
    }

    fn beta(&self) -> Expression<F> {
        Expression::Challenge(1)
    }

    fn gamma(&self) -> Expression<F> {
        Expression::Challenge(2)
    }

    fn permutation_relations(&'a self, t: usize) -> impl IntoIterator<Item = Expression<F>> + 'a {
        let chunk_size = self.cs.degree() - 2;

        let one = &Expression::Constant(F::one());
        let l_0 = &Expression::<F>::CommonPolynomial(CommonPolynomial::Lagrange(0));
        let l_last = &self.l_last();
        let l_active = &self.l_active();
        let identity = &Expression::<F>::CommonPolynomial(CommonPolynomial::Identity);
        let beta = &self.beta();
        let gamma = &self.gamma();

        let polys = self
            .cs
            .permutation()
            .get_columns()
            .iter()
            .map(|column| self.query(*column.column_type(), column.index(), 0, t))
            .map(Expression::<F>::Polynomial)
            .collect::<Vec<_>>();
        let permutation_fixeds = (0..self.num_permutation_fixed)
            .map(|i| Query::new(self.num_fixed + i, 0))
            .map(Expression::<F>::Polynomial)
            .collect::<Vec<_>>();
        let zs = (0..self.num_permutation_z)
            .map(|i| {
                let z = self.permutation_poly(t, i);
                (
                    Expression::<F>::Polynomial(Query::new(z, 0)),
                    Expression::<F>::Polynomial(Query::new(z, 1)),
                    Expression::<F>::Polynomial(Query::new(z, self.rotation_last())),
                )
            })
            .collect::<Vec<_>>();

        iter::empty()
            .chain(zs.first().map(|(z_0, _, _)| l_0 * (one - z_0)))
            .chain(zs.last().map(|(z_l, _, _)| l_last * (z_l * z_l - z_l)))
            .chain(
                zs.iter()
                    .skip(1)
                    .zip(zs.iter())
                    .map(|((z_i, _, _), (_, _, z_j_last))| l_0 * (z_i - z_j_last)),
            )
            .chain(
                zs.iter()
                    .zip(polys.chunks(chunk_size))
                    .zip(permutation_fixeds.chunks(chunk_size))
                    .enumerate()
                    .map(|(i, (((z, z_w, _), polys), permutation_fixeds))| {
                        let left = z_w
                            * polys
                                .iter()
                                .zip(permutation_fixeds.iter())
                                .map(|(poly, permutation_fixed)| {
                                    poly + beta * permutation_fixed + gamma
                                })
                                .reduce(|acc, expr| acc * expr)
                                .unwrap();
                        let right = z * polys
                            .iter()
                            .zip(
                                iter::successors(
                                    Some(F::DELTA.pow_vartime(&[(i * chunk_size) as u64])),
                                    |delta| Some(F::DELTA * delta),
                                )
                                .map(Expression::Constant),
                            )
                            .map(|(poly, delta)| poly + beta * delta * identity + gamma)
                            .reduce(|acc, expr| acc * expr)
                            .unwrap();
                        l_active * (left - right)
                    }),
            )
            .collect::<Vec<_>>()
    }

    fn lookup_relations(&'a self, t: usize) -> impl IntoIterator<Item = Expression<F>> + 'a {
        let one = &Expression::Constant(F::one());
        let l_0 = &Expression::<F>::CommonPolynomial(CommonPolynomial::Lagrange(0));
        let l_last = &self.l_last();
        let l_active = &self.l_active();
        let theta = &self.theta();
        let beta = &self.beta();
        let gamma = &self.gamma();

        let polys = (0..self.num_lookup_z)
            .map(|i| {
                let (z, permuted_input, permuted_table) = self.lookup_poly(t, i);
                (
                    Expression::<F>::Polynomial(Query::new(z, 0)),
                    Expression::<F>::Polynomial(Query::new(z, 1)),
                    Expression::<F>::Polynomial(Query::new(permuted_input, 0)),
                    Expression::<F>::Polynomial(Query::new(permuted_input, -1)),
                    Expression::<F>::Polynomial(Query::new(permuted_table, 0)),
                )
            })
            .collect::<Vec<_>>();

        let compress = |expressions: &'a [plonk::Expression<F>]| {
            expressions
                .iter()
                .rev()
                .zip(iter::successors(Some(one.clone()), |power_of_theta| {
                    Some(power_of_theta * theta)
                }))
                .map(|(expression, power_of_theta)| power_of_theta * self.convert(expression, t))
                .reduce(|acc, expr| acc + expr)
                .unwrap()
        };

        self.cs
            .lookups()
            .iter()
            .zip(polys.iter())
            .flat_map(
                |(lookup, (z, z_w, permuted_input, permuted_input_w_inv, permuted_table))| {
                    let input = compress(&lookup.input_expressions);
                    let table = compress(&lookup.table_expressions);
                    [
                        l_0 * (one - z),
                        l_last * (z * z - z),
                        l_active
                            * (z_w * (permuted_input + beta) * (permuted_table + gamma)
                                - z * (input + beta) * (table + gamma)),
                        l_0 * (permuted_input - permuted_table),
                        l_active
                            * (permuted_input - permuted_table)
                            * (permuted_input - permuted_input_w_inv),
                    ]
                },
            )
            .collect::<Vec<_>>()
    }
}

#[derive(Default)]
struct MockTranscript<F: FieldExt>(F);

impl<C: CurveAffine> Transcript<C, Challenge255<C>> for MockTranscript<C::Scalar> {
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        unreachable!()
    }

    fn common_point(&mut self, _: C) -> io::Result<()> {
        unreachable!()
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.0 = scalar;
        Ok(())
    }
}

pub fn compile<C: CurveExt>(vk: &VerifyingKey<C::AffineExt>, n: usize) -> Protocol<C> {
    let cs = vk.cs();

    let k = vk.get_domain().empty_lagrange().len().log2();
    let domain = Domain::new(k as usize);

    let preprocessed = vk
        .fixed_commitments()
        .iter()
        .chain(vk.permutation().commitments().iter())
        .cloned()
        .map(Into::into)
        .collect();

    let polynomials = &Polynomials::new(cs, n);

    let evaluations = iter::empty()
        // .chain((0..n).flat_map(move |t| polynomials.instance_queries(t)))
        .chain((0..n).flat_map(move |t| polynomials.advice_queries(t)))
        .chain(polynomials.fixed_queries())
        .chain(iter::once(polynomials.random_query()))
        .chain(polynomials.permutation_fixed_queries())
        .chain((0..n).flat_map(move |t| polynomials.permutation_z_queries::<true>(t)))
        .chain((0..n).flat_map(move |t| polynomials.lookup_queries::<true>(t)))
        .collect();

    let queries = (0..n)
        .flat_map(|t| {
            iter::empty()
                // .chain(polynomials.instance_queries(t))
                .chain(polynomials.advice_queries(t))
                .chain(polynomials.permutation_z_queries::<false>(t))
                .chain(polynomials.lookup_queries::<false>(t))
        })
        .chain(polynomials.fixed_queries())
        .chain(polynomials.permutation_fixed_queries())
        .chain(iter::once(polynomials.vanishing_query()))
        .chain(iter::once(polynomials.random_query()))
        .collect();

    let relations = (0..n)
        .flat_map(|t| {
            iter::empty()
                .chain(polynomials.gate_relations(t))
                .chain(polynomials.permutation_relations(t))
                .chain(polynomials.lookup_relations(t))
        })
        .collect();

    let transcript_initial_state = {
        let mut transcript = MockTranscript::default();
        vk.hash_into(&mut transcript).unwrap();
        transcript.0
    };

    Protocol {
        domain,
        preprocessed,
        num_statement: polynomials.num_statement(),
        num_auxiliary: polynomials.num_auxiliary(),
        num_challenge: polynomials.num_challenge(),
        evaluations,
        queries,
        relations,
        transcript_initial_state,
    }
}

#[cfg(test)]
pub(crate) mod test {
    use halo2_proofs::{
        arithmetic::{CurveAffine, FieldExt},
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Any, Circuit, Column,
            ConstraintSystem, Error, Fixed, Instance, TableColumn, VerifyingKey,
        },
        poly::{
            commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
            Rotation, VerificationStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use rand::RngCore;
    use std::fs;

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
    pub struct TestConfig {
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

    impl TestConfig {
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
                        table.assign_cell(|| "", self.byte, byte, || Ok(F::from(byte as u64)))?;
                    }
                    Ok(())
                },
            )
        }
    }

    #[derive(Clone, Default)]
    pub struct TestCircuit<F>(F);

    impl<F: FieldExt> TestCircuit<F> {
        fn new() -> Self {
            Self(F::from(u32::MAX as u64))
        }
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = TestConfig;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::new()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            TestConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            config.load_byte_table(&mut layouter)?;

            layouter.assign_region(
                || "",
                |mut region| {
                    let a = region.assign_advice_from_instance(
                        || "",
                        config.instance,
                        0,
                        config.a,
                        0,
                    )?;
                    let a_le_byte = |i: usize| {
                        let a = &a;
                        move || {
                            a.value()
                                .map(|a| F::from(((a.get_lower_32() >> (8 * i)) & 0xff) as u64))
                                .ok_or(Error::Synthesis)
                        }
                    };
                    region.assign_fixed(|| "", config.q_a, 1, || Ok(-F::one()))?;
                    region.assign_fixed(|| "", config.q_b, 1, || Ok(F::from(1 << 24)))?;
                    region.assign_fixed(|| "", config.q_c, 1, || Ok(F::from(1 << 16)))?;
                    region.assign_fixed(|| "", config.q_d, 1, || Ok(F::from(1 << 8)))?;
                    region.assign_fixed(|| "", config.q_e, 1, || Ok(F::one()))?;
                    region.assign_fixed(|| "", config.q_byte, 1, || Ok(F::one()))?;
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

    pub fn gen_vk_and_proof<'a, S, P, V, VS, R>(
        params: &'a S::ParamsProver,
        n: usize,
        rng: R,
    ) -> (VerifyingKey<S::Curve>, Vec<Vec<Vec<S::Scalar>>>, Vec<u8>)
    where
        S: CommitmentScheme,
        S::ParamsVerifier: 'a,
        P: Prover<'a, S>,
        V: Verifier<'a, S>,
        VS: VerificationStrategy<'a, S, V, R, Output = VS>,
        R: RngCore + Copy,
    {
        let circuit = TestCircuit::<S::Scalar>::new();
        let vk = keygen_vk::<S, _>(params, &circuit).unwrap();
        let pk = keygen_pk::<S, _>(params, vk.clone(), &circuit).unwrap();

        let instance = vec![vec![circuit.0]];
        MockProver::run(params.k(), &circuit, instance.clone())
            .unwrap()
            .assert_satisfied();

        let proof = {
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(Vec::new());
            create_proof::<S, P, _, _, _, _>(
                params,
                &pk,
                &vec![circuit; n],
                vec![[[instance[0][0]].as_slice()].as_slice(); n].as_slice(),
                rng,
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        };

        let accept = {
            let params = params.verifier_params();
            let strategy = VS::new(params, rng);
            let mut transcript = Blake2bRead::init(proof.as_slice());
            verify_proof(
                params,
                &vk,
                strategy,
                vec![[[instance[0][0]].as_slice()].as_slice(); n].as_slice(),
                &mut transcript,
            )
            .unwrap()
            .finalize()
        };
        assert!(accept);

        (vk, vec![instance; n], proof)
    }
}
