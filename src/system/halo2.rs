use crate::{
    util::{
        arithmetic::{root_of_unity, CurveAffine, Domain, FieldExt, Rotation},
        expression::{CommonPolynomial, Expression, Query},
        Itertools,
    },
    Protocol,
};
use halo2_proofs::{
    plonk::{self, Any, ConstraintSystem, VerifyingKey},
    poly,
    transcript::{EncodedChallenge, Transcript},
};
use std::{io, iter};

pub mod util;

#[cfg(test)]
mod test;

pub struct Config {
    pub zk: bool,
    pub query_instance: bool,
    pub num_instance: Vec<usize>,
    pub num_proof: usize,
    pub accumulator_indices: Option<Vec<(usize, usize)>>,
}

pub fn compile<C: CurveAffine>(vk: &VerifyingKey<C>, config: Config) -> Protocol<C> {
    let cs = vk.cs();
    let Config {
        zk,
        num_instance,
        query_instance,
        num_proof,
        accumulator_indices,
    } = config;

    let k = vk.get_domain().empty_lagrange().len().ilog2();
    let domain = Domain::new(k as usize, root_of_unity(k as usize));

    let preprocessed = vk
        .fixed_commitments()
        .iter()
        .chain(vk.permutation().commitments().iter())
        .cloned()
        .map(Into::into)
        .collect();

    let polynomials = &Polynomials::new(cs, zk, query_instance, num_instance, num_proof);

    let evaluations = iter::empty()
        .chain((0..num_proof).flat_map(move |t| polynomials.instance_queries(t)))
        .chain((0..num_proof).flat_map(move |t| polynomials.advice_queries(t)))
        .chain(polynomials.fixed_queries())
        .chain(polynomials.random_query())
        .chain(polynomials.permutation_fixed_queries())
        .chain((0..num_proof).flat_map(move |t| polynomials.permutation_z_queries::<true>(t)))
        .chain((0..num_proof).flat_map(move |t| polynomials.lookup_queries::<true>(t)))
        .collect();

    let queries = (0..num_proof)
        .flat_map(|t| {
            iter::empty()
                .chain(polynomials.instance_queries(t))
                .chain(polynomials.advice_queries(t))
                .chain(polynomials.permutation_z_queries::<false>(t))
                .chain(polynomials.lookup_queries::<false>(t))
        })
        .chain(polynomials.fixed_queries())
        .chain(polynomials.permutation_fixed_queries())
        .chain(iter::once(polynomials.vanishing_query()))
        .chain(polynomials.random_query())
        .collect();

    let constraints = (0..num_proof)
        .flat_map(|t| {
            iter::empty()
                .chain(polynomials.gate_constraints(t))
                .chain(polynomials.permutation_constraints(t))
                .chain(polynomials.lookup_constraints(t))
        })
        .collect();

    let transcript_initial_state = transcript_initial_state::<C>(vk);

    let accumulator_indices = accumulator_indices
        .map(|accumulator_indices| polynomials.accumulator_indices(accumulator_indices))
        .unwrap_or_default();

    Protocol {
        zk: config.zk,
        domain,
        preprocessed,
        num_instance: polynomials.num_instance(),
        num_witness: polynomials.num_witness(),
        num_challenge: polynomials.num_challenge(),
        evaluations,
        queries,
        constraints,
        transcript_initial_state,
        accumulator_indices,
    }
}

impl From<poly::Rotation> for Rotation {
    fn from(rotation: poly::Rotation) -> Rotation {
        Rotation(rotation.0)
    }
}

struct Polynomials<'a, F: FieldExt> {
    cs: &'a ConstraintSystem<F>,
    zk: bool,
    query_instance: bool,
    num_proof: usize,
    num_fixed: usize,
    num_permutation_fixed: usize,
    num_instance: Vec<usize>,
    num_advice: Vec<usize>,
    num_challenge: Vec<usize>,
    num_lookup_permuted: usize,
    permutation_chunk_size: usize,
    num_permutation_z: usize,
    num_lookup_z: usize,
}

impl<'a, F: FieldExt> Polynomials<'a, F> {
    fn new(
        cs: &'a ConstraintSystem<F>,
        zk: bool,
        query_instance: bool,
        num_instance: Vec<usize>,
        num_proof: usize,
    ) -> Self {
        // TODO: Re-enable optional-zk when it's merged in pse/halo2.
        let degree = if zk { cs.degree() } else { unimplemented!() };
        let permutation_chunk_size = if zk || cs.permutation().get_columns().len() >= degree {
            degree - 2
        } else {
            degree - 1
        };

        Self {
            cs,
            zk,
            query_instance,
            num_proof,
            num_fixed: cs.num_fixed_columns(),
            num_permutation_fixed: cs.permutation().get_columns().len(),
            num_instance,
            num_advice: vec![cs.num_advice_columns()],
            num_challenge: vec![0],
            num_lookup_permuted: 2 * cs.lookups().len(),
            permutation_chunk_size,
            num_permutation_z: cs
                .permutation()
                .get_columns()
                .len()
                .div_ceil(permutation_chunk_size),
            num_lookup_z: cs.lookups().len(),
        }
    }

    fn num_preprocessed(&self) -> usize {
        self.num_fixed + self.num_permutation_fixed
    }

    fn num_instance(&self) -> Vec<usize> {
        iter::repeat(self.num_instance.clone())
            .take(self.num_proof)
            .flatten()
            .collect()
    }

    fn num_witness(&self) -> Vec<usize> {
        iter::empty()
            .chain(
                self.num_advice
                    .clone()
                    .iter()
                    .map(|num| self.num_proof * num),
            )
            .chain([
                self.num_proof * self.num_lookup_permuted,
                self.num_proof * (self.num_permutation_z + self.num_lookup_z) + self.zk as usize,
            ])
            .collect()
    }

    fn num_challenge(&self) -> Vec<usize> {
        let mut num_challenge = self.num_challenge.clone();
        *num_challenge.last_mut().unwrap() += 1; // theta
        iter::empty()
            .chain(num_challenge)
            .chain([
                2, // beta, gamma
                0,
            ])
            .collect()
    }

    fn instance_offset(&self) -> usize {
        self.num_preprocessed()
    }

    fn witness_offset(&self) -> usize {
        self.instance_offset() + self.num_instance().len()
    }

    fn cs_witness_offset(&self) -> usize {
        self.witness_offset()
            + self
                .num_witness()
                .iter()
                .take(self.num_advice.len())
                .sum::<usize>()
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
            Any::Instance => self.instance_offset() + t * self.num_instance.len(),
            Any::Advice => self.witness_offset() + t * self.num_advice.iter().sum::<usize>(),
        };
        Query::new(offset + column_index, rotation.into())
    }

    fn instance_queries(&'a self, t: usize) -> impl IntoIterator<Item = Query> + 'a {
        self.query_instance
            .then_some(
                self.cs
                    .instance_queries()
                    .iter()
                    .map(move |(column, rotation)| {
                        self.query(*column.column_type(), column.index(), *rotation, t)
                    }),
            )
            .into_iter()
            .flatten()
    }

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
        let z_offset = self.cs_witness_offset() + self.num_witness()[self.num_advice.len()];
        z_offset + t * self.num_permutation_z + i
    }

    fn permutation_z_queries<const EVAL: bool>(
        &'a self,
        t: usize,
    ) -> impl IntoIterator<Item = Query> + 'a {
        match (self.zk, EVAL) {
            (true, true) => (0..self.num_permutation_z)
                .flat_map(move |i| {
                    let z = self.permutation_poly(t, i);
                    iter::empty()
                        .chain([Query::new(z, 0), Query::new(z, 1)])
                        .chain(if i == self.num_permutation_z - 1 {
                            None
                        } else {
                            Some(Query::new(z, self.rotation_last()))
                        })
                })
                .collect_vec(),
            (true, false) => iter::empty()
                .chain((0..self.num_permutation_z).flat_map(move |i| {
                    let z = self.permutation_poly(t, i);
                    [Query::new(z, 0), Query::new(z, 1)]
                }))
                .chain((0..self.num_permutation_z).rev().skip(1).map(move |i| {
                    let z = self.permutation_poly(t, i);
                    Query::new(z, self.rotation_last())
                }))
                .collect_vec(),
            (false, _) => (0..self.num_permutation_z)
                .flat_map(move |i| {
                    let z = self.permutation_poly(t, i);
                    [Query::new(z, 0), Query::new(z, 1)]
                })
                .collect_vec(),
        }
    }

    fn lookup_poly(&'a self, t: usize, i: usize) -> (usize, usize, usize) {
        let permuted_offset = self.cs_witness_offset();
        let z_offset = permuted_offset
            + self.num_witness()[self.num_advice.len()]
            + self.num_proof * self.num_permutation_z;
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
            self.witness_offset() + self.num_witness().iter().sum::<usize>(),
            0,
        )
    }

    fn random_query(&self) -> Option<Query> {
        self.zk.then_some(Query::new(
            self.witness_offset() + self.num_witness().iter().sum::<usize>() - 1,
            0,
        ))
    }

    fn convert(&self, expression: &plonk::Expression<F>, t: usize) -> Expression<F> {
        expression.evaluate(
            &|scalar| Expression::Constant(scalar),
            &|_| unreachable!(),
            &|query| {
                self.query(Any::Fixed, query.column_index(), query.rotation(), t)
                    .into()
            },
            &|query| {
                self.query(Any::Advice, query.column_index(), query.rotation(), t)
                    .into()
            },
            &|query| {
                self.query(Any::Instance, query.column_index(), query.rotation(), t)
                    .into()
            },
            &|a| -a,
            &|a, b| a + b,
            &|a, b| a * b,
            &|a, scalar| a * scalar,
        )
    }

    fn gate_constraints(&'a self, t: usize) -> impl IntoIterator<Item = Expression<F>> + 'a {
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
        if self.zk {
            Expression::CommonPolynomial(CommonPolynomial::Lagrange(self.rotation_last().0))
        } else {
            Expression::CommonPolynomial(CommonPolynomial::Lagrange(-1))
        }
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

    fn system_challenge_offset(&self) -> usize {
        let num_challenge = self.num_challenge();
        num_challenge[..num_challenge.len() - 3].iter().sum()
    }

    fn theta(&self) -> Expression<F> {
        Expression::Challenge(self.system_challenge_offset())
    }

    fn beta(&self) -> Expression<F> {
        Expression::Challenge(self.system_challenge_offset() + 1)
    }

    fn gamma(&self) -> Expression<F> {
        Expression::Challenge(self.system_challenge_offset() + 2)
    }

    fn permutation_constraints(&'a self, t: usize) -> impl IntoIterator<Item = Expression<F>> + 'a {
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
            .collect_vec();
        let permutation_fixeds = (0..self.num_permutation_fixed)
            .map(|i| Query::new(self.num_fixed + i, 0))
            .map(Expression::<F>::Polynomial)
            .collect_vec();
        let zs = (0..self.num_permutation_z)
            .map(|i| {
                let z = self.permutation_poly(t, i);
                (
                    Expression::<F>::Polynomial(Query::new(z, 0)),
                    Expression::<F>::Polynomial(Query::new(z, 1)),
                    Expression::<F>::Polynomial(Query::new(z, self.rotation_last())),
                )
            })
            .collect_vec();

        iter::empty()
            .chain(zs.first().map(|(z_0, _, _)| l_0 * (one - z_0)))
            .chain(
                zs.last()
                    .and_then(|(z_l, _, _)| self.zk.then_some(l_last * (z_l * z_l - z_l))),
            )
            .chain(if self.zk {
                zs.iter()
                    .skip(1)
                    .zip(zs.iter())
                    .map(|((z, _, _), (_, _, z_prev_last))| l_0 * (z - z_prev_last))
                    .collect_vec()
            } else {
                Vec::new()
            })
            .chain(
                zs.iter()
                    .zip(zs.iter().cycle().skip(1))
                    .zip(polys.chunks(self.permutation_chunk_size))
                    .zip(permutation_fixeds.chunks(self.permutation_chunk_size))
                    .enumerate()
                    .map(
                        |(i, ((((z, z_w, _), (_, z_next_w, _)), polys), permutation_fixeds))| {
                            let left = if self.zk || zs.len() == 1 {
                                z_w.clone()
                            } else {
                                z_w + l_last * (z_next_w - z_w)
                            } * polys
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
                                        Some(F::DELTA.pow_vartime(&[(i
                                            * self.permutation_chunk_size)
                                            as u64])),
                                        |delta| Some(F::DELTA * delta),
                                    )
                                    .map(Expression::Constant),
                                )
                                .map(|(poly, delta)| poly + beta * delta * identity + gamma)
                                .reduce(|acc, expr| acc * expr)
                                .unwrap();
                            if self.zk {
                                l_active * (left - right)
                            } else {
                                left - right
                            }
                        },
                    ),
            )
            .collect_vec()
    }

    fn lookup_constraints(&'a self, t: usize) -> impl IntoIterator<Item = Expression<F>> + 'a {
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
            .collect_vec();

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
                    let input = compress(lookup.input_expressions());
                    let table = compress(lookup.table_expressions());
                    iter::empty()
                        .chain(Some(l_0 * (one - z)))
                        .chain(self.zk.then_some(l_last * (z * z - z)))
                        .chain(Some(if self.zk {
                            l_active
                                * (z_w * (permuted_input + beta) * (permuted_table + gamma)
                                    - z * (input + beta) * (table + gamma))
                        } else {
                            z_w * (permuted_input + beta) * (permuted_table + gamma)
                                - z * (input + beta) * (table + gamma)
                        }))
                        .chain(self.zk.then_some(l_0 * (permuted_input - permuted_table)))
                        .chain(Some(if self.zk {
                            l_active
                                * (permuted_input - permuted_table)
                                * (permuted_input - permuted_input_w_inv)
                        } else {
                            (permuted_input - permuted_table)
                                * (permuted_input - permuted_input_w_inv)
                        }))
                },
            )
            .collect_vec()
    }

    fn accumulator_indices(
        &self,
        accumulator_indices: Vec<(usize, usize)>,
    ) -> Vec<Vec<(usize, usize)>> {
        (0..self.num_proof)
            .map(|t| {
                accumulator_indices
                    .iter()
                    .cloned()
                    .map(|(poly, row)| (poly + t * self.num_instance.len(), row))
                    .collect()
            })
            .collect()
    }
}

struct MockChallenge;

impl<C: CurveAffine> EncodedChallenge<C> for MockChallenge {
    type Input = ();

    fn new(_: &Self::Input) -> Self {
        unreachable!()
    }

    fn get_scalar(&self) -> C::Scalar {
        unreachable!()
    }
}

#[derive(Default)]
struct MockTranscript<F: FieldExt>(F);

impl<C: CurveAffine> Transcript<C, MockChallenge> for MockTranscript<C::Scalar> {
    fn squeeze_challenge(&mut self) -> MockChallenge {
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

fn transcript_initial_state<C: CurveAffine>(vk: &VerifyingKey<C>) -> C::Scalar {
    let mut transcript = MockTranscript::default();
    vk.hash_into(&mut transcript).unwrap();
    transcript.0
}
