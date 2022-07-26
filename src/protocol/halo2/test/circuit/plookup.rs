use crate::util::{BatchInvert, EitherOrBoth, Field, Itertools};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{
        Advice, Any, Challenge, Column, ConstraintSystem, Error, Expression, FirstPhase,
        SecondPhase, Selector, ThirdPhase, VirtualCells,
    },
    poly::Rotation,
};
use rayon::prelude::*;
use std::{collections::BTreeMap, convert::TryFrom, iter, ops::Mul};

fn query<F: FieldExt, T>(
    meta: &mut ConstraintSystem<F>,
    query_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> T,
) -> T {
    let mut tmp = None;
    meta.create_gate("", |meta| {
        tmp = Some(query_fn(meta));
        Some(Expression::Constant(F::zero()))
    });
    tmp.unwrap()
}

fn first_fit_packing(cap: usize, weights: Vec<usize>) -> Vec<Vec<usize>> {
    let mut bins = Vec::<(usize, Vec<usize>)>::new();

    weights.into_iter().enumerate().for_each(|(idx, weight)| {
        for (remaining, indices) in bins.iter_mut() {
            if *remaining >= weight {
                *remaining -= weight;
                indices.push(idx);
                return;
            }
        }
        bins.push((cap - weight, vec![idx]));
    });

    bins.into_iter().map(|(_, indices)| indices).collect()
}

fn max_advice_phase<F: Field>(expression: &Expression<F>) -> u8 {
    expression.evaluate(
        &|_| 0,
        &|_| 0,
        &|_| 0,
        &|query| query.phase(),
        &|_| 0,
        &|_| 0,
        &|a| a,
        &|a, b| a.max(b),
        &|a, b| a.max(b),
        &|a, _| a,
    )
}

fn min_challenge_phase<F: Field>(expression: &Expression<F>) -> Option<u8> {
    expression.evaluate(
        &|_| None,
        &|_| None,
        &|_| None,
        &|_| None,
        &|_| None,
        &|challenge| Some(challenge.phase()),
        &|a| a,
        &|a, b| match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(phase), None) | (None, Some(phase)) => Some(phase),
            (None, None) => None,
        },
        &|a, b| match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(phase), None) | (None, Some(phase)) => Some(phase),
            (None, None) => None,
        },
        &|a, _| a,
    )
}

fn advice_column_in<F: FieldExt>(meta: &mut ConstraintSystem<F>, phase: u8) -> Column<Advice> {
    match phase {
        0 => meta.advice_column_in(FirstPhase),
        1 => meta.advice_column_in(SecondPhase),
        2 => meta.advice_column_in(ThirdPhase),
        _ => unreachable!(),
    }
}

fn challenge_usable_after<F: FieldExt>(meta: &mut ConstraintSystem<F>, phase: u8) -> Challenge {
    match phase {
        0 => meta.challenge_usable_after(FirstPhase),
        1 => meta.challenge_usable_after(SecondPhase),
        2 => meta.challenge_usable_after(ThirdPhase),
        _ => unreachable!(),
    }
}

#[derive(Clone, Debug)]
pub struct ShuffleConfig<F: FieldExt, const ZK: bool> {
    l_0: Selector,
    zs: Vec<Column<Advice>>,
    gamma: Option<Challenge>,
    lhs: Vec<Expression<F>>,
    rhs: Vec<Expression<F>>,
}

impl<F: FieldExt, const ZK: bool> ShuffleConfig<F, ZK> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lhs: impl FnOnce(&mut VirtualCells<'_, F>) -> Vec<Expression<F>>,
        rhs: impl FnOnce(&mut VirtualCells<'_, F>) -> Vec<Expression<F>>,
        l_0: Option<Selector>,
    ) -> Self {
        let (lhs, rhs, gamma) = {
            let (lhs, rhs) = query(meta, |meta| {
                let (lhs, rhs) = (lhs(meta), rhs(meta));
                assert_eq!(lhs.len(), rhs.len());
                (lhs, rhs)
            });
            let phase = iter::empty()
                .chain(lhs.iter())
                .chain(rhs.iter())
                .map(max_advice_phase)
                .max()
                .unwrap();

            let gamma = challenge_usable_after(meta, phase);

            (lhs, rhs, gamma)
        };
        let lhs_with_gamma = |meta: &mut VirtualCells<'_, F>| {
            let gamma = meta.query_challenge(gamma);
            lhs.into_iter().zip(iter::repeat(gamma)).collect()
        };
        let rhs_with_gamma = |meta: &mut VirtualCells<'_, F>| {
            let gamma = meta.query_challenge(gamma);
            rhs.into_iter().zip(iter::repeat(gamma)).collect()
        };
        let mut config = Self::configure_with_gamma(
            meta,
            lhs_with_gamma,
            rhs_with_gamma,
            |_| None,
            |_| None,
            l_0,
        );
        config.gamma = Some(gamma);
        config
    }

    pub fn configure_with_gamma(
        meta: &mut ConstraintSystem<F>,
        lhs_with_gamma: impl FnOnce(&mut VirtualCells<'_, F>) -> Vec<(Expression<F>, Expression<F>)>,
        rhs_with_gamma: impl FnOnce(&mut VirtualCells<'_, F>) -> Vec<(Expression<F>, Expression<F>)>,
        lhs_coeff: impl FnOnce(&mut VirtualCells<'_, F>) -> Option<Expression<F>>,
        rhs_coeff: impl FnOnce(&mut VirtualCells<'_, F>) -> Option<Expression<F>>,
        l_0: Option<Selector>,
    ) -> Self {
        if ZK {
            todo!()
        }

        let (lhs_with_gamma, rhs_with_gamma, lhs_coeff, rhs_coeff) = query(meta, |meta| {
            let lhs_with_gamma = lhs_with_gamma(meta);
            let rhs_with_gamma = rhs_with_gamma(meta);
            let lhs_coeff = lhs_coeff(meta);
            let rhs_coeff = rhs_coeff(meta);
            assert_eq!(lhs_with_gamma.len(), rhs_with_gamma.len());

            (lhs_with_gamma, rhs_with_gamma, lhs_coeff, rhs_coeff)
        });

        let gamma_phase = iter::empty()
            .chain(lhs_with_gamma.iter())
            .chain(rhs_with_gamma.iter())
            .map(|(value, _)| max_advice_phase(value))
            .max()
            .unwrap();
        let z_phase = gamma_phase + 1;
        assert!(!lhs_with_gamma
            .iter()
            .any(|(_, gamma)| gamma.degree() != 0
                || min_challenge_phase(gamma).unwrap() < gamma_phase));
        assert!(!rhs_with_gamma
            .iter()
            .any(|(_, gamma)| gamma.degree() != 0
                || min_challenge_phase(gamma).unwrap() < gamma_phase));

        let [lhs_bins, rhs_bins] = [&lhs_with_gamma, &rhs_with_gamma].map(|value_with_gamma| {
            first_fit_packing(
                meta.degree::<false>() - 1,
                value_with_gamma
                    .iter()
                    .map(|(value, _)| value.degree())
                    .collect(),
            )
        });
        let num_z = lhs_bins.len().max(rhs_bins.len());

        let l_0 = l_0.unwrap_or_else(|| meta.selector());
        let zs = iter::repeat_with(|| advice_column_in(meta, z_phase))
            .take(num_z)
            .collect_vec();

        let collect_contribution = |value_with_gamma: Vec<(Expression<F>, Expression<F>)>,
                                    coeff: Option<Expression<F>>,
                                    bins: &[Vec<usize>]| {
            let mut contribution = bins
                .iter()
                .map(|bin| {
                    bin.iter()
                        .map(|idx| value_with_gamma[*idx].clone())
                        .map(|(value, gamma)| value + gamma)
                        .reduce(|acc, expr| acc * expr)
                        .unwrap()
                })
                .collect_vec();

            if let Some(coeff) = coeff {
                contribution[0] = coeff * contribution[0].clone();
            }

            contribution
        };
        let lhs = collect_contribution(lhs_with_gamma, lhs_coeff, &lhs_bins);
        let rhs = collect_contribution(rhs_with_gamma, rhs_coeff, &rhs_bins);

        meta.create_gate("Shuffle", |meta| {
            let l_0 = meta.query_selector(l_0);
            let zs = iter::empty()
                .chain(zs.iter().cloned().zip(iter::repeat(Rotation::cur())))
                .chain(Some((zs[0], Rotation::next())))
                .map(|(z, at)| meta.query_advice(z, at))
                .collect_vec();

            let one = Expression::Constant(F::one());
            let z_0 = zs[0].clone();

            iter::once(l_0 * (one - z_0)).chain(
                lhs.clone()
                    .into_iter()
                    .zip_longest(rhs.clone())
                    .zip(zs.clone().into_iter().zip(zs.into_iter().skip(1)))
                    .map(|(pair, (z_i, z_j))| match pair {
                        EitherOrBoth::Left(lhs) => z_i * lhs - z_j,
                        EitherOrBoth::Right(rhs) => z_i - z_j * rhs,
                        EitherOrBoth::Both(lhs, rhs) => z_i * lhs - z_j * rhs,
                    }),
            )
        });

        ShuffleConfig {
            l_0,
            zs,
            gamma: None,
            lhs,
            rhs,
        }
    }

    pub fn assign(&self, mut layouter: impl Layouter<F>, n: usize) -> Result<(), Error> {
        if ZK {
            todo!()
        }

        let lhs = self
            .lhs
            .iter()
            .map(|expression| layouter.evaluate_committed(expression))
            .fold(
                Value::known(Vec::with_capacity(self.lhs.len() * n)),
                |acc, evaluated| {
                    acc.zip(evaluated).map(|(mut acc, evaluated)| {
                        acc.extend(evaluated);
                        acc
                    })
                },
            );
        let rhs = self
            .rhs
            .iter()
            .map(|expression| layouter.evaluate_committed(expression))
            .fold(
                Value::known(Vec::with_capacity(self.rhs.len() * n)),
                |acc, evaluated| {
                    acc.zip(evaluated).map(|(mut acc, evaluated)| {
                        acc.extend(evaluated);
                        acc
                    })
                },
            );

        let z = lhs
            .zip(rhs)
            .map(|(mut lhs, mut rhs)| {
                rhs.iter_mut().batch_invert();

                let min_len = lhs.len().min(rhs.len());
                let trailing = if lhs.len() > min_len {
                    lhs.drain(min_len..).collect_vec()
                } else {
                    rhs.drain(min_len..).collect_vec()
                };

                let products = lhs
                    .into_par_iter()
                    .zip(rhs)
                    .map(|(lhs, rhs)| lhs * rhs)
                    .chain(trailing)
                    .collect::<Vec<_>>();

                let mut z = Vec::with_capacity(self.zs.len() * n + 1);
                z.push(F::one());
                for i in 0..n {
                    for j in (i..).step_by(n).take(self.zs.len()) {
                        z.push(products[j] * z.last().unwrap());
                    }
                }

                let _last = z.pop().unwrap();
                #[cfg(feature = "sanity-check")]
                assert_eq!(_last, F::one());

                z
            })
            .transpose_vec(self.zs.len() * n);

        layouter.assign_region(
            || "zs",
            |mut region| {
                self.l_0.enable(&mut region, 0)?;

                for (idx, column) in self.zs.iter().enumerate() {
                    for (offset, value) in z.iter().skip(idx).step_by(self.zs.len()).enumerate() {
                        region.assign_advice(|| "", *column, offset, || *value)?;
                    }
                }

                Ok(())
            },
        )
    }
}

fn binomial_coeffs(n: usize) -> Vec<u64> {
    debug_assert!(n > 0);

    match n {
        1 => vec![1],
        _ => {
            let last_row = binomial_coeffs(n - 1);
            iter::once(0)
                .chain(last_row.iter().cloned())
                .zip(last_row.iter().cloned().chain(iter::once(0)))
                .map(|(n, m)| n + m)
                .collect()
        }
    }
}

fn powers<T: Clone + Mul<Output = T>>(one: T, base: T) -> impl Iterator<Item = T> {
    iter::successors(Some(one), move |power| Some(base.clone() * power.clone()))
}

fn ordered_multiset<F: FieldExt>(inputs: &[Vec<F>], table: &[F]) -> Vec<F> {
    let mut input_counts = inputs
        .par_iter()
        .flatten()
        .fold(BTreeMap::new, |mut map, value| {
            map.entry(value)
                .and_modify(|count| *count += 1)
                .or_insert(1);
            map
        })
        .reduce(BTreeMap::new, |mut acc, map| {
            map.into_iter().for_each(|(value, count)| {
                acc.entry(value)
                    .and_modify(|acc| *acc += count)
                    .or_insert(count);
            });
            acc
        });

    let mut ordered = Vec::with_capacity((inputs.len() + 1) * inputs[0].len());
    for (count, value) in table.iter().dedup_with_count() {
        let count = input_counts
            .remove(value)
            .map(|input_count| input_count + count)
            .unwrap_or(count);
        ordered.extend(iter::repeat(*value).take(count));
    }

    #[cfg(feature = "sanity-check")]
    {
        assert_eq!(input_counts.len(), 0);
        assert_eq!(ordered.len(), ordered.capacity());
    }

    ordered.extend(iter::repeat(*ordered.last().unwrap()).take(ordered.capacity() - ordered.len()));

    ordered
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct PlookupConfig<F: FieldExt, const W: usize, const ZK: bool> {
    shuffle: ShuffleConfig<F, ZK>,
    compressed_inputs: Vec<Expression<F>>,
    compressed_table: Expression<F>,
    mixes: Vec<Column<Advice>>,
    theta: Option<Challenge>,
    beta: Challenge,
    gamma: Challenge,
}

impl<F: FieldExt, const W: usize, const ZK: bool> PlookupConfig<F, W, ZK> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        inputs: impl FnOnce(&mut VirtualCells<'_, F>) -> Vec<[Expression<F>; W]>,
        table: [Column<Any>; W],
        l_0: Option<Selector>,
        theta: Option<Challenge>,
        beta: Option<Challenge>,
        gamma: Option<Challenge>,
    ) -> Self {
        if ZK {
            todo!()
        }

        let inputs = query(meta, inputs);
        let t = inputs.len();
        let theta_phase = iter::empty()
            .chain(inputs.iter().flatten())
            .map(max_advice_phase)
            .chain(table.iter().map(|column| {
                Column::<Advice>::try_from(*column)
                    .map(|column| column.column_type().phase())
                    .unwrap_or_default()
            }))
            .max()
            .unwrap();
        let mixes_phase = theta_phase + 1;

        let theta = if W > 1 {
            Some(match theta {
                Some(theta) => {
                    assert!(theta.phase() >= theta_phase);
                    theta
                }
                None => challenge_usable_after(meta, theta_phase),
            })
        } else {
            assert!(theta.is_none());
            None
        };
        let mixes = iter::repeat_with(|| advice_column_in(meta, mixes_phase))
            .take(t + 1)
            .collect_vec();
        let [beta, gamma] = [beta, gamma].map(|challenge| match challenge {
            Some(challenge) => {
                assert!(challenge.phase() >= mixes_phase);
                challenge
            }
            None => challenge_usable_after(meta, mixes_phase),
        });
        assert_ne!(theta, Some(beta));
        assert_ne!(theta, Some(gamma));
        assert_ne!(beta, gamma);

        let (compressed_inputs, compressed_table, compressed_table_w) = query(meta, |meta| {
            let [table, table_w] = [Rotation::cur(), Rotation::next()]
                .map(|at| table.map(|column| meta.query_any(column, at)));
            let theta = theta.map(|theta| meta.query_challenge(theta));

            let compressed_inputs = inputs
                .iter()
                .map(|input| {
                    input
                        .iter()
                        .cloned()
                        .reduce(|acc, expr| acc * theta.clone().unwrap() + expr)
                        .unwrap()
                })
                .collect_vec();
            let compressed_table = table
                .iter()
                .cloned()
                .reduce(|acc, expr| acc * theta.clone().unwrap() + expr)
                .unwrap();
            let compressed_table_w = table_w
                .iter()
                .cloned()
                .reduce(|acc, expr| acc * theta.clone().unwrap() + expr)
                .unwrap();

            (compressed_inputs, compressed_table, compressed_table_w)
        });
        let lhs_with_gamma = |meta: &mut VirtualCells<'_, F>| {
            let [beta, gamma] = [beta, gamma].map(|challenge| meta.query_challenge(challenge));
            let one = Expression::Constant(F::one());
            let gamma_prime = (one + beta.clone()) * gamma.clone();

            let values = compressed_inputs.clone().into_iter().chain(Some(
                compressed_table.clone() + compressed_table_w.clone() * beta,
            ));
            let gammas = iter::empty()
                .chain(iter::repeat(gamma).take(t))
                .chain(Some(gamma_prime));
            values.zip(gammas).collect()
        };
        let rhs_with_gamma = |meta: &mut VirtualCells<'_, F>| {
            let mixes = iter::empty()
                .chain(mixes.iter().cloned().zip(iter::repeat(Rotation::cur())))
                .chain(Some((mixes[0], Rotation::next())))
                .map(|(column, at)| meta.query_advice(column, at))
                .collect_vec();
            let [beta, gamma] = [beta, gamma].map(|challenge| meta.query_challenge(challenge));
            let one = Expression::Constant(F::one());
            let gamma_prime = (one + beta.clone()) * gamma;

            let values = mixes
                .iter()
                .cloned()
                .zip(mixes.iter().skip(1).cloned())
                .zip(iter::repeat(beta))
                .map(|((mix_i, mix_j), beta)| mix_i + mix_j * beta);
            let gammas = iter::repeat(gamma_prime).take(t + 1);
            values.zip(gammas).collect()
        };
        let lhs_coeff = |meta: &mut VirtualCells<'_, F>| {
            let beta = meta.query_challenge(beta);
            let one = Expression::Constant(F::one());
            binomial_coeffs(t + 1)
                .into_iter()
                .zip(powers(one, beta))
                .map(|(coeff, power_of_beta)| Expression::Constant(F::from(coeff)) * power_of_beta)
                .reduce(|acc, expr| acc + expr)
        };
        let shuffle = ShuffleConfig::configure_with_gamma(
            meta,
            lhs_with_gamma,
            rhs_with_gamma,
            lhs_coeff,
            |_| None,
            l_0,
        );

        Self {
            shuffle,
            compressed_inputs,
            compressed_table,
            mixes,
            theta,
            beta,
            gamma,
        }
    }

    pub fn assign(&self, mut layouter: impl Layouter<F>, n: usize) -> Result<(), Error> {
        if ZK {
            todo!()
        }

        let compressed_inputs = self
            .compressed_inputs
            .iter()
            .map(|expression| layouter.evaluate_committed(expression))
            .fold(Value::known(Vec::new()), |acc, compressed_input| {
                acc.zip(compressed_input)
                    .map(|(mut acc, compressed_input)| {
                        acc.push(compressed_input);
                        acc
                    })
            });
        let compressed_table = layouter.evaluate_committed(&self.compressed_table);

        let mix = compressed_inputs
            .zip(compressed_table.as_ref())
            .map(|(compressed_inputs, compressed_table)| {
                ordered_multiset(&compressed_inputs, compressed_table)
            })
            .transpose_vec(self.mixes.len() * n);

        layouter.assign_region(
            || "mixes",
            |mut region| {
                for (idx, column) in self.mixes.iter().enumerate() {
                    for (offset, value) in mix.iter().skip(idx).step_by(self.mixes.len()).enumerate() {
                        region.assign_advice(|| "", *column, offset, || *value)?;
                    }
                }

                Ok(())
            },
        )?;

        self.shuffle.assign(layouter.namespace(|| "Shuffle"), n)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{PlookupConfig, ShuffleConfig};
    use crate::util::Itertools;
    use halo2_curves::{bn256::Fr, FieldExt};
    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter, Value},
        dev::{metadata::Constraint, FailureLocation, MockProver, VerifyFailure},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed},
        poly::Rotation,
    };
    use rand::{rngs::OsRng, RngCore};
    use std::{iter, mem};

    fn shuffled<F: Default, R: RngCore, const T: usize>(
        mut values: [Vec<F>; T],
        mut rng: R,
    ) -> [Vec<F>; T] {
        let n = values[0].len();
        let mut swap = |lhs: usize, rhs: usize| {
            let tmp = mem::take(&mut values[lhs / n][lhs % n]);
            values[lhs / n][lhs % n] = mem::replace(&mut values[rhs / n][rhs % n], tmp);
        };

        for row in (1..n * T).rev() {
            let rand_row = (rng.next_u32() as usize) % row;
            swap(row, rand_row);
        }

        values
    }

    #[derive(Clone)]
    pub struct Shuffler<F, const T: usize, const ZK: bool> {
        n: usize,
        lhs: Value<[Vec<F>; T]>,
        rhs: Value<[Vec<F>; T]>,
    }

    impl<F: FieldExt, const T: usize, const ZK: bool> Shuffler<F, T, ZK> {
        pub fn rand<R: RngCore>(k: u32, mut rng: R) -> Self {
            let n = 1 << k;
            let lhs = [(); T].map(|_| {
                let rng = &mut rng;
                iter::repeat_with(|| F::random(&mut *rng))
                    .take(n)
                    .collect_vec()
            });
            let rhs = shuffled(
                lhs.iter()
                    .map(|lhs| lhs.iter().map(F::square).collect())
                    .collect_vec()
                    .try_into()
                    .unwrap(),
                rng,
            );
            Self {
                n,
                lhs: Value::known(lhs),
                rhs: Value::known(rhs),
            }
        }
    }

    impl<F: FieldExt, const T: usize, const ZK: bool> Circuit<F> for Shuffler<F, T, ZK> {
        type Config = (
            [Column<Advice>; T],
            [Column<Advice>; T],
            ShuffleConfig<F, ZK>,
        );
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self {
                n: self.n,
                lhs: Value::unknown(),
                rhs: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let lhs = [(); T].map(|_| meta.advice_column());
            let rhs = [(); T].map(|_| meta.advice_column());
            let shuffle = ShuffleConfig::configure(
                meta,
                |meta| {
                    lhs.map(|column| {
                        let lhs = meta.query_advice(column, Rotation::cur());
                        lhs.clone() * lhs
                    })
                    .to_vec()
                },
                |meta| {
                    rhs.map(|column| meta.query_advice(column, Rotation::cur()))
                        .to_vec()
                },
                None,
            );

            (lhs, rhs, shuffle)
        }

        fn synthesize(
            &self,
            (lhs, rhs, shuffle): Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "",
                |mut region| {
                    for (idx, column) in lhs.into_iter().enumerate() {
                        let values = self.lhs.as_ref().map(|lhs| lhs[idx].clone());
                        for (offset, value) in
                            values.clone().transpose_vec(self.n).into_iter().enumerate()
                        {
                            region.assign_advice(|| "", column, offset, || value)?;
                        }
                    }
                    for (idx, column) in rhs.into_iter().enumerate() {
                        let values = self.rhs.as_ref().map(|rhs| rhs[idx].clone());
                        for (offset, value) in
                            values.clone().transpose_vec(self.n).into_iter().enumerate()
                        {
                            region.assign_advice(|| "", column, offset, || value)?;
                        }
                    }
                    Ok(())
                },
            )?;
            shuffle.assign(layouter.namespace(|| "Shuffle"), self.n)?;

            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct Plookuper<F, const W: usize, const T: usize, const ZK: bool> {
        n: usize,
        inputs: Value<[Vec<[F; W]>; T]>,
        table: Vec<[F; W]>,
    }

    impl<F: FieldExt, const W: usize, const T: usize, const ZK: bool> Plookuper<F, W, T, ZK> {
        pub fn rand<R: RngCore>(k: u32, mut rng: R) -> Self {
            let n = 1 << k;
            let m = rng.next_u32() as usize % n;
            let mut table = iter::repeat_with(|| [(); W].map(|_| F::random(&mut rng)))
                .take(m)
                .collect_vec();
            table.extend(
                iter::repeat(
                    table
                        .first()
                        .cloned()
                        .unwrap_or_else(|| [(); W].map(|_| F::random(&mut rng))),
                )
                .take(n - m),
            );
            let inputs = [(); T].map(|_| {
                iter::repeat_with(|| table[rng.next_u32() as usize % n])
                    .take(n)
                    .collect()
            });
            Self {
                n,
                inputs: Value::known(inputs),
                table,
            }
        }
    }

    impl<F: FieldExt, const W: usize, const T: usize, const ZK: bool> Circuit<F>
        for Plookuper<F, W, T, ZK>
    {
        type Config = (
            [[Column<Advice>; W]; T],
            [Column<Fixed>; W],
            PlookupConfig<F, W, ZK>,
        );
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self {
                n: self.n,
                inputs: Value::unknown(),
                table: self.table.clone(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let inputs = [(); T].map(|_| [(); W].map(|_| meta.advice_column()));
            let table = [(); W].map(|_| meta.fixed_column());
            let plookup = PlookupConfig::configure(
                meta,
                |meta| {
                    inputs
                        .iter()
                        .map(|input| input.map(|column| meta.query_advice(column, Rotation::cur())))
                        .collect()
                },
                table.map(|fixed| fixed.into()),
                None,
                None,
                None,
                None,
            );

            (inputs, table, plookup)
        }

        fn synthesize(
            &self,
            (inputs, table, plookup): Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "",
                |mut region| {
                    for (offset, value) in self.table.iter().enumerate() {
                        for (column, value) in table.iter().zip(value.iter()) {
                            region.assign_fixed(|| "", *column, offset, || Value::known(*value))?;
                        }
                    }
                    Ok(())
                },
            )?;
            layouter.assign_region(
                || "",
                |mut region| {
                    for (idx, columns) in inputs.iter().enumerate() {
                        let values = self.inputs.as_ref().map(|inputs| inputs[idx].clone());
                        for (offset, value) in values.transpose_vec(self.n).into_iter().enumerate()
                        {
                            for (column, value) in columns.iter().zip(value.transpose_array()) {
                                region.assign_advice(|| "", *column, offset, || value)?;
                            }
                        }
                    }
                    Ok(())
                },
            )?;
            plookup.assign(layouter.namespace(|| "Plookup"), self.n)?;
            Ok(())
        }
    }

    #[allow(dead_code)]
    fn assert_constraint_not_satisfied(
        result: Result<(), Vec<VerifyFailure>>,
        failures: Vec<(Constraint, FailureLocation)>,
    ) {
        match result {
            Err(expected) => {
                assert_eq!(
                    expected
                        .into_iter()
                        .map(|failure| match failure {
                            VerifyFailure::ConstraintNotSatisfied {
                                constraint,
                                location,
                                ..
                            } => (constraint, location),
                            _ => panic!("MockProver::verify has unexpected failure"),
                        })
                        .collect_vec(),
                    failures
                )
            }
            Ok(_) => {
                panic!("MockProver::verify unexpectedly succeeds")
            }
        }
    }

    #[test]
    fn test_shuffle() {
        const T: usize = 9;
        const ZK: bool = false;

        let k = 9;
        let circuit = Shuffler::<Fr, T, ZK>::rand(k, OsRng);

        let mut cs = ConstraintSystem::default();
        Shuffler::<Fr, T, ZK>::configure(&mut cs);
        assert_eq!(cs.degree::<ZK>(), 3);

        MockProver::run::<_, ZK>(k, &circuit, Vec::new())
            .unwrap()
            .assert_satisfied();

        #[cfg(not(feature = "sanity-check"))]
        {
            let n = 1 << k;
            let mut circuit = circuit;
            circuit.lhs = mem::take(&mut circuit.lhs).map(|mut value| {
                value[0][0] += Fr::one();
                value
            });
            assert_constraint_not_satisfied(
                MockProver::run::<_, ZK>(k, &circuit, Vec::new())
                    .unwrap()
                    .verify(),
                vec![(
                    (
                        (2, "Shuffle").into(),
                        (T * 2).div_ceil(cs.degree::<ZK>() - 1),
                        "",
                    )
                        .into(),
                    FailureLocation::InRegion {
                        region: (0, "").into(),
                        offset: n - 1,
                    },
                )],
            );
        }
    }

    #[test]
    fn test_plookup() {
        const W: usize = 2;
        const T: usize = 5;
        const ZK: bool = false;

        let k = 9;
        let circuit = Plookuper::<Fr, W, T, ZK>::rand(k, OsRng);

        let mut cs = ConstraintSystem::default();
        Plookuper::<Fr, W, T, ZK>::configure(&mut cs);
        assert_eq!(cs.degree::<ZK>(), 3);

        MockProver::run::<_, ZK>(k, &circuit, Vec::new())
            .unwrap()
            .assert_satisfied();

        #[cfg(not(feature = "sanity-check"))]
        {
            let n = 1 << k;
            let mut circuit = circuit;
            circuit.inputs = mem::take(&mut circuit.inputs).map(|mut inputs| {
                inputs[0][0][0] += Fr::one();
                inputs
            });
            assert_constraint_not_satisfied(
                MockProver::run::<_, ZK>(k, &circuit, Vec::new())
                    .unwrap()
                    .verify(),
                vec![(
                    (
                        (3, "Shuffle").into(),
                        (T + 1).div_ceil(cs.degree::<ZK>() - 1),
                        "",
                    )
                        .into(),
                    FailureLocation::InRegion {
                        region: (0, "").into(),
                        offset: n - 1,
                    },
                )],
            );
        }
    }
}
