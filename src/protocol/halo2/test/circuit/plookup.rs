use crate::util::{BatchInvert, Field};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{
        Advice, Any, Challenge, Circuit, Column, ConstraintSystem, Error, Expression, FirstPhase,
        Fixed, SecondPhase, Selector, ThirdPhase, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use rand::RngCore;
use std::{collections::BTreeMap, convert::TryFrom, iter, mem, ops::Mul};

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

#[derive(Clone)]
pub struct ShuffleConfig<const ZK: bool> {
    l_0: Selector,
    zs: Vec<Column<Advice>>,
    gamma: Option<Challenge>,
    lhs_bins: Vec<Vec<usize>>,
    rhs_bins: Vec<Vec<usize>>,
}

impl<const ZK: bool> ShuffleConfig<ZK> {
    pub fn configure<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
        lhs: impl Clone + FnOnce(&mut VirtualCells<'_, F>) -> Vec<Expression<F>>,
        rhs: impl Clone + FnOnce(&mut VirtualCells<'_, F>) -> Vec<Expression<F>>,
        l_0: Option<Selector>,
    ) -> Self {
        let gamma = {
            let (lhs, rhs) = {
                let mut tmp = None;
                meta.create_gate("", |meta| {
                    let (lhs, rhs) = (lhs.clone()(meta), rhs.clone()(meta));
                    assert_eq!(lhs.len(), rhs.len());
                    tmp = Some((lhs, rhs));
                    Some(Expression::Constant(F::zero()))
                });
                tmp.unwrap()
            };
            let phase = iter::empty()
                .chain(lhs.iter())
                .chain(rhs.iter())
                .map(max_advice_phase)
                .max()
                .unwrap();

            challenge_usable_after(meta, phase)
        };
        let lhs_with_gamma = |meta: &mut VirtualCells<'_, F>| {
            let lhs = lhs(meta);
            let gamma = meta.query_challenge(gamma);
            lhs.into_iter().zip(iter::repeat(gamma)).collect()
        };
        let rhs_with_gamma = |meta: &mut VirtualCells<'_, F>| {
            let rhs = rhs(meta);
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

    pub fn configure_with_gamma<F: FieldExt>(
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

        let (lhs_with_gamma, rhs_with_gamma, lhs_coeff, rhs_coeff) = {
            let mut tmp = None;
            meta.create_gate("", |meta| {
                let lhs_with_gamma = lhs_with_gamma(meta);
                let rhs_with_gamma = rhs_with_gamma(meta);
                let lhs_coeff = lhs_coeff(meta);
                let rhs_coeff = rhs_coeff(meta);
                assert_eq!(lhs_with_gamma.len(), rhs_with_gamma.len());
                tmp = Some((lhs_with_gamma, rhs_with_gamma, lhs_coeff, rhs_coeff));
                Some(Expression::Constant(F::zero()))
            });
            tmp.unwrap()
        };
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
            .collect::<Vec<_>>();

        meta.create_gate("Shuffle", |meta| {
            let l_0 = meta.query_selector(l_0);
            let zs = iter::empty()
                .chain(zs.iter().cloned().zip(iter::repeat(Rotation::cur())))
                .chain(Some((zs[0], Rotation::next())))
                .map(|(z, at)| meta.query_advice(z, at))
                .collect::<Vec<_>>();

            let one = Expression::Constant(F::one());
            let z_0 = zs[0].clone();

            let collect_contribution =
                |value_with_gamma: Vec<(Expression<F>, Expression<F>)>,
                 coeff: Option<Expression<F>>,
                 bins: &[Vec<usize>]| {
                    let mut contribution = bins
                        .iter()
                        .chain(iter::repeat(&Vec::new()).take(num_z - bins.len()))
                        .map(|bin| {
                            bin.iter()
                                .map(|idx| value_with_gamma[*idx].clone())
                                .map(|(value, gamma)| value + gamma)
                                .reduce(|acc, expr| acc * expr)
                        })
                        .collect::<Vec<_>>();

                    if let Some(coeff) = coeff {
                        contribution[0] = contribution[0].take().map(|value| coeff * value)
                    }

                    contribution
                };
            let lhs_contributions = collect_contribution(lhs_with_gamma, lhs_coeff, &lhs_bins);
            let rhs_contributions = collect_contribution(rhs_with_gamma, rhs_coeff, &rhs_bins);

            iter::once(l_0 * (one - z_0)).chain(
                lhs_contributions
                    .into_iter()
                    .zip(rhs_contributions)
                    .zip(zs.clone().into_iter().zip(zs.into_iter().skip(1)))
                    .map(|((lhs, rhs), (z_i, z_j))| {
                        lhs.map(|lhs| z_i.clone() * lhs).unwrap_or_else(|| z_i)
                            - rhs.map(|rhs| z_j.clone() * rhs).unwrap_or_else(|| z_j)
                    }),
            )
        });

        ShuffleConfig {
            l_0,
            zs,
            gamma: None,
            lhs_bins,
            rhs_bins,
        }
    }

    fn assign<F: FieldExt>(
        &self,
        layouter: impl Layouter<F>,
        lhs: Value<Vec<Vec<F>>>,
        rhs: Value<Vec<Vec<F>>>,
        n: usize,
    ) -> Result<(), Error> {
        let gamma = layouter.get_challenge(self.gamma.unwrap());
        let lhs_gammas = lhs
            .zip(gamma)
            .map(|(lhs, gamma)| lhs.into_iter().zip(iter::repeat(gamma)).collect::<Vec<_>>());
        let rhs_gammas = rhs
            .zip(gamma)
            .map(|(rhs, gamma)| rhs.into_iter().zip(iter::repeat(gamma)).collect::<Vec<_>>());
        self.assign_with_gamma(layouter, lhs_gammas, rhs_gammas, None, None, n)
    }

    fn assign_with_gamma<F: FieldExt>(
        &self,
        mut layouter: impl Layouter<F>,
        lhs_with_gamma: Value<Vec<(Vec<F>, F)>>,
        rhs_with_gamma: Value<Vec<(Vec<F>, F)>>,
        lhs_coeff: Option<Value<F>>,
        rhs_coeff: Option<Value<F>>,
        n: usize,
    ) -> Result<(), Error> {
        if ZK {
            todo!()
        }

        let lhs_coeff = lhs_coeff
            .map(|lhs_coeff| lhs_coeff.map(|lhs_coeff| Some(lhs_coeff)))
            .unwrap_or_else(|| Value::known(None));
        let rhs_coeff = rhs_coeff
            .map(|rhs_coeff| rhs_coeff.map(|rhs_coeff| Some(rhs_coeff)))
            .unwrap_or_else(|| Value::known(None));
        let z = lhs_with_gamma
            .zip(rhs_with_gamma)
            .zip(lhs_coeff)
            .zip(rhs_coeff)
            .map(
                |(((lhs_with_gamma, rhs_with_gamma), lhs_coeff), rhs_coeff)| {
                    let collect_contribution =
                        |mut value_with_gamma: Vec<(Vec<F>, F)>,
                         coeff: Option<F>,
                         bins: &[Vec<usize>]| {
                            let mut contribution = bins
                                .iter()
                                .map(|bin| {
                                    bin.iter()
                                        .map(|idx| mem::take(&mut value_with_gamma[*idx]))
                                        .map(|(mut values, gamma)| {
                                            values.iter_mut().for_each(|value| *value += gamma);
                                            values
                                        })
                                        .reduce(|mut acc, values| {
                                            acc.iter_mut()
                                                .zip(values)
                                                .for_each(|(acc, value)| *acc *= value);
                                            acc
                                        })
                                        .unwrap()
                                })
                                .collect::<Vec<_>>();

                            if let Some(coeff) = coeff {
                                contribution[0].iter_mut().for_each(|value| *value *= coeff);
                            }

                            contribution.into_iter().flatten().collect::<Vec<_>>()
                        };

                    let numers = collect_contribution(lhs_with_gamma, lhs_coeff, &self.lhs_bins);
                    let mut denoms =
                        collect_contribution(rhs_with_gamma, rhs_coeff, &self.rhs_bins);
                    denoms.iter_mut().batch_invert();

                    let products = numers
                        .into_iter()
                        .zip(denoms)
                        .map(|(numer, denom)| numer * denom)
                        .collect::<Vec<_>>();

                    let mut z = vec![F::one()];
                    for i in 0..n {
                        for j in (i..).step_by(n).take(self.zs.len()) {
                            z.push(products[j] * z.last().unwrap());
                        }
                    }

                    let _last = z.pop().unwrap();
                    #[cfg(feature = "sanity-check")]
                    assert_eq!(_last, F::one());

                    z
                },
            )
            .transpose_vec(self.zs.len() * n);

        layouter.assign_region(
            || "zs",
            |mut region| {
                self.l_0.enable(&mut region, 0)?;

                let mut z = z.iter();
                for offset in 0..n {
                    for column in self.zs.iter() {
                        region.assign_advice(|| "", *column, offset, || *z.next().unwrap())?;
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
    let mut input_counts =
        inputs
            .iter()
            .flatten()
            .fold(BTreeMap::<_, usize>::new(), |mut map, value| {
                map.entry(value)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                map
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

#[derive(Clone)]
pub struct PlookupConfig<const W: usize, const ZK: bool> {
    shuffle: ShuffleConfig<ZK>,
    mixes: Vec<Column<Advice>>,
    theta: Option<Challenge>,
    beta: Challenge,
    gamma: Challenge,
}

impl<const W: usize, const ZK: bool> PlookupConfig<W, ZK> {
    pub fn configure<F: FieldExt>(
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

        let inputs = {
            let mut tmp = None;
            meta.create_gate("", |meta| {
                tmp = Some(inputs(meta));
                Some(Expression::Constant(F::zero()))
            });
            tmp.unwrap()
        };
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
            .collect::<Vec<_>>();
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

        let lhs_with_gamma = |meta: &mut VirtualCells<'_, F>| {
            let [table, table_w] = [Rotation::cur(), Rotation::next()]
                .map(|at| table.map(|column| meta.query_any(column, at)));
            let theta = theta.map(|theta| meta.query_challenge(theta));
            let [beta, gamma] = [beta, gamma].map(|challenge| meta.query_challenge(challenge));
            let one = Expression::Constant(F::one());
            let gamma_prime = (one + beta.clone()) * gamma.clone();

            let table = table
                .iter()
                .cloned()
                .reduce(|acc, expr| acc * theta.clone().unwrap() + expr)
                .unwrap();
            let table_w = table_w
                .iter()
                .cloned()
                .reduce(|acc, expr| acc * theta.clone().unwrap() + expr)
                .unwrap();
            let inputs = inputs.iter().map(|input| {
                input
                    .iter()
                    .cloned()
                    .reduce(|acc, expr| acc * theta.clone().unwrap() + expr)
                    .unwrap()
            });

            let values = inputs.chain(Some(table + table_w * beta));
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
                .collect::<Vec<_>>();
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
            mixes,
            theta,
            beta,
            gamma,
        }
    }

    fn assign<F: FieldExt>(
        &self,
        mut layouter: impl Layouter<F>,
        inputs: Value<Vec<Vec<[F; W]>>>,
        table: Value<Vec<[F; W]>>,
        n: usize,
    ) -> Result<(), Error> {
        if ZK {
            todo!()
        }

        let (compressed_inputs, compressed_table, mix) = {
            let compress = |values: Vec<[F; W]>, theta: Option<F>| {
                if W > 1 {
                    let theta = theta.unwrap();
                    values
                        .into_iter()
                        .map(|value| {
                            value
                                .into_iter()
                                .reduce(|acc, value| acc * theta + value)
                                .unwrap()
                        })
                        .collect::<Vec<_>>()
                } else {
                    values.into_iter().map(|value| value[0]).collect::<Vec<_>>()
                }
            };

            let theta = self
                .theta
                .map(|theta| layouter.get_challenge(theta).map(Some))
                .unwrap_or_else(|| Value::known(None));
            let compressed_inputs = inputs.zip(theta).map(|(inputs, theta)| {
                inputs
                    .into_iter()
                    .map(|input| compress(input, theta))
                    .collect::<Vec<_>>()
            });
            let compressed_table = table
                .zip(theta)
                .map(|(table, theta)| compress(table, theta));

            let mix = compressed_inputs
                .as_ref()
                .zip(compressed_table.as_ref())
                .map(|(compressed_inputs, compressed_table)| {
                    ordered_multiset(compressed_inputs, compressed_table)
                });

            (compressed_inputs, compressed_table, mix)
        };

        let (lhs_with_gamma, rhs_with_gamma, lhs_coeff) = {
            let [beta, gamma] =
                [self.beta, self.gamma].map(|challenge| layouter.get_challenge(challenge));
            let gamma_prime = beta
                .zip(gamma)
                .map(|(beta, gamma)| (F::one() + beta) * gamma);

            let lhs_with_gamma = compressed_inputs
                .zip(compressed_table)
                .zip(beta)
                .zip(gamma)
                .zip(gamma_prime)
                .map(
                    |((((compressed_inputs, compressed_table), beta), gamma), gamma_prime)| {
                        let values = compressed_inputs.into_iter().chain(Some(
                            compressed_table
                                .iter()
                                .zip(compressed_table.iter().cycle().skip(1))
                                .map(|(table, table_w)| *table + beta * table_w)
                                .collect::<Vec<_>>(),
                        ));
                        let gammas = iter::empty()
                            .chain(iter::repeat(gamma).take(self.mixes.len() - 1))
                            .chain(Some(gamma_prime));

                        values.zip(gammas).collect::<Vec<_>>()
                    },
                );
            let rhs_with_gamma =
                mix.as_ref()
                    .zip(beta)
                    .zip(gamma_prime)
                    .map(|((mix, beta), gamma_prime)| {
                        let mut values = vec![Vec::with_capacity(n); self.mixes.len()];
                        for (idx, value) in (0..values.len()).cycle().zip(
                            mix.iter()
                                .zip(mix.iter().cycle().skip(1))
                                .map(|(mix_i, mix_j)| *mix_i + beta * mix_j),
                        ) {
                            values[idx].push(value);
                        }
                        let gammas = iter::repeat(gamma_prime).take(self.mixes.len());

                        values.into_iter().zip(gammas).collect::<Vec<_>>()
                    });
            let lhs_coeff = beta.map(|beta| {
                binomial_coeffs(self.mixes.len())
                    .into_iter()
                    .zip(powers(F::one(), beta))
                    .map(|(coeff, power_of_beta)| F::from(coeff) * power_of_beta)
                    .reduce(|acc, value| acc + value)
                    .unwrap()
            });

            (lhs_with_gamma, rhs_with_gamma, lhs_coeff)
        };

        let mix = mix.transpose_vec(self.mixes.len() * n);
        layouter.assign_region(
            || "mixes",
            |mut region| {
                let mut mix = mix.iter();
                for offset in 0..n {
                    for column in self.mixes.iter() {
                        region.assign_advice(|| "", *column, offset, || *mix.next().unwrap())?;
                    }
                }

                Ok(())
            },
        )?;

        self.shuffle.assign_with_gamma(
            layouter.namespace(|| "Shuffle"),
            lhs_with_gamma,
            rhs_with_gamma,
            Some(lhs_coeff),
            None,
            n,
        )?;

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
    pub fn rand<R: RngCore>(mut rng: R, n: usize) -> Self {
        let m = rng.next_u32() as usize % n;
        let mut table = iter::repeat_with(|| [(); W].map(|_| F::random(&mut rng)))
            .take(m)
            .collect::<Vec<_>>();
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

    pub fn instances(&self) -> Vec<Vec<F>> {
        Vec::new()
    }
}

impl<F: FieldExt, const W: usize, const T: usize, const ZK: bool> Circuit<F>
    for Plookuper<F, W, T, ZK>
{
    type Config = (
        [[Column<Advice>; W]; T],
        [Column<Fixed>; W],
        PlookupConfig<W, ZK>,
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
                    for (offset, value) in values.transpose_vec(self.n).into_iter().enumerate() {
                        for (column, value) in columns.iter().zip(value.transpose_array()) {
                            region.assign_advice(|| "", *column, offset, || value)?;
                        }
                    }
                }
                Ok(())
            },
        )?;
        plookup.assign(
            layouter.namespace(|| "Plookup"),
            self.inputs.as_ref().map(|input| input.to_vec()),
            Value::known(self.table.clone()),
            self.n,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{Plookuper, ShuffleConfig};
    use halo2_curves::{bn256::Fr, FieldExt};
    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter, Value},
        dev::{metadata::Constraint, FailureLocation, MockProver, VerifyFailure},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
        poly::Rotation,
    };
    use rand::{rngs::OsRng, RngCore};
    use std::{iter, mem};

    fn shuffled<T: Default, R: RngCore, const W: usize>(
        mut values: [Vec<T>; W],
        mut rng: R,
    ) -> [Vec<T>; W] {
        let n = values[0].len();
        let mut swap = |lhs: usize, rhs: usize| {
            let tmp = mem::take(&mut values[lhs / n][lhs % n]);
            values[lhs / n][lhs % n] = mem::replace(&mut values[rhs / n][rhs % n], tmp);
        };

        for row in (1..n * W).rev() {
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
        pub fn rand<R: RngCore>(mut rng: R, n: usize) -> Self {
            let lhs = [(); T].map(|_| {
                let rng = &mut rng;
                iter::repeat_with(|| F::random(&mut *rng))
                    .take(n)
                    .collect::<Vec<_>>()
            });
            let rhs = shuffled(lhs.clone(), rng);
            Self {
                n,
                lhs: Value::known(lhs),
                rhs: Value::known(rhs),
            }
        }
    }

    impl<F: FieldExt, const T: usize, const ZK: bool> Circuit<F> for Shuffler<F, T, ZK> {
        type Config = ([Column<Advice>; T], [Column<Advice>; T], ShuffleConfig<ZK>);
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
                    lhs.map(|column| meta.query_advice(column, Rotation::cur()))
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
            shuffle.assign(
                layouter.namespace(|| "Shuffle"),
                self.lhs.as_ref().map(|lhs| lhs.to_vec()),
                self.rhs.as_ref().map(|rhs| rhs.to_vec()),
                self.n,
            )?;

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
                        .collect::<Vec<_>>(),
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
        let n = 1 << k;
        let circuit = Shuffler::<Fr, T, ZK>::rand(OsRng, n);

        let mut cs = ConstraintSystem::default();
        Shuffler::<Fr, T, ZK>::configure(&mut cs);
        assert_eq!(cs.degree::<ZK>(), 3);

        MockProver::run::<_, ZK>(k, &circuit, Vec::new())
            .unwrap()
            .assert_satisfied();

        #[cfg(not(feature = "sanity-check"))]
        {
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
                    ((2, "Shuffle").into(), T.div_ceil(cs.degree::<ZK>() - 1), "").into(),
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
        let n = 1 << k;
        let circuit = Plookuper::<Fr, W, T, ZK>::rand(OsRng, n);

        let mut cs = ConstraintSystem::default();
        Plookuper::<Fr, W, T, ZK>::configure(&mut cs);
        assert_eq!(cs.degree::<ZK>(), 3);

        MockProver::run::<_, ZK>(k, &circuit, Vec::new())
            .unwrap()
            .assert_satisfied();

        #[cfg(not(feature = "sanity-check"))]
        {
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
                        (2, "Shuffle").into(),
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
