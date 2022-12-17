use crate::{
    loader::{LoadedScalar, Loader, ScalarLoader},
    pcs::{
        ipa::{Ipa, IpaProof, IpaSuccinctVerifyingKey, Round},
        MultiOpenScheme, Query,
    },
    util::{
        arithmetic::{ilog2, CurveAffine, Domain, FieldExt, Fraction},
        msm::Msm,
        transcript::TranscriptRead,
        Itertools,
    },
    Error,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    iter,
    marker::PhantomData,
};

#[derive(Clone, Debug)]
pub struct Bgh19;

impl<C, L> MultiOpenScheme<C, L> for Ipa<C, Bgh19>
where
    C: CurveAffine,
    L: Loader<C>,
{
    type SuccinctVerifyingKey = Bgh19SuccinctVerifyingKey<C>;
    type Proof = Bgh19Proof<C, L>;

    fn read_proof<T>(
        svk: &Self::SuccinctVerifyingKey,
        queries: &[Query<C::Scalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>,
    {
        Bgh19Proof::read(svk, queries, transcript)
    }

    fn succinct_verify(
        svk: &Self::SuccinctVerifyingKey,
        commitments: &[Msm<C, L>],
        x: &L::LoadedScalar,
        queries: &[Query<C::Scalar, L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::Accumulator, Error> {
        let loader = x.loader();
        let g = loader.ec_point_load_const(&svk.g);

        // Multiopen
        let sets = query_sets(queries);
        let p = {
            let coeffs = query_set_coeffs(&sets, x, &proof.x_3);

            let powers_of_x_1 = proof
                .x_1
                .powers(sets.iter().map(|set| set.polys.len()).max().unwrap());
            let f_eval = {
                let powers_of_x_2 = proof.x_2.powers(sets.len());
                let f_evals = sets
                    .iter()
                    .zip(coeffs.iter())
                    .zip(proof.q_evals.iter())
                    .map(|((set, coeff), q_eval)| set.f_eval(coeff, q_eval, &powers_of_x_1))
                    .collect_vec();
                x.loader()
                    .sum_products(&powers_of_x_2.iter().zip(f_evals.iter().rev()).collect_vec())
            };
            let msms = sets
                .iter()
                .zip(proof.q_evals.iter())
                .map(|(set, q_eval)| set.msm(commitments, q_eval, &powers_of_x_1));

            let (mut msm, constant) = iter::once(Msm::base(&proof.f) - Msm::constant(f_eval))
                .chain(msms)
                .zip(proof.x_4.powers(sets.len() + 1).into_iter().rev())
                .map(|(msm, power_of_x_4)| msm * &power_of_x_4)
                .sum::<Msm<_, _>>()
                .split();
            if let Some(constant) = constant {
                msm += Msm::base(&g) * &constant;
            }
            msm
        };

        // IPA
        Ipa::<C, ()>::succinct_verify(&svk.ipa, &p, &proof.x_3, &loader.load_zero(), &proof.ipa)
    }
}

#[derive(Clone, Debug)]
pub struct Bgh19SuccinctVerifyingKey<C: CurveAffine> {
    g: C,
    ipa: IpaSuccinctVerifyingKey<C>,
}

impl<C: CurveAffine> Bgh19SuccinctVerifyingKey<C> {
    pub fn new(domain: Domain<C::Scalar>, g: C, w: C, u: C) -> Self {
        Self {
            g,
            ipa: IpaSuccinctVerifyingKey::new(domain, u, Some(w)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Bgh19Proof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    // Multiopen
    x_1: L::LoadedScalar,
    x_2: L::LoadedScalar,
    f: L::LoadedEcPoint,
    x_3: L::LoadedScalar,
    q_evals: Vec<L::LoadedScalar>,
    x_4: L::LoadedScalar,
    // IPA
    ipa: IpaProof<C, L>,
}

impl<C, L> Bgh19Proof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn read<T: TranscriptRead<C, L>>(
        svk: &Bgh19SuccinctVerifyingKey<C>,
        queries: &[Query<C::Scalar>],
        transcript: &mut T,
    ) -> Result<Self, Error> {
        // Multiopen
        let x_1 = transcript.squeeze_challenge();
        let x_2 = transcript.squeeze_challenge();
        let f = transcript.read_ec_point()?;
        let x_3 = transcript.squeeze_challenge();
        let q_evals = transcript.read_n_scalars(query_sets(queries).len())?;
        let x_4 = transcript.squeeze_challenge();
        // IPA
        let s = transcript.read_ec_point()?;
        let xi = transcript.squeeze_challenge();
        let z = transcript.squeeze_challenge();
        let rounds = iter::repeat_with(|| {
            Ok(Round::new(
                transcript.read_ec_point()?,
                transcript.read_ec_point()?,
                transcript.squeeze_challenge(),
            ))
        })
        .take(svk.ipa.domain.k)
        .collect::<Result<Vec<_>, _>>()?;
        let c = transcript.read_scalar()?;
        let blind = transcript.read_scalar()?;
        let g = transcript.read_ec_point()?;
        Ok(Bgh19Proof {
            x_1,
            x_2,
            f,
            x_3,
            q_evals,
            x_4,
            ipa: IpaProof::new(Some((s, xi)), Some(blind), z, rounds, g, c),
        })
    }
}

fn query_sets<F, T>(queries: &[Query<F, T>]) -> Vec<QuerySet<F, T>>
where
    F: FieldExt,
    T: Clone,
{
    let poly_shifts = queries.iter().fold(
        Vec::<(usize, Vec<F>, Vec<&T>)>::new(),
        |mut poly_shifts, query| {
            if let Some(pos) = poly_shifts
                .iter()
                .position(|(poly, _, _)| *poly == query.poly)
            {
                let (_, shifts, evals) = &mut poly_shifts[pos];
                if !shifts.contains(&query.shift) {
                    shifts.push(query.shift);
                    evals.push(&query.eval);
                }
            } else {
                poly_shifts.push((query.poly, vec![query.shift], vec![&query.eval]));
            }
            poly_shifts
        },
    );

    poly_shifts.into_iter().fold(
        Vec::<QuerySet<F, T>>::new(),
        |mut sets, (poly, shifts, evals)| {
            if let Some(pos) = sets.iter().position(|set| {
                BTreeSet::from_iter(set.shifts.iter()) == BTreeSet::from_iter(shifts.iter())
            }) {
                let set = &mut sets[pos];
                if !set.polys.contains(&poly) {
                    set.polys.push(poly);
                    set.evals.push(
                        set.shifts
                            .iter()
                            .map(|lhs| {
                                let idx = shifts.iter().position(|rhs| lhs == rhs).unwrap();
                                evals[idx]
                            })
                            .collect(),
                    );
                }
            } else {
                let set = QuerySet {
                    shifts,
                    polys: vec![poly],
                    evals: vec![evals],
                };
                sets.push(set);
            }
            sets
        },
    )
}

fn query_set_coeffs<F, T>(sets: &[QuerySet<F, T>], x: &T, x_3: &T) -> Vec<QuerySetCoeff<F, T>>
where
    F: FieldExt,
    T: LoadedScalar<F>,
{
    let loader = x.loader();
    let superset = sets
        .iter()
        .flat_map(|set| set.shifts.clone())
        .sorted()
        .dedup();

    let size = 2.max(
        ilog2((sets.iter().map(|set| set.shifts.len()).max().unwrap() - 1).next_power_of_two()) + 1,
    );
    let powers_of_x = x.powers(size);
    let x_3_minus_x_shift_i = BTreeMap::from_iter(
        superset.map(|shift| (shift, x_3.clone() - x.clone() * loader.load_const(&shift))),
    );

    let mut coeffs = sets
        .iter()
        .map(|set| QuerySetCoeff::new(&set.shifts, &powers_of_x, x_3, &x_3_minus_x_shift_i))
        .collect_vec();

    T::Loader::batch_invert(coeffs.iter_mut().flat_map(QuerySetCoeff::denoms));
    T::Loader::batch_invert(coeffs.iter_mut().flat_map(QuerySetCoeff::denoms));
    coeffs.iter_mut().for_each(QuerySetCoeff::evaluate);

    coeffs
}

#[derive(Clone, Debug)]
struct QuerySet<'a, F, T> {
    shifts: Vec<F>,
    polys: Vec<usize>,
    evals: Vec<Vec<&'a T>>,
}

impl<'a, F, T> QuerySet<'a, F, T>
where
    F: FieldExt,
    T: LoadedScalar<F>,
{
    fn msm<C: CurveAffine, L: Loader<C, LoadedScalar = T>>(
        &self,
        commitments: &[Msm<'a, C, L>],
        q_eval: &T,
        powers_of_x_1: &[T],
    ) -> Msm<C, L> {
        self.polys
            .iter()
            .rev()
            .zip(powers_of_x_1)
            .map(|(poly, power_of_x_1)| commitments[*poly].clone() * power_of_x_1)
            .sum::<Msm<_, _>>()
            - Msm::constant(q_eval.clone())
    }

    fn f_eval(&self, coeff: &QuerySetCoeff<F, T>, q_eval: &T, powers_of_x_1: &[T]) -> T {
        let loader = q_eval.loader();
        let r_eval = {
            let r_evals = self
                .evals
                .iter()
                .map(|evals| {
                    loader.sum_products(
                        &coeff
                            .eval_coeffs
                            .iter()
                            .zip(evals.iter())
                            .map(|(coeff, eval)| (coeff.evaluated(), *eval))
                            .collect_vec(),
                    ) * coeff.r_eval_coeff.as_ref().unwrap().evaluated()
                })
                .collect_vec();
            loader.sum_products(&r_evals.iter().rev().zip(powers_of_x_1).collect_vec())
        };

        (q_eval.clone() - r_eval) * coeff.f_eval_coeff.evaluated()
    }
}

#[derive(Clone, Debug)]
struct QuerySetCoeff<F, T> {
    eval_coeffs: Vec<Fraction<T>>,
    r_eval_coeff: Option<Fraction<T>>,
    f_eval_coeff: Fraction<T>,
    _marker: PhantomData<F>,
}

impl<F, T> QuerySetCoeff<F, T>
where
    F: FieldExt,
    T: LoadedScalar<F>,
{
    fn new(shifts: &[F], powers_of_x: &[T], x_3: &T, x_3_minus_x_shift_i: &BTreeMap<F, T>) -> Self {
        let loader = x_3.loader();
        let normalized_ell_primes = shifts
            .iter()
            .enumerate()
            .map(|(j, shift_j)| {
                shifts
                    .iter()
                    .enumerate()
                    .filter(|&(i, _)| i != j)
                    .map(|(_, shift_i)| (*shift_j - shift_i))
                    .reduce(|acc, value| acc * value)
                    .unwrap_or_else(|| F::one())
            })
            .collect_vec();

        let x = &powers_of_x[1].clone();
        let x_pow_k_minus_one = {
            let k_minus_one = shifts.len() - 1;
            powers_of_x
                .iter()
                .enumerate()
                .skip(1)
                .filter_map(|(i, power_of_x)| {
                    (k_minus_one & (1 << i) == 1).then(|| power_of_x.clone())
                })
                .reduce(|acc, value| acc * value)
                .unwrap_or_else(|| loader.load_one())
        };

        let barycentric_weights = shifts
            .iter()
            .zip(normalized_ell_primes.iter())
            .map(|(shift, normalized_ell_prime)| {
                loader.sum_products_with_coeff(&[
                    (*normalized_ell_prime, &x_pow_k_minus_one, x_3),
                    (-(*normalized_ell_prime * shift), &x_pow_k_minus_one, x),
                ])
            })
            .map(Fraction::one_over)
            .collect_vec();

        let f_eval_coeff = Fraction::one_over(
            loader.product(
                &shifts
                    .iter()
                    .map(|shift| x_3_minus_x_shift_i.get(shift).unwrap())
                    .collect_vec(),
            ),
        );

        Self {
            eval_coeffs: barycentric_weights,
            r_eval_coeff: None,
            f_eval_coeff,
            _marker: PhantomData,
        }
    }

    fn denoms(&mut self) -> impl IntoIterator<Item = &'_ mut T> {
        if self.eval_coeffs.first().unwrap().denom().is_some() {
            return self
                .eval_coeffs
                .iter_mut()
                .chain(Some(&mut self.f_eval_coeff))
                .filter_map(Fraction::denom_mut)
                .collect_vec();
        }

        if self.r_eval_coeff.is_none() {
            self.eval_coeffs
                .iter_mut()
                .chain(Some(&mut self.f_eval_coeff))
                .for_each(Fraction::evaluate);

            let loader = self.f_eval_coeff.evaluated().loader();
            let barycentric_weights_sum = loader.sum(
                &self
                    .eval_coeffs
                    .iter()
                    .map(Fraction::evaluated)
                    .collect_vec(),
            );
            self.r_eval_coeff = Some(Fraction::one_over(barycentric_weights_sum));

            return vec![self.r_eval_coeff.as_mut().unwrap().denom_mut().unwrap()];
        }

        unreachable!()
    }

    fn evaluate(&mut self) {
        self.r_eval_coeff.as_mut().unwrap().evaluate();
    }
}
