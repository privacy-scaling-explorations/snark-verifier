use crate::{
    cost::{Cost, CostEstimation},
    loader::{LoadedScalar, Loader, ScalarLoader},
    pcs::{
        kzg::{KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey},
        PolynomialCommitmentScheme, Query,
    },
    util::{
        arithmetic::{CurveAffine, Fraction, MultiMillerLoop, PrimeField},
        msm::Msm,
        transcript::TranscriptRead,
        Itertools,
    },
    Error,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

/// Verifier of multi-open KZG. It is for the SHPLONK implementation
/// in [`halo2_proofs`].
/// Notations are following <https://eprint.iacr.org/2020/081>.
#[derive(Clone, Debug)]
pub struct Bdfg21;

impl<M, L> PolynomialCommitmentScheme<M::G1Affine, L> for KzgAs<M, Bdfg21>
where
    M: MultiMillerLoop,
    M::Scalar: PrimeField + Ord,
    L: Loader<M::G1Affine>,
{
    type VerifyingKey = KzgSuccinctVerifyingKey<M::G1Affine>;
    type Proof = Bdfg21Proof<M::G1Affine, L>;
    type Output = KzgAccumulator<M::G1Affine, L>;

    fn read_proof<T>(
        _: &KzgSuccinctVerifyingKey<M::G1Affine>,
        _: &[Query<M::Scalar>],
        transcript: &mut T,
    ) -> Result<Bdfg21Proof<M::G1Affine, L>, Error>
    where
        T: TranscriptRead<M::G1Affine, L>,
    {
        Bdfg21Proof::read(transcript)
    }

    fn verify(
        svk: &KzgSuccinctVerifyingKey<M::G1Affine>,
        commitments: &[Msm<M::G1Affine, L>],
        z: &L::LoadedScalar,
        queries: &[Query<M::Scalar, L::LoadedScalar>],
        proof: &Bdfg21Proof<M::G1Affine, L>,
    ) -> Result<Self::Output, Error> {
        let sets = query_sets(queries);
        let f = {
            let coeffs = query_set_coeffs(&sets, z, &proof.z_prime);

            let powers_of_mu = proof
                .mu
                .powers(sets.iter().map(|set| set.polys.len()).max().unwrap());
            let msms = sets
                .iter()
                .zip(coeffs.iter())
                .map(|(set, coeff)| set.msm(coeff, commitments, &powers_of_mu));

            msms.zip(proof.gamma.powers(sets.len()).into_iter())
                .map(|(msm, power_of_gamma)| msm * &power_of_gamma)
                .sum::<Msm<_, _>>()
                - Msm::base(&proof.w) * &coeffs[0].z_s
        };

        let rhs = Msm::base(&proof.w_prime);
        let lhs = f + rhs.clone() * &proof.z_prime;

        Ok(KzgAccumulator::new(
            lhs.evaluate(Some(svk.g)),
            rhs.evaluate(Some(svk.g)),
        ))
    }
}

/// Structured proof of [`Bdfg21`].
#[derive(Clone, Debug)]
pub struct Bdfg21Proof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    mu: L::LoadedScalar,
    gamma: L::LoadedScalar,
    w: L::LoadedEcPoint,
    z_prime: L::LoadedScalar,
    w_prime: L::LoadedEcPoint,
}

impl<C, L> Bdfg21Proof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn read<T: TranscriptRead<C, L>>(transcript: &mut T) -> Result<Self, Error> {
        let mu = transcript.squeeze_challenge();
        let gamma = transcript.squeeze_challenge();
        let w = transcript.read_ec_point()?;
        let z_prime = transcript.squeeze_challenge();
        let w_prime = transcript.read_ec_point()?;
        Ok(Bdfg21Proof {
            mu,
            gamma,
            w,
            z_prime,
            w_prime,
        })
    }
}

fn query_sets<F: PrimeField + Ord, T: Clone>(queries: &[Query<F, T>]) -> Vec<QuerySet<F, T>> {
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

fn query_set_coeffs<F: PrimeField + Ord, T: LoadedScalar<F>>(
    sets: &[QuerySet<F, T>],
    z: &T,
    z_prime: &T,
) -> Vec<QuerySetCoeff<F, T>> {
    let loader = z.loader();

    let superset = sets
        .iter()
        .flat_map(|set| set.shifts.clone())
        .sorted()
        .dedup();

    let size = sets
        .iter()
        .map(|set| set.shifts.len())
        .chain(Some(2))
        .max()
        .unwrap();
    let powers_of_z = z.powers(size);
    let z_prime_minus_z_shift_i = BTreeMap::from_iter(superset.map(|shift| {
        (
            shift,
            z_prime.clone() - z.clone() * loader.load_const(&shift),
        )
    }));

    let mut z_s_1 = None;
    let mut coeffs = sets
        .iter()
        .map(|set| {
            let coeff = QuerySetCoeff::new(
                &set.shifts,
                &powers_of_z,
                z_prime,
                &z_prime_minus_z_shift_i,
                &z_s_1,
            );
            if z_s_1.is_none() {
                z_s_1 = Some(coeff.z_s.clone());
            };
            coeff
        })
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

impl<'a, F: PrimeField, T: LoadedScalar<F>> QuerySet<'a, F, T> {
    fn msm<C: CurveAffine, L: Loader<C, LoadedScalar = T>>(
        &self,
        coeff: &QuerySetCoeff<F, T>,
        commitments: &[Msm<'a, C, L>],
        powers_of_mu: &[T],
    ) -> Msm<C, L> {
        self.polys
            .iter()
            .zip(self.evals.iter())
            .zip(powers_of_mu.iter())
            .map(|((poly, evals), power_of_mu)| {
                let loader = power_of_mu.loader();
                let commitment = coeff
                    .commitment_coeff
                    .as_ref()
                    .map(|commitment_coeff| {
                        commitments[*poly].clone() * commitment_coeff.evaluated()
                    })
                    .unwrap_or_else(|| commitments[*poly].clone());
                let r_eval = loader.sum_products(
                    &coeff
                        .eval_coeffs
                        .iter()
                        .zip(evals.iter().cloned())
                        .map(|(coeff, eval)| (coeff.evaluated(), eval))
                        .collect_vec(),
                ) * coeff.r_eval_coeff.as_ref().unwrap().evaluated();
                (commitment - Msm::constant(r_eval)) * power_of_mu
            })
            .sum()
    }
}

#[derive(Clone, Debug)]
struct QuerySetCoeff<F, T> {
    z_s: T,
    eval_coeffs: Vec<Fraction<T>>,
    commitment_coeff: Option<Fraction<T>>,
    r_eval_coeff: Option<Fraction<T>>,
    _marker: PhantomData<F>,
}

impl<F, T> QuerySetCoeff<F, T>
where
    F: PrimeField + Ord,
    T: LoadedScalar<F>,
{
    fn new(
        shifts: &[F],
        powers_of_z: &[T],
        z_prime: &T,
        z_prime_minus_z_shift_i: &BTreeMap<F, T>,
        z_s_1: &Option<T>,
    ) -> Self {
        let loader = z_prime.loader();

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
                    .unwrap_or(F::ONE)
            })
            .collect_vec();

        let z = &powers_of_z[1];
        let z_pow_k_minus_one = &powers_of_z[shifts.len() - 1];

        let barycentric_weights = shifts
            .iter()
            .zip(normalized_ell_primes.iter())
            .map(|(shift, normalized_ell_prime)| {
                loader.sum_products_with_coeff(&[
                    (*normalized_ell_prime, z_pow_k_minus_one, z_prime),
                    (-(*normalized_ell_prime * shift), z_pow_k_minus_one, z),
                ])
            })
            .map(Fraction::one_over)
            .collect_vec();

        let z_s = loader.product(
            &shifts
                .iter()
                .map(|shift| z_prime_minus_z_shift_i.get(shift).unwrap())
                .collect_vec(),
        );
        let z_s_1_over_z_s = z_s_1.clone().map(|z_s_1| Fraction::new(z_s_1, z_s.clone()));

        Self {
            z_s,
            eval_coeffs: barycentric_weights,
            commitment_coeff: z_s_1_over_z_s,
            r_eval_coeff: None,
            _marker: PhantomData,
        }
    }

    fn denoms(&mut self) -> impl IntoIterator<Item = &'_ mut T> {
        if self.eval_coeffs.first().unwrap().denom().is_some() {
            return self
                .eval_coeffs
                .iter_mut()
                .chain(self.commitment_coeff.as_mut())
                .filter_map(Fraction::denom_mut)
                .collect_vec();
        }

        if self.r_eval_coeff.is_none() {
            let loader = self.z_s.loader();
            self.eval_coeffs
                .iter_mut()
                .chain(self.commitment_coeff.as_mut())
                .for_each(Fraction::evaluate);
            let barycentric_weights_sum = loader.sum(
                &self
                    .eval_coeffs
                    .iter()
                    .map(Fraction::evaluated)
                    .collect_vec(),
            );
            self.r_eval_coeff = Some(match self.commitment_coeff.as_ref() {
                Some(coeff) => Fraction::new(coeff.evaluated().clone(), barycentric_weights_sum),
                None => Fraction::one_over(barycentric_weights_sum),
            });
            return vec![self.r_eval_coeff.as_mut().unwrap().denom_mut().unwrap()];
        }

        unreachable!()
    }

    fn evaluate(&mut self) {
        self.r_eval_coeff.as_mut().unwrap().evaluate();
    }
}

impl<M> CostEstimation<M::G1Affine> for KzgAs<M, Bdfg21>
where
    M: MultiMillerLoop,
    M::Scalar: PrimeField,
{
    type Input = Vec<Query<M::Scalar>>;

    fn estimate_cost(_: &Vec<Query<M::Scalar>>) -> Cost {
        Cost {
            num_commitment: 2,
            num_msm: 2,
            ..Default::default()
        }
    }
}
