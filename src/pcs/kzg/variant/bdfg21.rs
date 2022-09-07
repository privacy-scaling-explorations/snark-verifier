use crate::{
    cost::{Cost, CostEstimation},
    loader::{LoadedScalar, Loader, ScalarLoader},
    pcs::{
        kzg::accumulator::{Accumulator, PreAccumulator},
        PolynomialCommitmentScheme, Query,
    },
    util::{
        arithmetic::{CurveAffine, FieldExt, Fraction, MultiMillerLoop},
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

#[derive(Debug)]
pub struct Bdfg21<M: MultiMillerLoop>(PhantomData<M>);

impl<M, L> PolynomialCommitmentScheme<M::G1Affine, L> for Bdfg21<M>
where
    M: MultiMillerLoop,
    L: Loader<M::G1Affine>,
{
    type SuccinctVerifyingKey = M::G1Affine;
    type DecidingKey = (M::G2Affine, M::G2Affine);
    type Proof = Bdfg21Proof<M::G1Affine, L>;
    type PreAccumulator = PreAccumulator<M::G1Affine, L>;
    type Accumulator = Accumulator<M::G1Affine, L>;

    fn read_proof<T>(_: &[Query<M::Scalar>], transcript: &mut T) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<M::G1Affine, L>,
    {
        Bdfg21Proof::read(transcript)
    }

    fn succinct_verify(
        g1: &M::G1Affine,
        commitments: &[Msm<M::G1Affine, L>],
        z: &L::LoadedScalar,
        queries: &[Query<M::Scalar, L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::PreAccumulator, Error> {
        let sets = query_sets(queries);
        let coeffs = query_set_coeffs(&sets, z, &proof.z_prime);
        let f = {
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
                - Msm::base(proof.w.clone()) * &coeffs[0].z_s
        };

        let rhs = Msm::base(proof.w_prime.clone());
        let lhs = f + rhs.clone() * &proof.z_prime;

        Ok(PreAccumulator::new(*g1, lhs, rhs))
    }
}

#[derive(Debug)]
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

fn query_sets<F: FieldExt, T: Clone>(queries: &[Query<F, T>]) -> Vec<QuerySet<F, T>> {
    let poly_shifts = queries.iter().fold(
        Vec::<(usize, Vec<F>, Vec<&T>)>::new(),
        |mut poly_shifts, query| {
            if let Some(pos) = poly_shifts
                .iter()
                .position(|(poly, _, _)| *poly == query.poly)
            {
                let (_, shifts, evaluations) = &mut poly_shifts[pos];
                if !shifts.contains(&query.shift) {
                    shifts.push(query.shift);
                    evaluations.push(&query.evaluation);
                }
            } else {
                poly_shifts.push((query.poly, vec![query.shift], vec![&query.evaluation]));
            }
            poly_shifts
        },
    );

    poly_shifts.into_iter().fold(
        Vec::<QuerySet<F, T>>::new(),
        |mut sets, (poly, shifts, evaluations)| {
            if let Some(pos) = sets.iter().position(|set| {
                BTreeSet::from_iter(set.shifts.iter()) == BTreeSet::from_iter(shifts.iter())
            }) {
                let set = &mut sets[pos];
                if !set.polys.contains(&poly) {
                    set.polys.push(poly);
                    set.evaluations.push(
                        set.shifts
                            .iter()
                            .map(|lhs| {
                                let idx = shifts.iter().position(|rhs| lhs == rhs).unwrap();
                                evaluations[idx].clone()
                            })
                            .collect(),
                    );
                }
            } else {
                let set = QuerySet {
                    shifts,
                    polys: vec![poly],
                    evaluations: vec![evaluations.into_iter().cloned().collect()],
                };
                sets.push(set);
            }
            sets
        },
    )
}

fn query_set_coeffs<F: FieldExt, T: LoadedScalar<F>>(
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

    let size = 2.max(
        (sets.iter().map(|set| set.shifts.len()).max().unwrap() - 1)
            .next_power_of_two()
            .ilog2() as usize
            + 1,
    );
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

    T::batch_invert(coeffs.iter_mut().flat_map(QuerySetCoeff::denoms));
    T::batch_invert(coeffs.iter_mut().flat_map(QuerySetCoeff::denoms));
    coeffs.iter_mut().for_each(QuerySetCoeff::evaluate);

    coeffs
}

#[derive(Clone, Debug)]
struct QuerySet<F: FieldExt, T> {
    shifts: Vec<F>,
    polys: Vec<usize>,
    evaluations: Vec<Vec<T>>,
}

impl<F: FieldExt, T: LoadedScalar<F>> QuerySet<F, T> {
    fn msm<C: CurveAffine, L: Loader<C, LoadedScalar = T>>(
        &self,
        coeff: &QuerySetCoeff<F, T>,
        commitments: &[Msm<C, L>],
        powers_of_mu: &[T],
    ) -> Msm<C, L> {
        self.polys
            .iter()
            .zip(self.evaluations.iter())
            .zip(powers_of_mu.iter())
            .map(|((poly, evaluations), power_of_mu)| {
                let loader = power_of_mu.loader();
                let commitment = coeff
                    .commitment_coeff
                    .as_ref()
                    .map(|commitment_coeff| {
                        commitments[*poly].clone() * commitment_coeff.evaluated()
                    })
                    .unwrap_or_else(|| commitments[*poly].clone());
                let remainder = loader.sum_products(
                    &coeff
                        .evaluation_coeffs
                        .iter()
                        .zip(evaluations.iter())
                        .map(|(coeff, evaluation)| (coeff.evaluated(), evaluation))
                        .collect_vec(),
                ) * coeff.remainder_coeff.as_ref().unwrap().evaluated();
                (commitment - Msm::constant(remainder)) * power_of_mu
            })
            .sum()
    }
}

#[derive(Clone, Debug)]
struct QuerySetCoeff<F, T> {
    z_s: T,
    evaluation_coeffs: Vec<Fraction<T>>,
    commitment_coeff: Option<Fraction<T>>,
    remainder_coeff: Option<Fraction<T>>,
    _marker: PhantomData<F>,
}

impl<F, T> QuerySetCoeff<F, T>
where
    F: FieldExt,
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
                    .unwrap_or_else(|| F::one())
            })
            .collect_vec();

        let z = &powers_of_z[1].clone();
        let z_pow_k_minus_one = {
            let k_minus_one = shifts.len() - 1;
            powers_of_z
                .iter()
                .enumerate()
                .skip(1)
                .filter_map(|(i, power_of_z)| {
                    (k_minus_one & (1 << i) == 1).then_some(power_of_z.clone())
                })
                .reduce(|acc, value| acc * value)
                .unwrap_or_else(|| loader.load_one())
        };

        let barycentric_weights = shifts
            .iter()
            .zip(normalized_ell_primes.iter())
            .map(|(shift, normalized_ell_prime)| {
                loader.sum_products_with_coeff(&[
                    (*normalized_ell_prime, &z_pow_k_minus_one, z_prime),
                    (-(*normalized_ell_prime * shift), &z_pow_k_minus_one, z),
                ])
            })
            .map(Fraction::one_over)
            .collect_vec();

        let z_s = shifts
            .iter()
            .map(|shift| z_prime_minus_z_shift_i.get(shift).unwrap().clone())
            .reduce(|acc, z_prime_minus_z_shift_i| acc * z_prime_minus_z_shift_i)
            .unwrap();
        let z_s_1_over_z_s = z_s_1.clone().map(|z_s_1| Fraction::new(z_s_1, z_s.clone()));

        Self {
            z_s,
            evaluation_coeffs: barycentric_weights,
            commitment_coeff: z_s_1_over_z_s,
            remainder_coeff: None,
            _marker: PhantomData,
        }
    }

    fn denoms(&mut self) -> impl IntoIterator<Item = &'_ mut T> {
        if self.evaluation_coeffs.first().unwrap().denom().is_some() {
            self.evaluation_coeffs
                .iter_mut()
                .chain(self.commitment_coeff.as_mut())
                .filter_map(Fraction::denom_mut)
                .collect_vec()
        } else if self.remainder_coeff.is_none() {
            let loader = self.z_s.loader();
            self.evaluation_coeffs
                .iter_mut()
                .chain(self.commitment_coeff.as_mut())
                .for_each(Fraction::evaluate);
            let barycentric_weights_sum = loader.sum(
                &self
                    .evaluation_coeffs
                    .iter()
                    .map(Fraction::evaluated)
                    .collect_vec(),
            );
            self.remainder_coeff = Some(match self.commitment_coeff.clone() {
                Some(coeff) => Fraction::new(coeff.evaluated().clone(), barycentric_weights_sum),
                None => Fraction::one_over(barycentric_weights_sum),
            });
            vec![self.remainder_coeff.as_mut().unwrap().denom_mut().unwrap()]
        } else {
            unreachable!()
        }
    }

    fn evaluate(&mut self) {
        self.remainder_coeff.as_mut().unwrap().evaluate();
    }
}

impl<M> CostEstimation<M::G1Affine> for Bdfg21<M>
where
    M: MultiMillerLoop,
{
    type Input = Vec<Query<M::Scalar>>;

    fn estimate_cost(_: &Vec<Query<M::Scalar>>) -> Cost {
        Cost::new(0, 2, 0, 2)
    }
}
