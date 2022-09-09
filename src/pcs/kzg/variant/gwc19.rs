use crate::{
    cost::{Cost, CostEstimation},
    loader::{LoadedScalar, Loader},
    pcs::{
        kzg::accumulator::{Accumulator, PreAccumulator},
        PolynomialCommitmentScheme, Query,
    },
    util::{
        arithmetic::{CurveAffine, FieldExt, MultiMillerLoop},
        msm::Msm,
        transcript::TranscriptRead,
        Itertools,
    },
    Error,
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct Gwc19<M: MultiMillerLoop>(PhantomData<M>);

impl<M, L> PolynomialCommitmentScheme<M::G1Affine, L> for Gwc19<M>
where
    M: MultiMillerLoop,
    L: Loader<M::G1Affine>,
{
    type SuccinctVerifyingKey = M::G1Affine;
    type DecidingKey = (M::G2Affine, M::G2Affine);
    type Proof = Gwc19Proof<M::G1Affine, L>;
    type PreAccumulator = PreAccumulator<M::G1Affine, L>;
    type Accumulator = Accumulator<M::G1Affine, L>;

    fn read_proof<T>(queries: &[Query<M::Scalar>], transcript: &mut T) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<M::G1Affine, L>,
    {
        Gwc19Proof::read(queries, transcript)
    }

    fn succinct_verify(
        g1: &M::G1Affine,
        commitments: &[Msm<M::G1Affine, L>],
        z: &L::LoadedScalar,
        queries: &[Query<M::Scalar, L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Self::PreAccumulator, Error> {
        let sets = query_sets(queries);
        let powers_of_u = &proof.u.powers(sets.len());
        let f = {
            let powers_of_v = proof
                .v
                .powers(sets.iter().map(|set| set.polys.len()).max().unwrap());
            sets.iter()
                .map(|set| set.msm(commitments, &powers_of_v))
                .zip(powers_of_u.iter())
                .map(|(msm, power_of_u)| msm * power_of_u)
                .sum::<Msm<_, _>>()
        };
        let z_omegas = sets
            .iter()
            .map(|set| z.clone() * &z.loader().load_const(&set.shift));

        let rhs = proof
            .ws
            .iter()
            .zip(powers_of_u.iter())
            .map(|(w, power_of_u)| Msm::base(w.clone()) * power_of_u)
            .collect_vec();
        let lhs = f + rhs
            .iter()
            .zip(z_omegas)
            .map(|(uw, z_omega)| uw.clone() * &z_omega)
            .sum();

        Ok(PreAccumulator::new(*g1, lhs, rhs.into_iter().sum()))
    }
}

#[derive(Clone, Debug)]
pub struct Gwc19Proof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    v: L::LoadedScalar,
    ws: Vec<L::LoadedEcPoint>,
    u: L::LoadedScalar,
}

impl<C, L> Gwc19Proof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn read<T>(queries: &[Query<C::Scalar>], transcript: &mut T) -> Result<Self, Error>
    where
        T: TranscriptRead<C, L>,
    {
        let v = transcript.squeeze_challenge();
        let ws = transcript.read_n_ec_points(query_sets(queries).len())?;
        let u = transcript.squeeze_challenge();
        Ok(Gwc19Proof { v, ws, u })
    }
}

struct QuerySet<F: FieldExt, T> {
    shift: F,
    polys: Vec<usize>,
    evaluations: Vec<T>,
}

impl<F: FieldExt, T: Clone> QuerySet<F, T> {
    fn msm<C: CurveAffine, L: Loader<C, LoadedScalar = T>>(
        &self,
        commitments: &[Msm<C, L>],
        powers_of_v: &[L::LoadedScalar],
    ) -> Msm<C, L> {
        self.polys
            .iter()
            .zip(self.evaluations.iter())
            .map(|(poly, evaluation)| {
                let commitment = commitments[*poly].clone();
                commitment - Msm::constant(evaluation.clone())
            })
            .zip(powers_of_v.iter())
            .map(|(msm, power_of_v)| msm * power_of_v)
            .sum()
    }
}

fn query_sets<F: FieldExt, T: Clone + PartialEq>(queries: &[Query<F, T>]) -> Vec<QuerySet<F, T>> {
    queries.iter().fold(Vec::new(), |mut sets, query| {
        if let Some(pos) = sets.iter().position(|set| set.shift == query.shift) {
            sets[pos].polys.push(query.poly);
            sets[pos].evaluations.push(query.evaluation.clone());
        } else {
            sets.push(QuerySet {
                shift: query.shift,
                polys: vec![query.poly],
                evaluations: vec![query.evaluation.clone()],
            });
        }
        sets
    })
}

impl<M> CostEstimation<M::G1Affine> for Gwc19<M>
where
    M: MultiMillerLoop,
{
    type Input = Vec<Query<M::Scalar>>;

    fn estimate_cost(queries: &Vec<Query<M::Scalar>>) -> Cost {
        let num_w = query_sets(queries).len();
        Cost::new(0, num_w, 0, num_w)
    }
}
