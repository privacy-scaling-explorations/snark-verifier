use crate::{
    loader::{
        halo2::{
            loader::{Halo2Loader, Scalar},
            Valuetools,
        },
        LoadedEcPoint,
    },
    protocol::Protocol,
    scheme::kzg::{AccumulationStrategy, Accumulator, SameCurveAccumulation, MSM},
    util::{fe_from_limbs, Itertools, Transcript},
    Error,
};
use halo2_curves::CurveAffine;
use halo2_proofs::circuit::Value;
use halo2_wrong_ecc::{
    integer::AssignedInteger, maingate::AssignedValue, AssignedPoint, EccInstructions,
};
use std::{iter, rc::Rc};

fn ec_point_from_assigned_limbs<C: CurveAffine, const LIMBS: usize, const BITS: usize>(
    limbs: &[AssignedValue<C::Scalar>],
) -> Value<C> {
    assert_eq!(limbs.len(), 2 * LIMBS);

    let [x, y] = [&limbs[..LIMBS], &limbs[LIMBS..]].map(|limbs| {
        limbs
            .iter()
            .map(|assigned| assigned.value())
            .fold_zipped(Vec::new(), |mut acc, limb| {
                acc.push(*limb);
                acc
            })
            .map(|limbs| fe_from_limbs::<_, _, LIMBS, BITS>(limbs.try_into().unwrap()))
    });

    x.zip(y).map(|(x, y)| C::from_xy(x, y).unwrap())
}

impl<
        'a,
        C: CurveAffine,
        EccChip: EccInstructions<C, C::Scalar>,
        const LIMBS: usize,
        const BITS: usize,
    > SameCurveAccumulation<C::CurveExt, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>, LIMBS, BITS>
{
    pub fn finalize(self, g1: C) -> (EccChip::AssignedPoint, EccChip::AssignedPoint) {
        let (lhs, rhs) = self.accumulator.unwrap().evaluate(g1.to_curve());
        let loader = lhs.loader();
        (
            loader.ec_point_nomalize(&lhs.assigned()),
            loader.ec_point_nomalize(&rhs.assigned()),
        )
    }
}

impl<
        'a,
        C: CurveAffine,
        EccChip: EccInstructions<
            C,
            C::Scalar,
            AssignedPoint = AssignedPoint<AssignedInteger<C::Base, C::Scalar, LIMBS, BITS>>,
            AssignedScalar = AssignedValue<C::Scalar>,
        >,
        T,
        P,
        const LIMBS: usize,
        const BITS: usize,
    > AccumulationStrategy<C::CurveExt, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>, T, P>
    for SameCurveAccumulation<C::CurveExt, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>, LIMBS, BITS>
where
    C: CurveAffine,
    T: Transcript<C::CurveExt, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>>,
{
    type Output = ();

    fn extract_accumulator(
        &self,
        protocol: &Protocol<C::CurveExt>,
        loader: &Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>,
        transcript: &mut T,
        statements: &[Vec<Scalar<'a, C, C::Scalar, EccChip>>],
    ) -> Option<Accumulator<C::CurveExt, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>>> {
        let accumulator_indices = protocol.accumulator_indices.as_ref()?;

        let challenges = transcript.squeeze_n_challenges(accumulator_indices.len());
        let accumulators = accumulator_indices
            .iter()
            .map(|indices| {
                assert_eq!(indices.len(), 4 * LIMBS);
                let assigned_limbs = indices
                    .iter()
                    .map(|index| statements[index.0][index.1].assigned())
                    .collect_vec();
                let [lhs, rhs] = [&assigned_limbs[..2 * LIMBS], &assigned_limbs[2 * LIMBS..]].map(
                    |assigned_limbs| {
                        let ec_point =
                            ec_point_from_assigned_limbs::<_, LIMBS, BITS>(assigned_limbs);
                        loader.assign_ec_point(ec_point)
                    },
                );

                for (src, dst) in assigned_limbs.iter().zip(
                    iter::empty()
                        .chain(lhs.assigned().get_x().limbs())
                        .chain(lhs.assigned().get_y().limbs())
                        .chain(rhs.assigned().get_x().limbs())
                        .chain(rhs.assigned().get_y().limbs()),
                ) {
                    loader
                        .ctx_mut()
                        .constrain_equal(src.cell(), dst.as_ref().cell())
                        .unwrap();
                }

                Accumulator::new(MSM::base(lhs), MSM::base(rhs))
            })
            .collect_vec();

        Some(Accumulator::random_linear_combine(
            challenges.into_iter().zip(accumulators),
        ))
    }

    fn process(
        &mut self,
        _: &Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>,
        transcript: &mut T,
        _: P,
        accumulator: Accumulator<C::CurveExt, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>>,
    ) -> Result<Self::Output, Error> {
        self.accumulator = Some(match self.accumulator.take() {
            Some(curr_accumulator) => {
                accumulator + curr_accumulator * &transcript.squeeze_challenge()
            }
            None => accumulator,
        });
        Ok(())
    }
}
