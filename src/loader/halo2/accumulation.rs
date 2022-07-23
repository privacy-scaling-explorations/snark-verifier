use crate::{
    loader::{
        halo2::loader::{Halo2Loader, Scalar},
        LoadedEcPoint,
    },
    protocol::Protocol,
    scheme::kzg::{AccumulationStrategy, Accumulator, SameCurveAccumulation, MSM},
    util::{Itertools, Transcript},
    Error,
};
use halo2_curves::CurveAffine;
use halo2_wrong_ecc::AssignedPoint;
use std::rc::Rc;

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize>
    SameCurveAccumulation<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>, LIMBS, BITS>
{
    pub fn finalize(
        self,
        g1: C,
    ) -> (
        AssignedPoint<C::Base, C::Scalar, LIMBS, BITS>,
        AssignedPoint<C::Base, C::Scalar, LIMBS, BITS>,
    ) {
        let (lhs, rhs) = self.accumulator.unwrap().evaluate(g1.to_curve());
        let loader = lhs.loader();
        (
            loader.ec_point_nomalize(&lhs.assigned()),
            loader.ec_point_nomalize(&rhs.assigned()),
        )
    }
}

impl<'a, 'b, C, T, P, const LIMBS: usize, const BITS: usize>
    AccumulationStrategy<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>, T, P>
    for SameCurveAccumulation<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>, LIMBS, BITS>
where
    C: CurveAffine,
    T: Transcript<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>,
{
    type Output = ();

    fn extract_accumulator(
        &self,
        protocol: &Protocol<C::CurveExt>,
        loader: &Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
        transcript: &mut T,
        statements: &[Vec<Scalar<'a, 'b, C, LIMBS, BITS>>],
    ) -> Option<Accumulator<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>> {
        let accumulator_indices = protocol.accumulator_indices.as_ref()?;

        let challenges = transcript.squeeze_n_challenges(accumulator_indices.len());
        let accumulators = accumulator_indices
            .iter()
            .map(|indices| {
                assert_eq!(indices.len(), 4 * LIMBS);
                let assinged = indices
                    .iter()
                    .map(|index| statements[index.0][index.1].assigned())
                    .collect_vec();
                let lhs = loader.assign_ec_point_from_limbs(
                    assinged[..LIMBS].to_vec().try_into().unwrap(),
                    assinged[LIMBS..2 * LIMBS].to_vec().try_into().unwrap(),
                );
                let rhs = loader.assign_ec_point_from_limbs(
                    assinged[2 * LIMBS..3 * LIMBS].to_vec().try_into().unwrap(),
                    assinged[3 * LIMBS..].to_vec().try_into().unwrap(),
                );
                Accumulator::new(MSM::base(lhs), MSM::base(rhs))
            })
            .collect_vec();

        Some(Accumulator::random_linear_combine(
            challenges.into_iter().zip(accumulators),
        ))
    }

    fn process(
        &mut self,
        _: &Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
        transcript: &mut T,
        _: P,
        accumulator: Accumulator<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>,
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
