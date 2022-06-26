use crate::{
    loader::halo2::loader::{Halo2Loader, Scalar},
    protocol::Protocol,
    scheme::kzg::{accumulation::AccumulationStrategy, Accumulator},
    util::Transcript,
    Error,
};
use halo2_curves::CurveAffine;
use halo2_wrong_ecc::AssignedPoint;
use std::rc::Rc;

pub struct SameCurveRecursion<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> {
    accumulator: Option<Accumulator<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>>,
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Default
    for SameCurveRecursion<'a, 'b, C, LIMBS, BITS>
{
    fn default() -> Self {
        Self { accumulator: None }
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize>
    SameCurveRecursion<'a, 'b, C, LIMBS, BITS>
{
    pub fn finalize(
        self,
        g1: C,
    ) -> (
        AssignedPoint<C::Base, C::Scalar, LIMBS, BITS>,
        AssignedPoint<C::Base, C::Scalar, LIMBS, BITS>,
    ) {
        let (lhs, rhs) = self.accumulator.unwrap().evaluate(g1.to_curve());
        (lhs.assigned(), rhs.assigned())
    }
}

impl<'a, 'b, C, T, P, const LIMBS: usize, const BITS: usize>
    AccumulationStrategy<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>, T, P>
    for SameCurveRecursion<'a, 'b, C, LIMBS, BITS>
where
    C: CurveAffine,
    T: Transcript<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>,
{
    type Output = ();

    fn extract_accumulator(
        _protocol: &Protocol<C::CurveExt>,
        _loader: &Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
        _statements: &[&[Scalar<'a, 'b, C, LIMBS, BITS>]],
        _transcript: &mut T,
    ) -> Option<Accumulator<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>> {
        todo!()
    }

    fn process(
        &mut self,
        _: &Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
        transcript: &mut T,
        _: P,
        accumulator: Accumulator<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>,
    ) -> Result<Self::Output, Error> {
        match self.accumulator.as_mut() {
            Some(old_accumulator) => {
                *old_accumulator *= &transcript.squeeze_challenge();
                *old_accumulator += accumulator;
            }
            None => self.accumulator = Some(accumulator),
        }
        Ok(())
    }
}
