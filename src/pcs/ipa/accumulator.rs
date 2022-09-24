use crate::{loader::Loader, util::arithmetic::CurveAffine};

#[derive(Clone, Debug)]
pub struct IpaAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub xi: Vec<L::LoadedScalar>,
    pub u: L::LoadedEcPoint,
}

impl<C, L> IpaAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub fn new(xi: Vec<L::LoadedScalar>, u: L::LoadedEcPoint) -> Self {
        Self { xi, u }
    }
}
