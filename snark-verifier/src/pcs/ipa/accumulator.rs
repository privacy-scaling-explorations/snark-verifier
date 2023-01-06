use crate::{loader::Loader, util::arithmetic::CurveAffine};

/// Inner product argument accumulator.
#[derive(Clone, Debug)]
pub struct IpaAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    /// $\xi$.
    pub xi: Vec<L::LoadedScalar>,
    /// $U$.
    pub u: L::LoadedEcPoint,
}

impl<C, L> IpaAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    /// Initialize a [`IpaAccumulator`].
    pub fn new(xi: Vec<L::LoadedScalar>, u: L::LoadedEcPoint) -> Self {
        Self { xi, u }
    }
}
