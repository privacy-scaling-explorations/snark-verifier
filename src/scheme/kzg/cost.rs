use crate::{protocol::Protocol, util::Curve};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cost {
    pub num_statement: usize,
    pub num_commitment: usize,
    pub num_evaluation: usize,
    pub num_msm: usize,
}

impl Cost {
    pub fn new(
        num_statement: usize,
        num_commitment: usize,
        num_evaluation: usize,
        num_msm: usize,
    ) -> Self {
        Self {
            num_statement,
            num_commitment,
            num_evaluation,
            num_msm,
        }
    }
}

pub trait CostEstimation {
    fn estimate_cost<C: Curve>(protocol: &Protocol<C>) -> Cost;
}
