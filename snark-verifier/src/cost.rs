//! Cost estimation.

use std::ops::Add;

/// Cost of verification.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Cost {
    /// Number of instances.
    pub num_instance: usize,
    /// Number of commitments in proof.
    pub num_commitment: usize,
    /// Number of evaluations in proof.
    pub num_evaluation: usize,
    /// Number of scalar multiplications to perform.
    pub num_msm: usize,
    /// Number of pairings to perform.
    pub num_pairing: usize,
}

impl Add<Cost> for Cost {
    type Output = Cost;

    fn add(mut self, rhs: Cost) -> Self::Output {
        self.num_instance += rhs.num_instance;
        self.num_commitment += rhs.num_commitment;
        self.num_evaluation += rhs.num_evaluation;
        self.num_msm += rhs.num_msm;
        self.num_pairing += rhs.num_pairing;
        self
    }
}

/// For estimating cost of a verifier.
pub trait CostEstimation<T> {
    /// Input for [`CostEstimation::estimate_cost`].
    type Input;

    /// Estimate cost of verifier given the input.
    fn estimate_cost(input: &Self::Input) -> Cost;
}
