use std::ops::Add;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cost {
    pub num_instance: usize,
    pub num_commitment: usize,
    pub num_evaluation: usize,
    pub num_msm: usize,
}

impl Cost {
    pub fn new(
        num_instance: usize,
        num_commitment: usize,
        num_evaluation: usize,
        num_msm: usize,
    ) -> Self {
        Self {
            num_instance,
            num_commitment,
            num_evaluation,
            num_msm,
        }
    }
}

impl Add<Cost> for Cost {
    type Output = Cost;

    fn add(self, rhs: Cost) -> Self::Output {
        Cost::new(
            self.num_instance + rhs.num_instance,
            self.num_commitment + rhs.num_commitment,
            self.num_evaluation + rhs.num_evaluation,
            self.num_msm + rhs.num_msm,
        )
    }
}

pub trait CostEstimation<T> {
    type Input;

    fn estimate_cost(input: &Self::Input) -> Cost;
}
