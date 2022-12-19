use std::ops::Add;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Cost {
    pub num_instance: usize,
    pub num_commitment: usize,
    pub num_evaluation: usize,
    pub num_msm: usize,
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

pub trait CostEstimation<T> {
    type Input;

    fn estimate_cost(input: &Self::Input) -> Cost;
}
