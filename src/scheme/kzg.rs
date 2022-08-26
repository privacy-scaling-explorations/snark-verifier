use crate::{
    protocol::Protocol,
    util::{Curve, Expression},
};

mod accumulation;
mod accumulator;
mod cost;
mod msm;

pub use accumulation::{
    plonk::PlonkAccumulationScheme, shplonk::ShplonkAccumulationScheme, AccumulationScheme,
    AccumulationStrategy, SameCurveAccumulation,
};
pub use accumulator::Accumulator;
pub use cost::{Cost, CostEstimation};
pub use msm::MSM;

pub fn langranges<C: Curve, T>(
    protocol: &Protocol<C>,
    instances: &[Vec<T>],
) -> impl IntoIterator<Item = i32> {
    protocol
        .relations
        .iter()
        .cloned()
        .sum::<Expression<_>>()
        .used_langrange()
        .into_iter()
        .chain(
            0..instances
                .iter()
                .map(|instance| instance.len())
                .max()
                .unwrap_or_default() as i32,
        )
}
