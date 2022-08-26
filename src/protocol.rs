use crate::util::{Curve, Domain, Expression, Group, Itertools, Query};

#[cfg(feature = "halo2")]
pub mod halo2;

#[derive(Clone, Debug)]
pub struct Protocol<C: Curve> {
    pub zk: bool,
    pub domain: Domain<C::Scalar>,
    pub preprocessed: Vec<C>,
    pub num_instance: Vec<usize>,
    pub num_witness: Vec<usize>,
    pub num_challenge: Vec<usize>,
    pub evaluations: Vec<Query>,
    pub queries: Vec<Query>,
    pub relations: Vec<Expression<C::Scalar>>,
    pub transcript_initial_state: C::Scalar,
    pub accumulator_indices: Option<Vec<Vec<(usize, usize)>>>,
}

impl<C: Curve> Protocol<C> {
    pub fn vanishing_poly(&self) -> usize {
        self.preprocessed.len() + self.num_instance.len() + self.num_witness.iter().sum::<usize>()
    }
}

pub struct Snark<C: Curve> {
    pub protocol: Protocol<C>,
    pub instances: Vec<Vec<<C as Group>::Scalar>>,
    pub proof: Vec<u8>,
}

impl<C: Curve> Snark<C> {
    pub fn new(
        protocol: Protocol<C>,
        instances: Vec<Vec<<C as Group>::Scalar>>,
        proof: Vec<u8>,
    ) -> Self {
        assert_eq!(
            protocol.num_instance,
            instances
                .iter()
                .map(|instances| instances.len())
                .collect_vec()
        );
        Snark {
            protocol,
            instances,
            proof,
        }
    }
}
