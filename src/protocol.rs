use crate::util::{Curve, Domain, Expression, Query};

#[cfg(feature = "halo2")]
pub mod halo2;

#[derive(Clone, Debug)]
pub struct Protocol<C: Curve> {
    pub domain: Domain<C::Scalar>,
    pub preprocessed: Vec<C>,
    pub num_statement: usize,
    pub num_auxiliary: Vec<usize>,
    pub num_challenge: Vec<usize>,
    pub evaluations: Vec<Query>,
    pub queries: Vec<Query>,
    pub relations: Vec<Expression<C::Scalar>>,
    pub transcript_initial_state: C::Scalar,
}

impl<C: Curve> Protocol<C> {
    pub fn vanishing_poly(&self) -> usize {
        self.preprocessed.len() + self.num_statement + self.num_auxiliary.iter().sum::<usize>()
    }

    pub fn langranges<T>(&self, statements: &[&[T]]) -> impl IntoIterator<Item = i32> {
        self.relations
            .iter()
            .cloned()
            .sum::<Expression<_>>()
            .used_langrange()
            .into_iter()
            .chain(
                0..statements
                    .iter()
                    .map(|statement| statement.len())
                    .max()
                    .unwrap_or_default() as i32,
            )
    }
}
