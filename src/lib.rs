#![feature(int_log)]
#![feature(int_roundings)]
#![feature(assert_matches)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::upper_case_acronyms)]

pub mod cost;
pub mod loader;
pub mod pcs;
pub mod system;
pub mod util;
pub mod verifier;

#[derive(Clone, Debug)]
pub enum Error {
    InvalidInstances,
    InvalidLinearization,
    MissingQuery(util::expression::Query),
    MissingChallenge(usize),
    Transcript(std::io::ErrorKind, String),
}

#[derive(Clone, Debug)]
pub struct Protocol<C: util::arithmetic::CurveAffine> {
    pub zk: bool,
    pub domain: util::arithmetic::Domain<C::Scalar>,
    pub preprocessed: Vec<C>,
    pub num_instance: Vec<usize>,
    pub num_witness: Vec<usize>,
    pub num_challenge: Vec<usize>,
    pub evaluations: Vec<util::expression::Query>,
    pub queries: Vec<util::expression::Query>,
    pub quotient: util::expression::QuotientPolynomial<C::Scalar>,
    pub linearization: Option<util::expression::LinearizationStrategy>,
    pub transcript_initial_state: Option<C::Scalar>,
    pub accumulator_indices: Vec<Vec<(usize, usize)>>,
}
