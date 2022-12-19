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
    InvalidProtocol(String),
    AssertionFailure(String),
    Transcript(std::io::ErrorKind, String),
}
