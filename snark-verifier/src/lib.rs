//! Generic (S)NARK verifier.

#![allow(
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::upper_case_acronyms
)]
#![deny(missing_debug_implementations, missing_docs, unsafe_code, rustdoc::all)]

pub mod cost;
pub mod loader;
pub mod pcs;
pub mod system;
pub mod util;
pub mod verifier;

/// Error that could happen while verification.
#[derive(Clone, Debug)]
pub enum Error {
    /// Instances that don't match the amount specified in protocol.
    InvalidInstances,
    /// Protocol that is unreasonable for a verifier.
    InvalidProtocol(String),
    /// Assertion failure while verification.
    AssertionFailure(String),
    /// Transcript error.
    Transcript(std::io::ErrorKind, String),
}
