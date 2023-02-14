//! Hash algorithms.

#[cfg(feature = "loader_halo2")]
mod poseidon;

#[cfg(feature = "loader_halo2")]
pub use crate::util::hash::poseidon::Poseidon;

#[cfg(feature = "loader_evm")]
pub use sha3::{Digest, Keccak256};
