mod code;
pub(crate) mod loader;
mod util;

#[cfg(test)]
mod test;

pub use loader::{EcPoint, EvmLoader, Scalar};
pub use util::{
    compile_yul, encode_calldata, estimate_gas, fe_to_u256, modulus, u256_to_fe, Address,
    ExecutorBuilder, MemoryChunk, H256, U256, U512,
};

#[cfg(test)]
pub use test::execute;
