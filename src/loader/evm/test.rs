use crate::{loader::evm::test::tui::Tui, util::Itertools};
use foundry_evm::{
    executor::{backend::Backend, fork::MultiFork, ExecutorBuilder},
    revm::{AccountInfo, Bytecode},
    utils::h256_to_u256_be,
    Address,
};
use std::env::var_os;

mod tui;

fn small_address(lsb: u8) -> Address {
    let mut address = Address::zero();
    *address.0.last_mut().unwrap() = lsb;
    address
}

fn debug() -> bool {
    matches!(
        var_os("DEBUG"),
        Some(value) if value.to_str() == Some("1")
    )
}

pub fn execute(code: Vec<u8>, calldata: Vec<u8>) -> (bool, u64, Vec<u64>) {
    let debug = debug();
    let caller = small_address(0xfe);
    let callee = small_address(0xff);

    let mut evm = ExecutorBuilder::default()
        .with_gas_limit(u64::MAX.into())
        .set_tracing(debug)
        .set_debugger(debug)
        .build(Backend::new(MultiFork::new().0, None));

    evm.backend_mut().insert_account_info(
        callee,
        AccountInfo::new(0.into(), 1, Bytecode::new_raw(code.into())),
    );

    let result = evm
        .call_raw(caller, callee, calldata.into(), 0.into())
        .unwrap();

    let costs = result
        .logs
        .into_iter()
        .map(|log| h256_to_u256_be(log.topics[0]).as_u64())
        .collect_vec();

    if debug {
        Tui::new(result.debug.unwrap().flatten(0), 0).start();
    }

    (!result.reverted, result.gas, costs)
}
