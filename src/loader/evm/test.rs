use crate::loader::evm::test::tui::Tui;
use foundry_evm::{
    executor::{builder::Backend, ExecutorBuilder},
    revm::AccountInfo,
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

pub fn execute(code: Vec<u8>, calldata: Vec<u8>) -> (bool, u64) {
    let debug = debug();
    let caller = small_address(0xfe);
    let callee = small_address(0xff);

    let mut builder = ExecutorBuilder::default().with_gas_limit(u64::MAX.into());

    if debug {
        builder = builder.set_tracing(true).set_debugger(true);
    }

    let mut evm = builder.build(Backend::simple());

    evm.db
        .insert_cache(callee, AccountInfo::new(0.into(), 1, code.into()));

    let result = evm
        .call_raw(caller, callee, calldata.into(), 0.into())
        .unwrap();

    if debug {
        Tui::new(result.debug.unwrap().flatten(0), 0).start();
    }

    (!result.reverted, result.gas)
}
