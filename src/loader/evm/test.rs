use crate::{
    loader::evm::{test::tui::Tui, util::ExecutorBuilder},
    util::Itertools,
};
use ethereum_types::{Address, U256};
use revm::{AccountInfo, Bytecode};
use std::env::var_os;

mod tui;

fn debug() -> bool {
    matches!(
        var_os("DEBUG"),
        Some(value) if value.to_str() == Some("1")
    )
}

pub fn execute(code: Vec<u8>, calldata: Vec<u8>) -> (bool, u64, Vec<u64>) {
    assert!(
        code.len() <= 0x6000,
        "Contract size {} exceeds the limit 24576",
        code.len()
    );

    let debug = debug();
    let caller = Address::from_low_u64_be(0xfe);
    let callee = Address::from_low_u64_be(0xff);

    let mut evm = ExecutorBuilder::default()
        .with_gas_limit(u64::MAX.into())
        .set_debugger(debug)
        .build();

    evm.db_mut().insert_account_info(
        callee,
        AccountInfo::new(0.into(), 1, Bytecode::new_raw(code.into())),
    );

    let result = evm.call_raw(caller, callee, calldata.into(), 0.into());

    let costs = result
        .logs
        .into_iter()
        .map(|log| U256::from_big_endian(log.topics[0].as_bytes()).as_u64())
        .collect_vec();

    if debug {
        Tui::new(result.debug.unwrap().flatten(0), 0).start();
    }

    (!result.reverted, result.gas_used, costs)
}
