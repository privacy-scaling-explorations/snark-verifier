#[cfg(test)]
mod tui;

#[cfg(test)]
mod test {
    use super::tui::Tui;
    use foundry_evm::{
        executor::{builder::Backend, ExecutorBuilder},
        revm::AccountInfo,
        Address,
    };
    use std::env::var_os;

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

    fn run(code: Vec<u8>, calldata: Vec<u8>) -> (bool, u64) {
        let debug = debug();
        let caller = small_address(0xfe);
        let callee = small_address(0xff);

        let mut builder = ExecutorBuilder::new().with_gas_limit(u64::MAX.into());

        if debug {
            builder = builder.with_tracing().with_debugger();
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

    #[test]
    fn test_evm_loader() {
        run(vec![0x60, 0x01, 0x60, 0x01, 0x01, 0x00], Vec::new());
    }
}
