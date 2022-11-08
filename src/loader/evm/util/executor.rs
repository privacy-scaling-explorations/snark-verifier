//! Copied and modified from https://github.com/foundry-rs/foundry/blob/master/evm/src/executor/mod.rs

use bytes::Bytes;
use ethereum_types::{Address, H256, U256, U64};
use revm::{
    evm_inner, opcode, spec_opcode_gas, Account, BlockEnv, CallInputs, CallScheme, CreateInputs,
    CreateScheme, Database, DatabaseCommit, EVMData, Env, ExecutionResult, Gas, GasInspector,
    InMemoryDB, Inspector, Interpreter, Memory, OpCode, Return, TransactOut, TransactTo, TxEnv,
};
use sha3::{Digest, Keccak256};
use std::{cell::RefCell, collections::HashMap, fmt::Display, rc::Rc};

macro_rules! return_ok {
    () => {
        Return::Continue | Return::Stop | Return::Return | Return::SelfDestruct
    };
}

fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
    Keccak256::digest(data.as_ref()).into()
}

fn get_contract_address(sender: impl Into<Address>, nonce: impl Into<U256>) -> Address {
    let mut stream = rlp::RlpStream::new();
    stream.begin_list(2);
    stream.append(&sender.into());
    stream.append(&nonce.into());

    let hash = keccak256(&stream.out());

    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash[12..]);
    Address::from(bytes)
}

fn get_create2_address(
    from: impl Into<Address>,
    salt: [u8; 32],
    init_code: impl Into<Bytes>,
) -> Address {
    get_create2_address_from_hash(from, salt, keccak256(init_code.into().as_ref()).to_vec())
}

fn get_create2_address_from_hash(
    from: impl Into<Address>,
    salt: [u8; 32],
    init_code_hash: impl Into<Bytes>,
) -> Address {
    let bytes = [
        &[0xff],
        from.into().as_bytes(),
        salt.as_slice(),
        init_code_hash.into().as_ref(),
    ]
    .concat();

    let hash = keccak256(&bytes);

    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash[12..]);
    Address::from(bytes)
}

fn get_create_address(call: &CreateInputs, nonce: u64) -> Address {
    match call.scheme {
        CreateScheme::Create => get_contract_address(call.caller, nonce),
        CreateScheme::Create2 { salt } => {
            let mut buffer: [u8; 4 * 8] = [0; 4 * 8];
            salt.to_big_endian(&mut buffer);
            get_create2_address(call.caller, buffer, call.init_code.clone())
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Bytes,
    pub block_hash: Option<H256>,
    pub block_number: Option<U64>,
    pub transaction_hash: Option<H256>,
    pub transaction_index: Option<U64>,
    pub log_index: Option<U256>,
    pub transaction_log_index: Option<U256>,
    pub log_type: Option<String>,
    pub removed: Option<bool>,
}

#[derive(Clone, Debug, Default)]
struct LogCollector {
    logs: Vec<Log>,
}

impl<DB: Database> Inspector<DB> for LogCollector {
    fn log(&mut self, _: &mut EVMData<'_, DB>, address: &Address, topics: &[H256], data: &Bytes) {
        self.logs.push(Log {
            address: *address,
            topics: topics.to_vec(),
            data: data.clone(),
            ..Default::default()
        });
    }

    fn call(
        &mut self,
        _: &mut EVMData<'_, DB>,
        call: &mut CallInputs,
        _: bool,
    ) -> (Return, Gas, Bytes) {
        (Return::Continue, Gas::new(call.gas_limit), Bytes::new())
    }
}

#[derive(Clone, Debug, Copy)]
pub enum CallKind {
    Call,
    StaticCall,
    CallCode,
    DelegateCall,
    Create,
    Create2,
}

impl Default for CallKind {
    fn default() -> Self {
        CallKind::Call
    }
}

impl From<CallScheme> for CallKind {
    fn from(scheme: CallScheme) -> Self {
        match scheme {
            CallScheme::Call => CallKind::Call,
            CallScheme::StaticCall => CallKind::StaticCall,
            CallScheme::CallCode => CallKind::CallCode,
            CallScheme::DelegateCall => CallKind::DelegateCall,
        }
    }
}

impl From<CreateScheme> for CallKind {
    fn from(create: CreateScheme) -> Self {
        match create {
            CreateScheme::Create => CallKind::Create,
            CreateScheme::Create2 { .. } => CallKind::Create2,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DebugArena {
    pub arena: Vec<DebugNode>,
}

impl DebugArena {
    fn push_node(&mut self, mut new_node: DebugNode) -> usize {
        fn recursively_push(
            arena: &mut Vec<DebugNode>,
            entry: usize,
            mut new_node: DebugNode,
        ) -> usize {
            match new_node.depth {
                _ if arena[entry].depth == new_node.depth - 1 => {
                    let id = arena.len();
                    new_node.location = arena[entry].children.len();
                    new_node.parent = Some(entry);
                    arena[entry].children.push(id);
                    arena.push(new_node);
                    id
                }
                _ => {
                    let child = *arena[entry].children.last().unwrap();
                    recursively_push(arena, child, new_node)
                }
            }
        }

        if self.arena.is_empty() {
            self.arena.push(new_node);
            0
        } else if new_node.depth == 0 {
            let id = self.arena.len();
            new_node.location = self.arena[0].children.len();
            new_node.parent = Some(0);
            self.arena[0].children.push(id);
            self.arena.push(new_node);
            id
        } else {
            recursively_push(&mut self.arena, 0, new_node)
        }
    }

    #[cfg(test)]
    pub fn flatten(&self, entry: usize) -> Vec<(Address, Vec<DebugStep>, CallKind)> {
        let node = &self.arena[entry];

        let mut flattened = vec![];
        if !node.steps.is_empty() {
            flattened.push((node.address, node.steps.clone(), node.kind));
        }
        flattened.extend(node.children.iter().flat_map(|child| self.flatten(*child)));

        flattened
    }
}

#[derive(Clone, Debug, Default)]
pub struct DebugNode {
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub location: usize,
    pub address: Address,
    pub kind: CallKind,
    pub depth: usize,
    pub steps: Vec<DebugStep>,
}

#[derive(Clone, Debug)]
pub struct DebugStep {
    pub stack: Vec<U256>,
    pub memory: Memory,
    pub instruction: Instruction,
    pub push_bytes: Option<Vec<u8>>,
    pub pc: usize,
    pub total_gas_used: u64,
}

impl Default for DebugStep {
    fn default() -> Self {
        Self {
            stack: vec![],
            memory: Memory::new(),
            instruction: Instruction(revm::opcode::INVALID),
            push_bytes: None,
            pc: 0,
            total_gas_used: 0,
        }
    }
}

impl DebugStep {
    #[cfg(test)]
    pub fn pretty_opcode(&self) -> String {
        if let Some(push_bytes) = &self.push_bytes {
            format!("{}(0x{})", self.instruction, hex::encode(push_bytes))
        } else {
            self.instruction.to_string()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Instruction(pub u8);

impl From<u8> for Instruction {
    fn from(op: u8) -> Instruction {
        Instruction(op)
    }
}

impl Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            OpCode::try_from_u8(self.0).map_or_else(
                || format!("UNDEFINED(0x{:02x})", self.0),
                |opcode| opcode.as_str().to_string(),
            )
        )
    }
}

#[derive(Clone, Debug)]
struct Debugger {
    arena: DebugArena,
    head: usize,
    context: Address,
    gas_inspector: Rc<RefCell<GasInspector>>,
}

impl Debugger {
    fn new(gas_inspector: Rc<RefCell<GasInspector>>) -> Self {
        Self {
            arena: Default::default(),
            head: Default::default(),
            context: Default::default(),
            gas_inspector,
        }
    }

    fn enter(&mut self, depth: usize, address: Address, kind: CallKind) {
        self.context = address;
        self.head = self.arena.push_node(DebugNode {
            depth,
            address,
            kind,
            ..Default::default()
        });
    }

    fn exit(&mut self) {
        if let Some(parent_id) = self.arena.arena[self.head].parent {
            let DebugNode {
                depth,
                address,
                kind,
                ..
            } = self.arena.arena[parent_id];
            self.context = address;
            self.head = self.arena.push_node(DebugNode {
                depth,
                address,
                kind,
                ..Default::default()
            });
        }
    }
}

impl<DB: Database> Inspector<DB> for Debugger {
    fn step(
        &mut self,
        interpreter: &mut Interpreter,
        data: &mut EVMData<'_, DB>,
        _is_static: bool,
    ) -> Return {
        let pc = interpreter.program_counter();
        let op = interpreter.contract.bytecode.bytecode()[pc];

        let opcode_infos = spec_opcode_gas(data.env.cfg.spec_id);
        let opcode_info = &opcode_infos[op as usize];

        let push_size = if opcode_info.is_push() {
            (op - opcode::PUSH1 + 1) as usize
        } else {
            0
        };
        let push_bytes = match push_size {
            0 => None,
            n => {
                let start = pc + 1;
                let end = start + n;
                Some(interpreter.contract.bytecode.bytecode()[start..end].to_vec())
            }
        };

        let spent = interpreter.gas.limit() - self.gas_inspector.borrow().gas_remaining();
        let total_gas_used = spent - (interpreter.gas.refunded() as u64).min(spent / 5);

        self.arena.arena[self.head].steps.push(DebugStep {
            pc,
            stack: interpreter.stack().data().clone(),
            memory: interpreter.memory.clone(),
            instruction: Instruction(op),
            push_bytes,
            total_gas_used,
        });

        Return::Continue
    }

    fn call(
        &mut self,
        data: &mut EVMData<'_, DB>,
        call: &mut CallInputs,
        _: bool,
    ) -> (Return, Gas, Bytes) {
        self.enter(
            data.journaled_state.depth() as usize,
            call.context.code_address,
            call.context.scheme.into(),
        );

        (Return::Continue, Gas::new(call.gas_limit), Bytes::new())
    }

    fn call_end(
        &mut self,
        _: &mut EVMData<'_, DB>,
        _: &CallInputs,
        gas: Gas,
        status: Return,
        retdata: Bytes,
        _: bool,
    ) -> (Return, Gas, Bytes) {
        self.exit();

        (status, gas, retdata)
    }

    fn create(
        &mut self,
        data: &mut EVMData<'_, DB>,
        call: &mut CreateInputs,
    ) -> (Return, Option<Address>, Gas, Bytes) {
        let nonce = data.journaled_state.account(call.caller).info.nonce;
        self.enter(
            data.journaled_state.depth() as usize,
            get_create_address(call, nonce),
            CallKind::Create,
        );

        (
            Return::Continue,
            None,
            Gas::new(call.gas_limit),
            Bytes::new(),
        )
    }

    fn create_end(
        &mut self,
        _: &mut EVMData<'_, DB>,
        _: &CreateInputs,
        status: Return,
        address: Option<Address>,
        gas: Gas,
        retdata: Bytes,
    ) -> (Return, Option<Address>, Gas, Bytes) {
        self.exit();

        (status, address, gas, retdata)
    }
}

#[macro_export]
macro_rules! call_inspectors {
    ($id:ident, [ $($inspector:expr),+ ], $call:block) => {
        $({
            if let Some($id) = $inspector {
                $call;
            }
        })+
    }
}

struct InspectorData {
    logs: Vec<Log>,
    debug: Option<DebugArena>,
}

#[derive(Default)]
struct InspectorStack {
    gas: Option<Rc<RefCell<GasInspector>>>,
    logs: Option<LogCollector>,
    debugger: Option<Debugger>,
}

impl InspectorStack {
    fn collect_inspector_states(self) -> InspectorData {
        InspectorData {
            logs: self.logs.map(|logs| logs.logs).unwrap_or_default(),
            debug: self.debugger.map(|debugger| debugger.arena),
        }
    }
}

impl<DB: Database> Inspector<DB> for InspectorStack {
    fn initialize_interp(
        &mut self,
        interpreter: &mut Interpreter,
        data: &mut EVMData<'_, DB>,
        is_static: bool,
    ) -> Return {
        call_inspectors!(
            inspector,
            [
                &mut self.gas.as_deref().map(|gas| gas.borrow_mut()),
                &mut self.logs,
                &mut self.debugger
            ],
            {
                let status = inspector.initialize_interp(interpreter, data, is_static);

                if status != Return::Continue {
                    return status;
                }
            }
        );

        Return::Continue
    }

    fn step(
        &mut self,
        interpreter: &mut Interpreter,
        data: &mut EVMData<'_, DB>,
        is_static: bool,
    ) -> Return {
        call_inspectors!(
            inspector,
            [
                &mut self.gas.as_deref().map(|gas| gas.borrow_mut()),
                &mut self.logs,
                &mut self.debugger
            ],
            {
                let status = inspector.step(interpreter, data, is_static);

                if status != Return::Continue {
                    return status;
                }
            }
        );

        Return::Continue
    }

    fn log(
        &mut self,
        evm_data: &mut EVMData<'_, DB>,
        address: &Address,
        topics: &[H256],
        data: &Bytes,
    ) {
        call_inspectors!(inspector, [&mut self.logs], {
            inspector.log(evm_data, address, topics, data);
        });
    }

    fn step_end(
        &mut self,
        interpreter: &mut Interpreter,
        data: &mut EVMData<'_, DB>,
        is_static: bool,
        status: Return,
    ) -> Return {
        call_inspectors!(
            inspector,
            [
                &mut self.gas.as_deref().map(|gas| gas.borrow_mut()),
                &mut self.logs,
                &mut self.debugger
            ],
            {
                let status = inspector.step_end(interpreter, data, is_static, status);

                if status != Return::Continue {
                    return status;
                }
            }
        );

        Return::Continue
    }

    fn call(
        &mut self,
        data: &mut EVMData<'_, DB>,
        call: &mut CallInputs,
        is_static: bool,
    ) -> (Return, Gas, Bytes) {
        call_inspectors!(
            inspector,
            [
                &mut self.gas.as_deref().map(|gas| gas.borrow_mut()),
                &mut self.logs,
                &mut self.debugger
            ],
            {
                let (status, gas, retdata) = inspector.call(data, call, is_static);

                if status != Return::Continue {
                    return (status, gas, retdata);
                }
            }
        );

        (Return::Continue, Gas::new(call.gas_limit), Bytes::new())
    }

    fn call_end(
        &mut self,
        data: &mut EVMData<'_, DB>,
        call: &CallInputs,
        remaining_gas: Gas,
        status: Return,
        retdata: Bytes,
        is_static: bool,
    ) -> (Return, Gas, Bytes) {
        call_inspectors!(
            inspector,
            [
                &mut self.gas.as_deref().map(|gas| gas.borrow_mut()),
                &mut self.logs,
                &mut self.debugger
            ],
            {
                let (new_status, new_gas, new_retdata) = inspector.call_end(
                    data,
                    call,
                    remaining_gas,
                    status,
                    retdata.clone(),
                    is_static,
                );

                if new_status != status || (new_status == Return::Revert && new_retdata != retdata)
                {
                    return (new_status, new_gas, new_retdata);
                }
            }
        );

        (status, remaining_gas, retdata)
    }

    fn create(
        &mut self,
        data: &mut EVMData<'_, DB>,
        call: &mut CreateInputs,
    ) -> (Return, Option<Address>, Gas, Bytes) {
        call_inspectors!(
            inspector,
            [
                &mut self.gas.as_deref().map(|gas| gas.borrow_mut()),
                &mut self.logs,
                &mut self.debugger
            ],
            {
                let (status, addr, gas, retdata) = inspector.create(data, call);

                if status != Return::Continue {
                    return (status, addr, gas, retdata);
                }
            }
        );

        (
            Return::Continue,
            None,
            Gas::new(call.gas_limit),
            Bytes::new(),
        )
    }

    fn create_end(
        &mut self,
        data: &mut EVMData<'_, DB>,
        call: &CreateInputs,
        status: Return,
        address: Option<Address>,
        remaining_gas: Gas,
        retdata: Bytes,
    ) -> (Return, Option<Address>, Gas, Bytes) {
        call_inspectors!(
            inspector,
            [
                &mut self.gas.as_deref().map(|gas| gas.borrow_mut()),
                &mut self.logs,
                &mut self.debugger
            ],
            {
                let (new_status, new_address, new_gas, new_retdata) = inspector.create_end(
                    data,
                    call,
                    status,
                    address,
                    remaining_gas,
                    retdata.clone(),
                );

                if new_status != status {
                    return (new_status, new_address, new_gas, new_retdata);
                }
            }
        );

        (status, address, remaining_gas, retdata)
    }

    fn selfdestruct(&mut self) {
        call_inspectors!(inspector, [&mut self.logs, &mut self.debugger], {
            Inspector::<DB>::selfdestruct(inspector);
        });
    }
}

pub struct RawCallResult {
    pub exit_reason: Return,
    pub reverted: bool,
    pub result: Bytes,
    pub gas_used: u64,
    pub gas_refunded: u64,
    pub logs: Vec<Log>,
    pub debug: Option<DebugArena>,
    pub state_changeset: Option<HashMap<Address, Account>>,
    pub env: Env,
    pub out: TransactOut,
}

#[derive(Clone, Debug)]
pub struct DeployResult {
    pub exit_reason: Return,
    pub reverted: bool,
    pub address: Option<Address>,
    pub gas_used: u64,
    pub gas_refunded: u64,
    pub logs: Vec<Log>,
    pub debug: Option<DebugArena>,
    pub env: Env,
}

#[derive(Debug, Default)]
pub struct ExecutorBuilder {
    debugger: bool,
    gas_limit: Option<U256>,
}

impl ExecutorBuilder {
    pub fn set_debugger(mut self, enable: bool) -> Self {
        self.debugger = enable;
        self
    }

    pub fn with_gas_limit(mut self, gas_limit: U256) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    pub fn build(self) -> Executor {
        Executor::new(self.debugger, self.gas_limit.unwrap_or(U256::MAX))
    }
}

#[derive(Clone, Debug)]
pub struct Executor {
    db: InMemoryDB,
    debugger: bool,
    gas_limit: U256,
}

impl Executor {
    fn new(debugger: bool, gas_limit: U256) -> Self {
        Executor {
            db: InMemoryDB::default(),
            debugger,
            gas_limit,
        }
    }

    pub fn db_mut(&mut self) -> &mut InMemoryDB {
        &mut self.db
    }

    pub fn deploy(&mut self, from: Address, code: Bytes, value: U256) -> DeployResult {
        let env = self.build_test_env(from, TransactTo::Create(CreateScheme::Create), code, value);
        let result = self.call_raw_with_env(env);
        self.commit(&result);

        let RawCallResult {
            exit_reason,
            out,
            gas_used,
            gas_refunded,
            logs,
            debug,
            env,
            ..
        } = result;

        let address = match (exit_reason, out) {
            (return_ok!(), TransactOut::Create(_, Some(address))) => Some(address),
            _ => None,
        };

        DeployResult {
            exit_reason,
            reverted: !matches!(exit_reason, return_ok!()),
            address,
            gas_used,
            gas_refunded,
            logs,
            debug,
            env,
        }
    }

    pub fn call_raw(
        &self,
        from: Address,
        to: Address,
        calldata: Bytes,
        value: U256,
    ) -> RawCallResult {
        let env = self.build_test_env(from, TransactTo::Call(to), calldata, value);
        self.call_raw_with_env(env)
    }

    fn call_raw_with_env(&self, mut env: Env) -> RawCallResult {
        let mut inspector = self.inspector();
        let result =
            evm_inner::<_, true>(&mut env, &mut self.db.clone(), &mut inspector).transact();
        let (exec_result, state_changeset) = result;
        let ExecutionResult {
            exit_reason,
            gas_refunded,
            gas_used,
            out,
            ..
        } = exec_result;

        let result = match out {
            TransactOut::Call(ref data) => data.to_owned(),
            _ => Bytes::default(),
        };
        let InspectorData { logs, debug } = inspector.collect_inspector_states();

        RawCallResult {
            exit_reason,
            reverted: !matches!(exit_reason, return_ok!()),
            result,
            gas_used,
            gas_refunded,
            logs: logs.to_vec(),
            debug,
            state_changeset: Some(state_changeset.into_iter().collect()),
            env,
            out,
        }
    }

    fn commit(&mut self, result: &RawCallResult) {
        if let Some(state_changeset) = result.state_changeset.as_ref() {
            self.db
                .commit(state_changeset.clone().into_iter().collect());
        }
    }

    fn inspector(&self) -> InspectorStack {
        let mut stack = InspectorStack {
            logs: Some(LogCollector::default()),
            ..Default::default()
        };
        if self.debugger {
            let gas_inspector = Rc::new(RefCell::new(GasInspector::default()));
            stack.gas = Some(gas_inspector.clone());
            stack.debugger = Some(Debugger::new(gas_inspector));
        }
        stack
    }

    fn build_test_env(
        &self,
        caller: Address,
        transact_to: TransactTo,
        data: Bytes,
        value: U256,
    ) -> Env {
        Env {
            block: BlockEnv {
                gas_limit: self.gas_limit,
                ..BlockEnv::default()
            },
            tx: TxEnv {
                caller,
                transact_to,
                data,
                value,
                gas_limit: self.gas_limit.as_u64(),
                ..TxEnv::default()
            },
            ..Env::default()
        }
    }
}
