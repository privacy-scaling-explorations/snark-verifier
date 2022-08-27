use crate::util::Itertools;
use ethereum_types::U256;
use std::{collections::HashMap, iter};

pub enum Precompiled {
    BigModExp = 0x05,
    Bn254Add = 0x6,
    Bn254ScalarMul = 0x7,
    Bn254Pairing = 0x8,
}

#[derive(Clone, Debug)]
pub struct Code {
    code: Vec<u8>,
    constants: HashMap<U256, usize>,
    stack_len: usize,
}

impl Code {
    pub fn new(constants: impl IntoIterator<Item = U256>) -> Self {
        let mut code = Self {
            code: Vec::new(),
            constants: HashMap::new(),
            stack_len: 0,
        };
        let constants = constants.into_iter().collect_vec();
        for constant in constants.iter() {
            code.push(*constant);
        }
        code.constants = HashMap::from_iter(
            constants
                .into_iter()
                .enumerate()
                .map(|(idx, value)| (value, idx)),
        );
        code
    }

    pub fn deployment(code: Vec<u8>) -> Vec<u8> {
        let code_len = code.len();
        assert_ne!(code_len, 0);

        iter::empty()
            .chain([
                PUSH1 + 1,
                (code_len >> 8) as u8,
                (code_len & 0xff) as u8,
                PUSH1,
                14,
                PUSH1,
                0,
                CODECOPY,
            ])
            .chain([
                PUSH1 + 1,
                (code_len >> 8) as u8,
                (code_len & 0xff) as u8,
                PUSH1,
                0,
                RETURN,
            ])
            .chain(code)
            .collect()
    }

    pub fn stack_len(&self) -> usize {
        self.stack_len
    }

    pub fn len(&self) -> usize {
        self.code.len()
    }

    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }

    pub fn push<T: Into<U256>>(&mut self, value: T) -> &mut Self {
        let value = value.into();
        match self.constants.get(&value) {
            Some(idx) if (0..16).contains(&(self.stack_len - idx - 1)) => {
                self.dup(self.stack_len - idx - 1);
            }
            _ => {
                let mut bytes = vec![0; 32];
                value.to_big_endian(&mut bytes);
                let bytes = bytes
                    .iter()
                    .position(|byte| *byte != 0)
                    .map_or(vec![0], |pos| bytes.drain(pos..).collect());
                self.code.push(PUSH1 - 1 + bytes.len() as u8);
                self.code.extend(bytes);
                self.stack_len += 1;
            }
        }
        self
    }

    pub fn dup(&mut self, pos: usize) -> &mut Self {
        assert!((0..16).contains(&pos));
        self.code.push(DUP1 + pos as u8);
        self.stack_len += 1;
        self
    }

    pub fn swap(&mut self, pos: usize) -> &mut Self {
        assert!((1..17).contains(&pos));
        self.code.push(SWAP1 - 1 + pos as u8);
        self
    }
}

impl From<Code> for Vec<u8> {
    fn from(code: Code) -> Self {
        code.code
    }
}

macro_rules! impl_opcodes {
    ($($method:ident -> ($opcode:ident, $stack_len_diff:expr))*) => {
        $(
            #[allow(dead_code)]
            impl Code {
                pub fn $method(&mut self) -> &mut Self {
                    self.code.push($opcode);
                    self.stack_len = ((self.stack_len as isize) + $stack_len_diff) as usize;
                    self
                }
            }
        )*
    };
}

impl_opcodes!(
    stop -> (STOP, 0)
    add -> (ADD, -1)
    mul -> (MUL, -1)
    sub -> (SUB, -1)
    div -> (DIV, -1)
    sdiv -> (SDIV, -1)
    r#mod -> (MOD, -1)
    smod -> (SMOD, -1)
    addmod -> (ADDMOD, -2)
    mulmod -> (MULMOD, -2)
    exp -> (EXP, -1)
    signextend -> (SIGNEXTEND, -1)
    lt -> (LT, -1)
    gt -> (GT, -1)
    slt -> (SLT, -1)
    sgt -> (SGT, -1)
    eq -> (EQ, -1)
    iszero -> (ISZERO, 0)
    and -> (AND, -1)
    or -> (OR, -1)
    xor -> (XOR, -1)
    not -> (NOT, 0)
    byte -> (BYTE, -1)
    shl -> (SHL, -1)
    shr -> (SHR, -1)
    sar -> (SAR, -1)
    keccak256 -> (SHA3, -1)
    address -> (ADDRESS, 1)
    balance -> (BALANCE, 0)
    origin -> (ORIGIN, 1)
    caller -> (CALLER, 1)
    callvalue -> (CALLVALUE, 1)
    calldataload -> (CALLDATALOAD, 0)
    calldatasize -> (CALLDATASIZE, 1)
    calldatacopy -> (CALLDATACOPY, -3)
    codesize -> (CODESIZE, 1)
    codecopy -> (CODECOPY, -3)
    gasprice -> (GASPRICE, 1)
    extcodesize -> (EXTCODESIZE, 0)
    extcodecopy -> (EXTCODECOPY, -4)
    returndatasize -> (RETURNDATASIZE, 1)
    returndatacopy -> (RETURNDATACOPY, -3)
    extcodehash -> (EXTCODEHASH, 0)
    blockhash -> (BLOCKHASH, 0)
    coinbase -> (COINBASE, 1)
    timestamp -> (TIMESTAMP, 1)
    number -> (NUMBER, 1)
    difficulty -> (DIFFICULTY, 1)
    gaslimit -> (GASLIMIT, 1)
    chainid -> (CHAINID, 1)
    selfbalance -> (SELFBALANCE, 1)
    basefee -> (BASEFEE, 1)
    pop -> (POP, -1)
    mload -> (MLOAD, 0)
    mstore -> (MSTORE, -2)
    mstore8 -> (MSTORE8, -2)
    sload -> (SLOAD, 0)
    sstore -> (SSTORE, -2)
    jump -> (JUMP, -1)
    jumpi -> (JUMPI, -2)
    pc -> (PC, 1)
    msize -> (MSIZE, 1)
    gas -> (GAS, 1)
    jumpdest -> (JUMPDEST, 0)
    log0 -> (LOG0, -2)
    log1 -> (LOG1, -3)
    log2 -> (LOG2, -4)
    log3 -> (LOG3, -5)
    log4 -> (LOG4, -6)
    create -> (CREATE, -2)
    call -> (CALL, -6)
    callcode -> (CALLCODE, -6)
    r#return -> (RETURN, -2)
    delegatecall -> (DELEGATECALL, -5)
    create2 -> (CREATE2, -3)
    staticcall -> (STATICCALL, -5)
    revert -> (REVERT, -2)
    selfdestruct -> (SELFDESTRUCT, -1)
);

const STOP: u8 = 0x00;
const ADD: u8 = 0x01;
const MUL: u8 = 0x02;
const SUB: u8 = 0x03;
const DIV: u8 = 0x04;
const SDIV: u8 = 0x05;
const MOD: u8 = 0x06;
const SMOD: u8 = 0x07;
const ADDMOD: u8 = 0x08;
const MULMOD: u8 = 0x09;
const EXP: u8 = 0x0A;
const SIGNEXTEND: u8 = 0x0B;
const LT: u8 = 0x10;
const GT: u8 = 0x11;
const SLT: u8 = 0x12;
const SGT: u8 = 0x13;
const EQ: u8 = 0x14;
const ISZERO: u8 = 0x15;
const AND: u8 = 0x16;
const OR: u8 = 0x17;
const XOR: u8 = 0x18;
const NOT: u8 = 0x19;
const BYTE: u8 = 0x1A;
const SHL: u8 = 0x1B;
const SHR: u8 = 0x1C;
const SAR: u8 = 0x1D;
const SHA3: u8 = 0x20;
const ADDRESS: u8 = 0x30;
const BALANCE: u8 = 0x31;
const ORIGIN: u8 = 0x32;
const CALLER: u8 = 0x33;
const CALLVALUE: u8 = 0x34;
const CALLDATALOAD: u8 = 0x35;
const CALLDATASIZE: u8 = 0x36;
const CALLDATACOPY: u8 = 0x37;
const CODESIZE: u8 = 0x38;
const CODECOPY: u8 = 0x39;
const GASPRICE: u8 = 0x3A;
const EXTCODESIZE: u8 = 0x3B;
const EXTCODECOPY: u8 = 0x3C;
const RETURNDATASIZE: u8 = 0x3D;
const RETURNDATACOPY: u8 = 0x3E;
const EXTCODEHASH: u8 = 0x3F;
const BLOCKHASH: u8 = 0x40;
const COINBASE: u8 = 0x41;
const TIMESTAMP: u8 = 0x42;
const NUMBER: u8 = 0x43;
const DIFFICULTY: u8 = 0x44;
const GASLIMIT: u8 = 0x45;
const CHAINID: u8 = 0x46;
const SELFBALANCE: u8 = 0x47;
const BASEFEE: u8 = 0x48;
const POP: u8 = 0x50;
const MLOAD: u8 = 0x51;
const MSTORE: u8 = 0x52;
const MSTORE8: u8 = 0x53;
const SLOAD: u8 = 0x54;
const SSTORE: u8 = 0x55;
const JUMP: u8 = 0x56;
const JUMPI: u8 = 0x57;
const PC: u8 = 0x58;
const MSIZE: u8 = 0x59;
const GAS: u8 = 0x5A;
const JUMPDEST: u8 = 0x5B;
const PUSH1: u8 = 0x60;
const DUP1: u8 = 0x80;
const SWAP1: u8 = 0x90;
const LOG0: u8 = 0xA0;
const LOG1: u8 = 0xA1;
const LOG2: u8 = 0xA2;
const LOG3: u8 = 0xA3;
const LOG4: u8 = 0xA4;
const CREATE: u8 = 0xF0;
const CALL: u8 = 0xF1;
const CALLCODE: u8 = 0xF2;
const RETURN: u8 = 0xF3;
const DELEGATECALL: u8 = 0xF4;
const CREATE2: u8 = 0xF5;
const STATICCALL: u8 = 0xFA;
const REVERT: u8 = 0xFD;
const SELFDESTRUCT: u8 = 0xFF;
