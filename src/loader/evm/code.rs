use ethereum_types::U256;
use foundry_evm::{revm::opcode::*, HashMap};

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
        let constants = constants.into_iter().collect::<Vec<_>>();
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
