pub enum Precompiled {
    BigModExp = 0x05,
    Bn254Add = 0x6,
    Bn254ScalarMul = 0x7,
    Bn254Pairing = 0x8,
}

#[derive(Clone, Debug)]
pub struct SolidityAssemblyCode {
    // runtime code area
    runtime: String,
}

impl SolidityAssemblyCode {
    pub fn new() -> Self {
        Self {
            runtime: String::new(),
        }
    }

    pub fn code(&self, base_modulus: String, scalar_modulus: String) -> String {
        format!(
            "
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {{
    fallback(bytes calldata) external returns (bytes memory) {{
        assembly (\"memory-safe\") {{
            // Enforce that Solidity memory layout is respected
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {{
                revert(0, 0)
            }}

            let success := true
            let f_p := {base_modulus}
            let f_q := {scalar_modulus}
            function validate_ec_point(x, y) -> valid {{
                {{
                    let x_lt_p := lt(x, {base_modulus})
                    let y_lt_p := lt(y, {base_modulus})
                    valid := and(x_lt_p, y_lt_p)
                }}
                {{
                    let y_square := mulmod(y, y, {base_modulus})
                    let x_square := mulmod(x, x, {base_modulus})
                    let x_cube := mulmod(x_square, x, {base_modulus})
                    let x_cube_plus_3 := addmod(x_cube, 3, {base_modulus})
                    let is_affine := eq(x_cube_plus_3, y_square)
                    valid := and(valid, is_affine)
                }}
            }}
            {}
        }}
    }}
}}
        ",
            self.runtime
        )
    }

    pub fn runtime_append(&mut self, mut code: String) {
        code.push('\n');
        self.runtime.push_str(&code);
    }
}
