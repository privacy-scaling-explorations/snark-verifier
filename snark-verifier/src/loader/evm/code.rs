pub enum Precompiled {
    BigModExp = 0x05,
    Bn254Add = 0x6,
    Bn254ScalarMul = 0x7,
    Bn254Pairing = 0x8,
}

#[derive(Clone, Debug)]
pub struct YulCode {
    // runtime code area
    runtime: String,
}

impl YulCode {
    pub fn new() -> Self {
        YulCode {
            runtime: String::new(),
        }
    }

    pub fn code(&self, base_modulus: String, scalar_modulus: String) -> String {
        format!(
            "
        object \"plonk_verifier\" {{
            code {{
                function allocate(size) -> ptr {{
                    ptr := mload(0x40)
                    if eq(ptr, 0) {{ ptr := 0x60 }}
                    mstore(0x40, add(ptr, size))
                }}
                let size := datasize(\"Runtime\")
                let offset := allocate(size)
                datacopy(offset, dataoffset(\"Runtime\"), size)
                return(offset, size)
            }}
            object \"Runtime\" {{
                code {{
                    let success:bool := true
                    let f_p := {base_modulus}
                    let f_q := {scalar_modulus}
                    function validate_ec_point(x, y) -> valid:bool {{
                        {{
                            let x_lt_p:bool := lt(x, {base_modulus})
                            let y_lt_p:bool := lt(y, {base_modulus})
                            valid := and(x_lt_p, y_lt_p)
                        }}
                        {{
                            let x_is_zero:bool := eq(x, 0)
                            let y_is_zero:bool := eq(y, 0)
                            let x_or_y_is_zero:bool := or(x_is_zero, y_is_zero)
                            let x_and_y_is_not_zero:bool := not(x_or_y_is_zero)
                            valid := and(x_and_y_is_not_zero, valid)
                        }}
                        {{
                            let y_square := mulmod(y, y, {base_modulus})
                            let x_square := mulmod(x, x, {base_modulus})
                            let x_cube := mulmod(x_square, x, {base_modulus})
                            let x_cube_plus_3 := addmod(x_cube, 3, {base_modulus})
                            let y_square_eq_x_cube_plus_3:bool := eq(x_cube_plus_3, y_square)
                            valid := and(y_square_eq_x_cube_plus_3, valid)
                        }}
                    }}
                    {}
                }}
            }}
        }}",
            self.runtime
        )
    }

    pub fn runtime_append(&mut self, mut code: String) {
        code.push('\n');
        self.runtime.push_str(&code);
    }
}
