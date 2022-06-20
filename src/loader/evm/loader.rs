use crate::{
    hex,
    loader::evm::{Code, Precompiled},
    loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, ScalarLoader},
    util::{Curve, FieldOps, PrimeField, UncompressedEncoding},
};
use ethereum_types::{U256, U512};
use std::{
    borrow::Borrow,
    cell::RefCell,
    fmt::Debug,
    iter,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    rc::Rc,
};

pub fn modulus<F: PrimeField<Repr = [u8; 32]>>() -> U256 {
    U256::from_little_endian((-F::one()).to_repr().as_ref()) + 1
}

#[derive(Clone)]
pub struct Pointer<const SIZE: usize> {
    loader: Rc<EvmLoader>,
    memory_address: Option<usize>,
}

impl<const SIZE: usize> Pointer<SIZE> {
    pub const fn is_null(&self) -> bool {
        self.memory_address.is_none()
    }

    pub fn memory_address(&self) -> usize {
        self.memory_address.unwrap()
    }
}

impl<const SIZE: usize> Debug for Pointer<SIZE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pointer")
            .field("size", &SIZE)
            .field(
                "memory_address",
                &hex!(self.memory_address.unwrap_or_default().to_be_bytes()),
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct EvmLoader {
    base_modulus: U256,
    scalar_modulus: U256,
    code: RefCell<Code>,
    cd_offset: RefCell<usize>,
    memory_offset: RefCell<usize>,
}

impl EvmLoader {
    pub fn new<Fq, Fr>() -> Rc<Self>
    where
        Fq: PrimeField<Repr = [u8; 32]>,
        Fr: PrimeField<Repr = [u8; 32]>,
    {
        let base_modulus = modulus::<Fq>();
        let scalar_modulus = modulus::<Fr>();
        let code = Code::new([1.into(), base_modulus, scalar_modulus - 1, scalar_modulus])
            .push(1)
            .to_owned();
        Rc::new(Self {
            base_modulus,
            scalar_modulus,
            code: RefCell::new(code),
            cd_offset: RefCell::new(0),
            memory_offset: RefCell::new(0),
        })
    }

    pub fn code(self: &Rc<Self>) -> Vec<u8> {
        let mut code = self.code.borrow().clone();
        let dst = code.len() + 9;
        code.push(dst)
            .jumpi()
            .push(0)
            .push(0)
            .revert()
            .jumpdest()
            .stop()
            .to_owned()
            .into()
    }

    pub fn null_ptr<const SIZE: usize>(self: &Rc<Self>) -> Pointer<SIZE> {
        Pointer {
            loader: self.clone(),
            memory_address: None,
        }
    }

    fn ptr<const SIZE: usize>(self: &Rc<Self>, memory_address: usize) -> Pointer<SIZE> {
        Pointer {
            loader: self.clone(),
            memory_address: Some(memory_address),
        }
    }

    pub fn allocate<const SIZE: usize>(self: &Rc<Self>) -> Pointer<SIZE> {
        let memory_address = *self.memory_offset.borrow();
        *self.memory_offset.borrow_mut() += SIZE;
        self.ptr(memory_address)
    }

    fn push(self: &Rc<Self>, value: &Scalar) {
        if let Some(constant) = value.constant {
            self.code.borrow_mut().push(constant);
        } else {
            assert!(!value.ptr.is_null());
            self.code.borrow_mut().push(value.memory_address()).mload();
        }
    }

    pub fn calldataload_scalar(self: &Rc<Self>) -> Scalar {
        let cd_offset = *self.cd_offset.borrow();
        *self.cd_offset.borrow_mut() += 0x20;
        let ptr = self.allocate();
        self.code
            .borrow_mut()
            .push(self.scalar_modulus)
            .push(cd_offset)
            .calldataload()
            .r#mod()
            .push(ptr.memory_address())
            .mstore();
        Scalar::variable(ptr)
    }

    pub fn calldataload_ec_point(self: &Rc<Self>) -> EcPoint {
        let cd_offset = *self.cd_offset.borrow();
        *self.cd_offset.borrow_mut() += 0x40;
        let ptr = self.allocate();
        self.code
            .borrow_mut()
            // [..., success]
            .push(cd_offset)
            // [..., success, x_cd_ptr]
            .calldataload()
            // [..., success, x]
            .dup(0)
            // [..., success, x, x]
            .push(ptr.memory_address())
            // [..., success, x, x, x_ptr]
            .mstore()
            // [..., success, x]
            .push(cd_offset + 0x20)
            // [..., success, x, y_cd_ptr]
            .calldataload()
            // [..., success, x, y]
            .dup(0)
            // [..., success, x, y, y]
            .push(ptr.memory_address() + 0x20)
            // [..., success, x, y, y, y_ptr]
            .mstore()
            // [..., success, x, y]
            .push(self.base_modulus)
            // [..., success, x, y, p]
            .dup(2)
            // [..., success, x, y, p, x]
            .lt()
            // [..., success, x, y, x_lt_p]
            .push(self.base_modulus)
            // [..., success, x, y, x_lt_p, p]
            .dup(2)
            // [..., success, x, y, x_lt_p, p, y]
            .lt()
            // [..., success, x, y, x_lt_p, y_lt_p]
            .and()
            // [..., success, x, y, valid]
            .dup(2)
            // [..., success, x, y, valid, x]
            .iszero()
            // [..., success, x, y, valid, x_is_zero]
            .dup(2)
            // [..., success, x, y, valid, x_is_zero, y]
            .iszero()
            // [..., success, x, y, valid, x_is_zero, y_is_zero]
            .or()
            // [..., success, x, y, valid, x_or_y_is_zero]
            .not()
            // [..., success, x, y, valid, x_and_y_is_not_zero]
            .and()
            // [..., success, x, y, valid]
            .push(self.base_modulus)
            // [..., success, x, y, valid, p]
            .dup(2)
            // [..., success, x, y, valid, p, y]
            .dup(0)
            // [..., success, x, y, valid, p, y, y]
            .mulmod()
            // [..., success, x, y, valid, y_square]
            .push(self.base_modulus)
            // [..., success, x, y, valid, y_square, p]
            .push(3)
            // [..., success, x, y, valid, y_square, p, 3]
            .push(self.base_modulus)
            // [..., success, x, y, valid, y_square, p, 3, p]
            .dup(6)
            // [..., success, x, y, valid, y_square, p, 3, p, x]
            .push(self.base_modulus)
            // [..., success, x, y, valid, y_square, p, 3, p, x, p]
            .dup(1)
            // [..., success, x, y, valid, y_square, p, 3, p, x, p, x]
            .dup(0)
            // [..., success, x, y, valid, y_square, p, 3, p, x, p, x, x]
            .mulmod()
            // [..., success, x, y, valid, y_square, p, 3, p, x, x_square]
            .mulmod()
            // [..., success, x, y, valid, y_square, p, 3, x_cube]
            .addmod()
            // [..., success, x, y, valid, y_square, x_cube_plus_3]
            .eq()
            // [..., success, x, y, valid, y_square_eq_x_cube_plus_3]
            .and()
            // [..., success, x, y, valid]
            .swap(2)
            // [..., success, valid, y, x]
            .pop()
            // [..., success, valid, y]
            .pop()
            // [..., success, valid]
            .and();
        EcPoint::variable(ptr)
    }

    pub fn squeeze_challenge(
        self: &Rc<Self>,
        ptr: &mut Pointer<0x20>,
        mut length: usize,
    ) -> Scalar {
        let challenge_ptr = self.allocate();
        let hash_ptr = self.allocate::<32>();

        if length == 0x20 {
            self.code
                .borrow_mut()
                .push(1)
                .push(ptr.memory_address() + 0x20)
                .mstore8();
            length += 1;
        }

        self.code
            .borrow_mut()
            .push(self.scalar_modulus)
            .push(length)
            .push(ptr.memory_address())
            .keccak256()
            .dup(0)
            .push(hash_ptr.memory_address())
            .mstore()
            .r#mod()
            .push(challenge_ptr.memory_address())
            .mstore();

        *ptr = hash_ptr;
        Scalar::variable(challenge_ptr)
    }

    pub fn copy_scalar(self: &Rc<Self>, value: &Scalar, ptr: &Pointer<0x20>) {
        match (value.constant, value.ptr.memory_address) {
            (Some(constant), None) => {
                self.code
                    .borrow_mut()
                    .push(constant)
                    .push(ptr.memory_address())
                    .mstore();
            }
            (None, Some(memory_address)) => {
                self.code
                    .borrow_mut()
                    .push(memory_address)
                    .mload()
                    .push(ptr.memory_address())
                    .mstore();
            }
            _ => unreachable!(),
        }
    }

    pub fn dup_scalar(self: &Rc<Self>, value: &Scalar) -> Scalar {
        let ptr = self.allocate();
        match (value.constant, value.ptr.memory_address) {
            (Some(constant), None) => {
                self.code
                    .borrow_mut()
                    .push(constant)
                    .push(ptr.memory_address())
                    .mstore();
            }
            (None, Some(memory_address)) => {
                self.code
                    .borrow_mut()
                    .push(memory_address)
                    .mload()
                    .push(ptr.memory_address())
                    .mstore();
            }
            _ => unreachable!(),
        }
        Scalar::variable(ptr)
    }

    fn dup_ec_point(self: &Rc<Self>, value: &EcPoint) -> EcPoint {
        let ptr = self.allocate();
        match (value.constant, value.ptr.memory_address) {
            (Some((x, y)), None) => {
                self.code
                    .borrow_mut()
                    .push(x)
                    .push(ptr.memory_address())
                    .mstore()
                    .push(y)
                    .push(ptr.memory_address() + 0x20)
                    .mstore();
            }
            (None, Some(memory_address)) => {
                self.code
                    .borrow_mut()
                    .push(memory_address)
                    .mload()
                    .push(ptr.memory_address())
                    .mstore()
                    .push(memory_address + 0x20)
                    .mload()
                    .push(ptr.memory_address() + 0x20)
                    .mstore();
            }
            _ => unreachable!(),
        }
        EcPoint::variable(ptr)
    }

    fn staticcall(self: &Rc<Self>, precompile: Precompiled, cd_offset: usize, rd_offset: usize) {
        let (cd_length, rd_length) = match precompile {
            Precompiled::BigModExp => (0xc0, 0x20),
            Precompiled::Bn254Add => (0x80, 0x40),
            Precompiled::Bn254ScalarMul => (0x60, 0x40),
            Precompiled::Bn254Pairing => (0x180, 0x20),
        };
        self.code
            .borrow_mut()
            .push(rd_length)
            .push(rd_offset)
            .push(cd_length)
            .push(cd_offset)
            .push(precompile as usize)
            .gas()
            .staticcall()
            .and();
    }

    fn invert(self: &Rc<Self>, value: &Scalar) -> Scalar {
        assert!(!value.ptr.is_null());
        let rd_ptr = self.allocate();
        let [cd_ptr, ..] = [
            &Scalar::constant(self.null_ptr(), 0x20),
            &Scalar::constant(self.null_ptr(), 0x20),
            &Scalar::constant(self.null_ptr(), 0x20),
            value,
            &Scalar::constant(self.null_ptr(), self.scalar_modulus - 2),
            &Scalar::constant(self.null_ptr(), self.scalar_modulus),
        ]
        .map(|value| self.dup_scalar(value).ptr);
        self.staticcall(
            Precompiled::BigModExp,
            cd_ptr.memory_address(),
            rd_ptr.memory_address(),
        );
        Scalar::variable(rd_ptr)
    }

    fn ec_point_add(self: &Rc<Self>, lhs: &EcPoint, rhs: &EcPoint) -> EcPoint {
        let rd_ptr = self.dup_ec_point(lhs).ptr;
        self.dup_ec_point(rhs);
        self.staticcall(
            Precompiled::Bn254Add,
            rd_ptr.memory_address(),
            rd_ptr.memory_address(),
        );
        EcPoint::variable(rd_ptr)
    }

    fn ec_point_scalar_mul(self: &Rc<Self>, ec_point: &EcPoint, scalar: &Scalar) -> EcPoint {
        let rd_ptr = self.dup_ec_point(ec_point).ptr;
        self.dup_scalar(scalar);
        self.staticcall(
            Precompiled::Bn254ScalarMul,
            rd_ptr.memory_address(),
            rd_ptr.memory_address(),
        );
        EcPoint::variable(rd_ptr)
    }

    pub fn pairing(
        self: &Rc<Self>,
        lhs: &EcPoint,
        g2: (U256, U256, U256, U256),
        rhs: &EcPoint,
        minus_s_g2: (U256, U256, U256, U256),
    ) {
        let rd_ptr = self.dup_ec_point(lhs).ptr;
        self.allocate::<0x80>();
        self.code
            .borrow_mut()
            .push(g2.0)
            .push(rd_ptr.memory_address() + 0x40)
            .mstore()
            .push(g2.1)
            .push(rd_ptr.memory_address() + 0x60)
            .mstore()
            .push(g2.2)
            .push(rd_ptr.memory_address() + 0x80)
            .mstore()
            .push(g2.3)
            .push(rd_ptr.memory_address() + 0xa0)
            .mstore();
        self.dup_ec_point(rhs);
        self.allocate::<0x80>();
        self.code
            .borrow_mut()
            .push(minus_s_g2.0)
            .push(rd_ptr.memory_address() + 0x100)
            .mstore()
            .push(minus_s_g2.1)
            .push(rd_ptr.memory_address() + 0x120)
            .mstore()
            .push(minus_s_g2.2)
            .push(rd_ptr.memory_address() + 0x140)
            .mstore()
            .push(minus_s_g2.3)
            .push(rd_ptr.memory_address() + 0x160)
            .mstore();
        self.staticcall(
            Precompiled::Bn254Pairing,
            rd_ptr.memory_address(),
            rd_ptr.memory_address(),
        );
        self.code
            .borrow_mut()
            .push(rd_ptr.memory_address())
            .mload()
            .and();
    }

    fn ec_point_sub(self: &Rc<Self>, _: &EcPoint, _: &EcPoint) -> EcPoint {
        todo!()
    }

    fn ec_point_neg(self: &Rc<Self>, _: &EcPoint) -> EcPoint {
        todo!()
    }

    fn add(self: &Rc<Self>, lhs: &Scalar, rhs: &Scalar) -> Scalar {
        if let (Some(lhs), Some(rhs)) = (lhs.constant, rhs.constant) {
            return Scalar::constant(
                self.null_ptr(),
                U256::try_from(
                    (U512::from(lhs) + U512::from(rhs)) % U512::from(self.scalar_modulus),
                )
                .unwrap(),
            );
        }

        let ptr = self.allocate();

        self.code.borrow_mut().push(self.scalar_modulus);
        self.push(rhs);
        self.push(lhs);
        self.code
            .borrow_mut()
            .addmod()
            .push(ptr.memory_address())
            .mstore();

        Scalar::variable(ptr)
    }

    fn sub(self: &Rc<Self>, lhs: &Scalar, rhs: &Scalar) -> Scalar {
        if rhs.is_const() {
            return self.add(lhs, &self.neg(rhs));
        }

        self.code.borrow_mut().push(self.scalar_modulus);
        self.push(rhs);
        self.code.borrow_mut().push(self.scalar_modulus).sub();

        let ptr = self.allocate();

        self.push(lhs);
        self.code
            .borrow_mut()
            .addmod()
            .push(ptr.memory_address())
            .mstore();

        Scalar::variable(ptr)
    }

    fn mul(self: &Rc<Self>, lhs: &Scalar, rhs: &Scalar) -> Scalar {
        if let (Some(lhs), Some(rhs)) = (lhs.constant, rhs.constant) {
            return Scalar::constant(
                self.null_ptr(),
                U256::try_from(
                    (U512::from(lhs) * U512::from(rhs)) % U512::from(self.scalar_modulus),
                )
                .unwrap(),
            );
        }

        let ptr = self.allocate();

        self.code.borrow_mut().push(self.scalar_modulus);
        self.push(rhs);
        self.push(lhs);
        self.code
            .borrow_mut()
            .mulmod()
            .push(ptr.memory_address())
            .mstore();

        Scalar::variable(ptr)
    }

    fn neg(self: &Rc<Self>, value: &Scalar) -> Scalar {
        if let Some(constant) = value.constant {
            return Scalar::constant(self.null_ptr(), self.scalar_modulus - constant);
        }

        let ptr = self.allocate();

        self.push(value);
        self.code
            .borrow_mut()
            .push(self.scalar_modulus)
            .sub()
            .push(ptr.memory_address())
            .mstore();

        Scalar::variable(ptr)
    }
}

#[derive(Clone, Debug)]
pub struct EcPoint {
    ptr: Pointer<0x40>,
    constant: Option<(U256, U256)>,
}

impl EcPoint {
    fn constant(ptr: Pointer<0x40>, value: (U256, U256)) -> Self {
        Self {
            ptr,
            constant: Some(value),
        }
    }

    fn variable(ptr: Pointer<0x40>) -> Self {
        Self {
            ptr,
            constant: None,
        }
    }

    pub const fn is_const(&self) -> bool {
        self.constant.is_some()
    }

    pub fn memory_address(&self) -> usize {
        self.ptr.memory_address()
    }
}

impl Add for EcPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.ptr.loader.ec_point_add(&self, &rhs)
    }
}

impl Sub for EcPoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.ptr.loader.ec_point_sub(&self, &rhs)
    }
}

impl Neg for EcPoint {
    type Output = Self;

    fn neg(self) -> Self {
        self.ptr.loader.ec_point_neg(&self)
    }
}

impl<'a> Add<&'a Self> for EcPoint {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self {
        self.ptr.loader.ec_point_add(&self, rhs)
    }
}

impl<'a> Sub<&'a Self> for EcPoint {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self {
        self.ptr.loader.ec_point_sub(&self, rhs)
    }
}

impl AddAssign for EcPoint {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.ptr.loader.ec_point_add(self, &rhs);
    }
}

impl SubAssign for EcPoint {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.ptr.loader.ec_point_sub(self, &rhs);
    }
}

impl<'a> AddAssign<&'a Self> for EcPoint {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = self.ptr.loader.ec_point_add(self, rhs);
    }
}

impl<'a> SubAssign<&'a Self> for EcPoint {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self = self.ptr.loader.ec_point_sub(self, rhs);
    }
}

impl<C> LoadedEcPoint<C> for EcPoint
where
    C: Curve + UncompressedEncoding<Uncompressed = [u8; 0x40]>,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    type Loader = Rc<EvmLoader>;

    fn loader(&self) -> &Rc<EvmLoader> {
        self.ptr.loader.borrow()
    }

    fn multi_scalar_multiplication(pairs: impl IntoIterator<Item = (Scalar, EcPoint)>) -> Self {
        pairs
            .into_iter()
            .map(|(scalar, ec_point)| match scalar.constant {
                Some(constant) if constant == U256::one() => ec_point,
                _ => ec_point.ptr.loader.ec_point_scalar_mul(&ec_point, &scalar),
            })
            .reduce(|acc, ec_point| acc + ec_point)
            .unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct Scalar {
    ptr: Pointer<0x20>,
    constant: Option<U256>,
}

impl Scalar {
    fn constant<T: Into<U256>>(ptr: Pointer<0x20>, value: T) -> Self {
        Self {
            ptr,
            constant: Some(value.into()),
        }
    }

    fn variable(ptr: Pointer<0x20>) -> Self {
        Self {
            ptr,
            constant: None,
        }
    }

    pub fn ptr(&self) -> Pointer<0x20> {
        self.ptr.clone()
    }

    pub const fn is_const(&self) -> bool {
        self.constant.is_some()
    }

    pub fn memory_address(&self) -> usize {
        self.ptr.memory_address()
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.ptr.loader.add(&self, &rhs)
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.ptr.loader.sub(&self, &rhs)
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        self.ptr.loader.mul(&self, &rhs)
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self {
        self.ptr.loader.neg(&self)
    }
}

impl<'a> Add<&'a Self> for Scalar {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self {
        self.ptr.loader.add(&self, rhs)
    }
}

impl<'a> Sub<&'a Self> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self {
        self.ptr.loader.sub(&self, rhs)
    }
}

impl<'a> Mul<&'a Self> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &'a Self) -> Self {
        self.ptr.loader.mul(&self, rhs)
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.ptr.loader.add(self, &rhs);
    }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.ptr.loader.sub(self, &rhs);
    }
}

impl MulAssign for Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.ptr.loader.mul(self, &rhs);
    }
}

impl<'a> AddAssign<&'a Self> for Scalar {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = self.ptr.loader.add(self, rhs);
    }
}

impl<'a> SubAssign<&'a Self> for Scalar {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self = self.ptr.loader.sub(self, rhs);
    }
}

impl<'a> MulAssign<&'a Self> for Scalar {
    fn mul_assign(&mut self, rhs: &'a Self) {
        *self = self.ptr.loader.mul(self, rhs);
    }
}

impl FieldOps for Scalar {
    fn invert(&self) -> Option<Scalar> {
        Some(self.ptr.loader.invert(self))
    }
}

impl<F: PrimeField<Repr = [u8; 0x20]>> LoadedScalar<F> for Scalar {
    type Loader = Rc<EvmLoader>;

    fn loader(&self) -> &Rc<EvmLoader> {
        self.ptr.loader.borrow()
    }

    fn batch_invert<'a>(values: impl IntoIterator<Item = &'a mut Self>) {
        let values = values.into_iter().collect::<Vec<_>>();
        let loader = &values.first().unwrap().ptr.loader;
        let products = iter::once(values[0].clone())
            .chain(
                iter::repeat_with(|| loader.allocate::<0x20>())
                    .map(Scalar::variable)
                    .take(values.len() - 1),
            )
            .collect::<Vec<_>>();

        loader.code.borrow_mut().push(loader.scalar_modulus);
        for _ in 2..values.len() {
            loader.code.borrow_mut().dup(0);
        }

        loader.push(products.first().unwrap());
        for (idx, (value, product)) in values.iter().zip(products.iter()).skip(1).enumerate() {
            loader.push(value);
            loader.code.borrow_mut().mulmod();
            if idx < values.len() - 2 {
                loader.code.borrow_mut().dup(0);
            }
            loader
                .code
                .borrow_mut()
                .push(product.memory_address())
                .mstore();
        }

        let inv = loader.invert(products.last().unwrap());

        loader.code.borrow_mut().push(loader.scalar_modulus);
        for _ in 2..values.len() {
            loader.code.borrow_mut().dup(0);
        }

        loader.push(&inv);
        for (value, product) in values.iter().rev().zip(
            products
                .iter()
                .rev()
                .skip(1)
                .map(Option::Some)
                .chain(iter::once(None)),
        ) {
            if let Some(product) = product {
                loader.push(value);
                loader
                    .code
                    .borrow_mut()
                    .dup(2)
                    .dup(2)
                    .push(product.memory_address())
                    .mload()
                    .mulmod()
                    .push(value.memory_address())
                    .mstore()
                    .mulmod();
            } else {
                loader
                    .code
                    .borrow_mut()
                    .push(value.memory_address())
                    .mstore();
            }
        }
    }
}

impl<C> EcPointLoader<C> for Rc<EvmLoader>
where
    C: Curve + UncompressedEncoding<Uncompressed = [u8; 0x40]>,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    type LoadedEcPoint = EcPoint;

    fn ec_point_load_const(&self, value: &C) -> EcPoint {
        let bytes = value.to_uncompressed();
        let (x, y) = (
            U256::from_little_endian(&bytes[..32]),
            U256::from_little_endian(&bytes[32..]),
        );
        EcPoint::constant(self.null_ptr(), (x, y))
    }
}

impl<F: PrimeField<Repr = [u8; 0x20]>> ScalarLoader<F> for Rc<EvmLoader> {
    type LoadedScalar = Scalar;

    fn load_const(&self, value: &F) -> Scalar {
        Scalar::constant(
            self.null_ptr(),
            U256::from_little_endian(value.to_repr().as_slice()),
        )
    }
}

#[cfg(test)]
pub mod test {
    use crate::loader::evm::Tui;
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

    pub fn execute(code: Vec<u8>, calldata: Vec<u8>) -> (bool, u64) {
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
}
