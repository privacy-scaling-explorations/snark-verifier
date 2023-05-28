use crate::{
    loader::{
        halo2::shim::{EccInstructions, IntegerInstructions},
        EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader,
    },
    util::{
        arithmetic::{CurveAffine, Field, FieldOps},
        Itertools,
    },
};
use halo2_proofs::circuit;
use std::{
    cell::{Ref, RefCell, RefMut},
    fmt::{self, Debug},
    marker::PhantomData,
    ops::{Add, AddAssign, Deref, Mul, MulAssign, Neg, Sub, SubAssign},
    rc::Rc,
};

/// `Loader` implementation for generating verifier in [`halo2_proofs`] circuit.
#[derive(Debug)]
pub struct Halo2Loader<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> {
    ecc_chip: RefCell<EccChip>,
    ctx: RefCell<EccChip::Context>,
    num_scalar: RefCell<usize>,
    num_ec_point: RefCell<usize>,
    _marker: PhantomData<C>,
    #[cfg(test)]
    row_meterings: RefCell<Vec<(String, usize)>>,
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Halo2Loader<'a, C, EccChip> {
    /// Initialize a [`Halo2Loader`] with given [`EccInstructions`] and
    /// [`EccInstructions::Context`].
    pub fn new(ecc_chip: EccChip, ctx: EccChip::Context) -> Rc<Self> {
        Rc::new(Self {
            ecc_chip: RefCell::new(ecc_chip),
            ctx: RefCell::new(ctx),
            num_scalar: RefCell::default(),
            num_ec_point: RefCell::default(),
            #[cfg(test)]
            row_meterings: RefCell::default(),
            _marker: PhantomData,
        })
    }

    /// Into [`EccInstructions::Context`].
    pub fn into_ctx(self) -> EccChip::Context {
        self.ctx.into_inner()
    }

    /// Returns reference of [`EccInstructions`].
    pub fn ecc_chip(&self) -> Ref<EccChip> {
        self.ecc_chip.borrow()
    }

    /// Returns reference of [`EccInstructions::ScalarChip`].
    pub fn scalar_chip(&self) -> Ref<EccChip::ScalarChip> {
        Ref::map(self.ecc_chip(), |ecc_chip| ecc_chip.scalar_chip())
    }

    /// Returns reference of [`EccInstructions::Context`].
    pub fn ctx(&self) -> Ref<EccChip::Context> {
        self.ctx.borrow()
    }

    /// Returns mutable reference of [`EccInstructions::Context`].
    pub fn ctx_mut(&self) -> RefMut<'_, EccChip::Context> {
        self.ctx.borrow_mut()
    }

    fn assign_const_scalar(self: &Rc<Self>, constant: C::Scalar) -> EccChip::AssignedScalar {
        self.scalar_chip()
            .assign_constant(&mut self.ctx_mut(), constant)
            .unwrap()
    }

    /// Assign a field element witness.
    pub fn assign_scalar(
        self: &Rc<Self>,
        scalar: circuit::Value<C::Scalar>,
    ) -> Scalar<'a, C, EccChip> {
        let assigned = self
            .scalar_chip()
            .assign_integer(&mut self.ctx_mut(), scalar)
            .unwrap();
        self.scalar_from_assigned(assigned)
    }

    /// Returns [`Scalar`] with assigned field element.
    pub fn scalar_from_assigned(
        self: &Rc<Self>,
        assigned: EccChip::AssignedScalar,
    ) -> Scalar<'a, C, EccChip> {
        self.scalar(Value::Assigned(assigned))
    }

    fn scalar(
        self: &Rc<Self>,
        value: Value<C::Scalar, EccChip::AssignedScalar>,
    ) -> Scalar<'a, C, EccChip> {
        let index = *self.num_scalar.borrow();
        *self.num_scalar.borrow_mut() += 1;
        Scalar {
            loader: self.clone(),
            index,
            value: value.into(),
        }
    }

    fn assign_const_ec_point(self: &Rc<Self>, constant: C) -> EccChip::AssignedEcPoint {
        self.ecc_chip()
            .assign_constant(&mut self.ctx_mut(), constant)
            .unwrap()
    }

    /// Assign an elliptic curve point witness.
    pub fn assign_ec_point(
        self: &Rc<Self>,
        ec_point: circuit::Value<C>,
    ) -> EcPoint<'a, C, EccChip> {
        let assigned = self
            .ecc_chip()
            .assign_point(&mut self.ctx_mut(), ec_point)
            .unwrap();
        self.ec_point_from_assigned(assigned)
    }

    /// Returns [`EcPoint`] with assigned elliptic curve point.
    pub fn ec_point_from_assigned(
        self: &Rc<Self>,
        assigned: EccChip::AssignedEcPoint,
    ) -> EcPoint<'a, C, EccChip> {
        self.ec_point(Value::Assigned(assigned))
    }

    fn ec_point(
        self: &Rc<Self>,
        value: Value<C, EccChip::AssignedEcPoint>,
    ) -> EcPoint<'a, C, EccChip> {
        let index = *self.num_ec_point.borrow();
        *self.num_ec_point.borrow_mut() += 1;
        EcPoint {
            loader: self.clone(),
            index,
            value: value.into(),
        }
    }

    fn add(
        self: &Rc<Self>,
        lhs: &Scalar<'a, C, EccChip>,
        rhs: &Scalar<'a, C, EccChip>,
    ) -> Scalar<'a, C, EccChip> {
        let output = match (lhs.value().deref(), rhs.value().deref()) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs + rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => self
                .scalar_chip()
                .sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(C::Scalar::ONE, assigned)],
                    *constant,
                )
                .map(Value::Assigned)
                .unwrap(),
            (Value::Assigned(lhs), Value::Assigned(rhs)) => self
                .scalar_chip()
                .sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(C::Scalar::ONE, lhs), (C::Scalar::ONE, rhs)],
                    C::Scalar::ZERO,
                )
                .map(Value::Assigned)
                .unwrap(),
        };
        self.scalar(output)
    }

    fn sub(
        self: &Rc<Self>,
        lhs: &Scalar<'a, C, EccChip>,
        rhs: &Scalar<'a, C, EccChip>,
    ) -> Scalar<'a, C, EccChip> {
        let output = match (lhs.value().deref(), rhs.value().deref()) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs - rhs),
            (Value::Constant(constant), Value::Assigned(assigned)) => self
                .scalar_chip()
                .sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(-C::Scalar::ONE, assigned)],
                    *constant,
                )
                .map(Value::Assigned)
                .unwrap(),
            (Value::Assigned(assigned), Value::Constant(constant)) => self
                .scalar_chip()
                .sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(C::Scalar::ONE, assigned)],
                    -*constant,
                )
                .map(Value::Assigned)
                .unwrap(),
            (Value::Assigned(lhs), Value::Assigned(rhs)) => {
                IntegerInstructions::sub(self.scalar_chip().deref(), &mut self.ctx_mut(), lhs, rhs)
                    .map(Value::Assigned)
                    .unwrap()
            }
        };
        self.scalar(output)
    }

    fn mul(
        self: &Rc<Self>,
        lhs: &Scalar<'a, C, EccChip>,
        rhs: &Scalar<'a, C, EccChip>,
    ) -> Scalar<'a, C, EccChip> {
        let output = match (lhs.value().deref(), rhs.value().deref()) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs * rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => self
                .scalar_chip()
                .sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(*constant, assigned)],
                    C::Scalar::ZERO,
                )
                .map(Value::Assigned)
                .unwrap(),
            (Value::Assigned(lhs), Value::Assigned(rhs)) => self
                .scalar_chip()
                .sum_products_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(C::Scalar::ONE, lhs, rhs)],
                    C::Scalar::ZERO,
                )
                .map(Value::Assigned)
                .unwrap(),
        };
        self.scalar(output)
    }

    fn neg(self: &Rc<Self>, scalar: &Scalar<'a, C, EccChip>) -> Scalar<'a, C, EccChip> {
        let output = match scalar.value().deref() {
            Value::Constant(constant) => Value::Constant(constant.neg()),
            Value::Assigned(assigned) => {
                IntegerInstructions::neg(self.scalar_chip().deref(), &mut self.ctx_mut(), assigned)
                    .map(Value::Assigned)
                    .unwrap()
            }
        };
        self.scalar(output)
    }

    fn invert(self: &Rc<Self>, scalar: &Scalar<'a, C, EccChip>) -> Scalar<'a, C, EccChip> {
        let output = match scalar.value().deref() {
            Value::Constant(constant) => Value::Constant(Field::invert(constant).unwrap()),
            Value::Assigned(assigned) => Value::Assigned(
                IntegerInstructions::invert(
                    self.scalar_chip().deref(),
                    &mut self.ctx_mut(),
                    assigned,
                )
                .unwrap(),
            ),
        };
        self.scalar(output)
    }
}

#[cfg(test)]
impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Halo2Loader<'a, C, EccChip> {
    fn start_row_metering(self: &Rc<Self>, identifier: &str) {
        use crate::loader::halo2::shim::Context;

        self.row_meterings
            .borrow_mut()
            .push((identifier.to_string(), self.ctx().offset()))
    }

    fn end_row_metering(self: &Rc<Self>) {
        use crate::loader::halo2::shim::Context;

        let mut row_meterings = self.row_meterings.borrow_mut();
        let (_, row) = row_meterings.last_mut().unwrap();
        *row = self.ctx().offset() - *row;
    }

    pub fn print_row_metering(self: &Rc<Self>) {
        for (identifier, cost) in self.row_meterings.borrow().iter() {
            println!("{}: {}", identifier, cost);
        }
    }
}

#[derive(Clone, Debug)]
pub enum Value<T, L> {
    Constant(T),
    Assigned(L),
}

impl<T, L> Value<T, L> {
    fn maybe_const(&self) -> Option<T>
    where
        T: Copy,
    {
        match self {
            Value::Constant(constant) => Some(*constant),
            _ => None,
        }
    }

    fn assigned(&self) -> &L {
        match self {
            Value::Assigned(assigned) => assigned,
            _ => unreachable!(),
        }
    }
}

/// Field element
#[derive(Clone)]
pub struct Scalar<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> {
    loader: Rc<Halo2Loader<'a, C, EccChip>>,
    index: usize,
    value: RefCell<Value<C::Scalar, EccChip::AssignedScalar>>,
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Scalar<'a, C, EccChip> {
    /// Returns reference of [`Rc<Halo2Loader>`]
    pub fn loader(&self) -> &Rc<Halo2Loader<'a, C, EccChip>> {
        &self.loader
    }

    /// Returns reference of [`EccInstructions::AssignedScalar`].
    pub fn assigned(&self) -> Ref<EccChip::AssignedScalar> {
        if let Some(constant) = self.maybe_const() {
            *self.value.borrow_mut() = Value::Assigned(self.loader.assign_const_scalar(constant))
        }
        Ref::map(self.value.borrow(), Value::assigned)
    }

    /// If scalar already assigned, returns itself as [`EccInstructions::AssignedScalar`]. Otherwise,
    /// scalar is constant, so loader assigned the constant scalar and returns the assigned scalar.
    pub fn into_assigned(self) -> EccChip::AssignedScalar {
        match self.value.into_inner() {
            Value::Constant(constant) => self.loader.assign_const_scalar(constant),
            Value::Assigned(assigned) => assigned,
        }
    }

    fn value(&self) -> Ref<Value<C::Scalar, EccChip::AssignedScalar>> {
        self.value.borrow()
    }

    fn maybe_const(&self) -> Option<C::Scalar> {
        self.value().deref().maybe_const()
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> PartialEq for Scalar<'a, C, EccChip> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> LoadedScalar<C::Scalar>
    for Scalar<'a, C, EccChip>
{
    type Loader = Rc<Halo2Loader<'a, C, EccChip>>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Debug for Scalar<'a, C, EccChip> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar")
            .field("value", &self.value)
            .finish()
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> FieldOps for Scalar<'a, C, EccChip> {
    fn invert(&self) -> Option<Self> {
        Some(self.loader.invert(self))
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Add for Scalar<'a, C, EccChip> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Halo2Loader::add(&self.loader, &self, &rhs)
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Sub for Scalar<'a, C, EccChip> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Halo2Loader::sub(&self.loader, &self, &rhs)
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Mul for Scalar<'a, C, EccChip> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Halo2Loader::mul(&self.loader, &self, &rhs)
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Neg for Scalar<'a, C, EccChip> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Halo2Loader::neg(&self.loader, &self)
    }
}

impl<'a, 'b, C: CurveAffine, EccChip: EccInstructions<'a, C>> Add<&'b Self>
    for Scalar<'a, C, EccChip>
{
    type Output = Self;

    fn add(self, rhs: &'b Self) -> Self::Output {
        Halo2Loader::add(&self.loader, &self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine, EccChip: EccInstructions<'a, C>> Sub<&'b Self>
    for Scalar<'a, C, EccChip>
{
    type Output = Self;

    fn sub(self, rhs: &'b Self) -> Self::Output {
        Halo2Loader::sub(&self.loader, &self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine, EccChip: EccInstructions<'a, C>> Mul<&'b Self>
    for Scalar<'a, C, EccChip>
{
    type Output = Self;

    fn mul(self, rhs: &'b Self) -> Self::Output {
        Halo2Loader::mul(&self.loader, &self, rhs)
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> AddAssign for Scalar<'a, C, EccChip> {
    fn add_assign(&mut self, rhs: Self) {
        *self = Halo2Loader::add(&self.loader, self, &rhs)
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> SubAssign for Scalar<'a, C, EccChip> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = Halo2Loader::sub(&self.loader, self, &rhs)
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> MulAssign for Scalar<'a, C, EccChip> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Halo2Loader::mul(&self.loader, self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine, EccChip: EccInstructions<'a, C>> AddAssign<&'b Self>
    for Scalar<'a, C, EccChip>
{
    fn add_assign(&mut self, rhs: &'b Self) {
        *self = Halo2Loader::add(&self.loader, self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine, EccChip: EccInstructions<'a, C>> SubAssign<&'b Self>
    for Scalar<'a, C, EccChip>
{
    fn sub_assign(&mut self, rhs: &'b Self) {
        *self = Halo2Loader::sub(&self.loader, self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine, EccChip: EccInstructions<'a, C>> MulAssign<&'b Self>
    for Scalar<'a, C, EccChip>
{
    fn mul_assign(&mut self, rhs: &'b Self) {
        *self = Halo2Loader::mul(&self.loader, self, rhs)
    }
}

/// Elliptic curve point
#[derive(Clone)]
pub struct EcPoint<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> {
    loader: Rc<Halo2Loader<'a, C, EccChip>>,
    index: usize,
    value: RefCell<Value<C, EccChip::AssignedEcPoint>>,
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> EcPoint<'a, C, EccChip> {
    /// Into [`EccInstructions::AssignedEcPoint`].
    pub fn into_assigned(self) -> EccChip::AssignedEcPoint {
        match self.value.into_inner() {
            Value::Constant(constant) => self.loader.assign_const_ec_point(constant),
            Value::Assigned(assigned) => assigned,
        }
    }

    /// Returns reference of [`EccInstructions::AssignedEcPoint`].
    pub fn assigned(&self) -> Ref<EccChip::AssignedEcPoint> {
        if let Some(constant) = self.maybe_const() {
            *self.value.borrow_mut() = Value::Assigned(self.loader.assign_const_ec_point(constant))
        }
        Ref::map(self.value.borrow(), Value::assigned)
    }

    fn value(&self) -> Ref<Value<C, EccChip::AssignedEcPoint>> {
        self.value.borrow()
    }

    fn maybe_const(&self) -> Option<C> {
        self.value().deref().maybe_const()
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> PartialEq for EcPoint<'a, C, EccChip> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> LoadedEcPoint<C>
    for EcPoint<'a, C, EccChip>
{
    type Loader = Rc<Halo2Loader<'a, C, EccChip>>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Debug for EcPoint<'a, C, EccChip> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPoint")
            .field("index", &self.index)
            .field("value", &self.value)
            .finish()
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> ScalarLoader<C::Scalar>
    for Rc<Halo2Loader<'a, C, EccChip>>
{
    type LoadedScalar = Scalar<'a, C, EccChip>;

    fn load_const(&self, value: &C::Scalar) -> Scalar<'a, C, EccChip> {
        self.scalar(Value::Constant(*value))
    }

    fn assert_eq(
        &self,
        annotation: &str,
        lhs: &Scalar<'a, C, EccChip>,
        rhs: &Scalar<'a, C, EccChip>,
    ) -> Result<(), crate::Error> {
        self.scalar_chip()
            .assert_equal(&mut self.ctx_mut(), &lhs.assigned(), &rhs.assigned())
            .map_err(|_| crate::Error::AssertionFailure(annotation.to_string()))
    }

    fn sum_with_coeff_and_const(
        &self,
        values: &[(C::Scalar, &Scalar<'a, C, EccChip>)],
        constant: C::Scalar,
    ) -> Scalar<'a, C, EccChip> {
        let values = values
            .iter()
            .map(|(coeff, value)| (*coeff, value.assigned()))
            .collect_vec();
        self.scalar(Value::Assigned(
            self.scalar_chip()
                .sum_with_coeff_and_const(&mut self.ctx_mut(), &values, constant)
                .unwrap(),
        ))
    }

    fn sum_products_with_coeff_and_const(
        &self,
        values: &[(C::Scalar, &Scalar<'a, C, EccChip>, &Scalar<'a, C, EccChip>)],
        constant: C::Scalar,
    ) -> Scalar<'a, C, EccChip> {
        let values = values
            .iter()
            .map(|(coeff, lhs, rhs)| (*coeff, lhs.assigned(), rhs.assigned()))
            .collect_vec();
        self.scalar(Value::Assigned(
            self.scalar_chip()
                .sum_products_with_coeff_and_const(&mut self.ctx_mut(), &values, constant)
                .unwrap(),
        ))
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> EcPointLoader<C>
    for Rc<Halo2Loader<'a, C, EccChip>>
{
    type LoadedEcPoint = EcPoint<'a, C, EccChip>;

    fn ec_point_load_const(&self, ec_point: &C) -> EcPoint<'a, C, EccChip> {
        self.ec_point(Value::Constant(*ec_point))
    }

    fn ec_point_assert_eq(
        &self,
        annotation: &str,
        lhs: &EcPoint<'a, C, EccChip>,
        rhs: &EcPoint<'a, C, EccChip>,
    ) -> Result<(), crate::Error> {
        if let (Value::Constant(lhs), Value::Constant(rhs)) =
            (lhs.value().deref(), rhs.value().deref())
        {
            assert_eq!(lhs, rhs);
            Ok(())
        } else {
            let lhs = lhs.assigned();
            let rhs = rhs.assigned();
            self.ecc_chip()
                .assert_equal(&mut self.ctx_mut(), lhs.deref(), rhs.deref())
                .map_err(|_| crate::Error::AssertionFailure(annotation.to_string()))
        }
    }

    fn multi_scalar_multiplication(
        pairs: &[(
            &<Self as ScalarLoader<C::Scalar>>::LoadedScalar,
            &EcPoint<'a, C, EccChip>,
        )],
    ) -> EcPoint<'a, C, EccChip> {
        let loader = &pairs[0].0.loader;

        let (constant, fixed_base, variable_base_non_scaled, variable_base_scaled) =
            pairs.iter().cloned().fold(
                (C::identity(), Vec::new(), Vec::new(), Vec::new()),
                |(
                    mut constant,
                    mut fixed_base,
                    mut variable_base_non_scaled,
                    mut variable_base_scaled,
                ),
                 (scalar, base)| {
                    match (scalar.value().deref(), base.value().deref()) {
                        (Value::Constant(scalar), Value::Constant(base)) => {
                            constant = (*base * scalar + constant).into()
                        }
                        (Value::Assigned(_), Value::Constant(base)) => {
                            fixed_base.push((scalar, *base))
                        }
                        (Value::Constant(scalar), Value::Assigned(_))
                            if scalar.eq(&C::Scalar::ONE) =>
                        {
                            variable_base_non_scaled.push(base);
                        }
                        _ => variable_base_scaled.push((scalar, base)),
                    };
                    (
                        constant,
                        fixed_base,
                        variable_base_non_scaled,
                        variable_base_scaled,
                    )
                },
            );

        let fixed_base_msm = (!fixed_base.is_empty())
            .then(|| {
                let fixed_base = fixed_base
                    .into_iter()
                    .map(|(scalar, base)| (scalar.assigned(), base))
                    .collect_vec();
                loader
                    .ecc_chip
                    .borrow_mut()
                    .fixed_base_msm(&mut loader.ctx_mut(), &fixed_base)
                    .unwrap()
            })
            .map(RefCell::new);
        let variable_base_msm = (!variable_base_scaled.is_empty())
            .then(|| {
                let variable_base_scaled = variable_base_scaled
                    .into_iter()
                    .map(|(scalar, base)| (scalar.assigned(), base.assigned()))
                    .collect_vec();
                loader
                    .ecc_chip
                    .borrow_mut()
                    .variable_base_msm(&mut loader.ctx_mut(), &variable_base_scaled)
                    .unwrap()
            })
            .map(RefCell::new);
        let output = loader
            .ecc_chip()
            .sum_with_const(
                &mut loader.ctx_mut(),
                &variable_base_non_scaled
                    .into_iter()
                    .map(EcPoint::assigned)
                    .chain(fixed_base_msm.as_ref().map(RefCell::borrow))
                    .chain(variable_base_msm.as_ref().map(RefCell::borrow))
                    .collect_vec(),
                constant,
            )
            .unwrap();

        loader.ec_point_from_assigned(output)
    }
}

impl<'a, C: CurveAffine, EccChip: EccInstructions<'a, C>> Loader<C>
    for Rc<Halo2Loader<'a, C, EccChip>>
{
    #[cfg(test)]
    fn start_cost_metering(&self, identifier: &str) {
        self.start_row_metering(identifier)
    }

    #[cfg(test)]
    fn end_cost_metering(&self) {
        self.end_row_metering()
    }
}
