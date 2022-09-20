use crate::{
    loader::{
        halo2::shim::{EccInstructions, IntegerInstructions},
        EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader,
    },
    util::{
        arithmetic::{Curve, CurveAffine, Field, FieldExt, FieldOps, Group},
        Itertools,
    },
};
use halo2_proofs::circuit::{self, Region};
use halo2_wrong_ecc::maingate::RegionCtx;
use rand::rngs::OsRng;
use std::{
    cell::{Ref, RefCell},
    collections::btree_map::{BTreeMap, Entry},
    fmt::{self, Debug},
    iter,
    marker::PhantomData,
    ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign, Neg, Sub, SubAssign},
    rc::Rc,
};

const WINDOW_SIZE: usize = 3;

#[derive(Debug)]
pub struct Halo2Loader<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> {
    ecc_chip: RefCell<EccChip>,
    ctx: RefCell<RegionCtx<'a, N>>,
    num_scalar: RefCell<usize>,
    num_ec_point: RefCell<usize>,
    const_ec_point: RefCell<BTreeMap<(C::Base, C::Base), EcPoint<'a, C, N, EccChip>>>,
    _marker: PhantomData<C>,
    #[cfg(test)]
    row_meterings: RefCell<Vec<(String, usize)>>,
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>>
    Halo2Loader<'a, C, N, EccChip>
{
    pub fn new(ecc_chip: EccChip, ctx: RegionCtx<'a, N>) -> Rc<Self> {
        Rc::new(Self {
            ecc_chip: RefCell::new(ecc_chip),
            ctx: RefCell::new(ctx),
            num_scalar: RefCell::default(),
            num_ec_point: RefCell::default(),
            const_ec_point: RefCell::default(),
            #[cfg(test)]
            row_meterings: RefCell::default(),
            _marker: PhantomData,
        })
    }

    pub fn into_region(self) -> Region<'a, N> {
        self.ctx.into_inner().into_region()
    }

    pub fn ecc_chip(&self) -> impl Deref<Target = EccChip> + '_ {
        self.ecc_chip.borrow()
    }

    pub fn scalar_chip(&self) -> impl Deref<Target = EccChip::ScalarChip> + '_ {
        Ref::map(self.ecc_chip.borrow(), |ecc_chip| ecc_chip.scalar_chip())
    }

    pub fn ctx(&self) -> impl Deref<Target = RegionCtx<'a, N>> + '_ {
        self.ctx.borrow()
    }

    pub(crate) fn ctx_mut(&self) -> impl DerefMut<Target = RegionCtx<'a, N>> + '_ {
        self.ctx.borrow_mut()
    }

    pub fn assign_const_scalar(self: &Rc<Self>, constant: C::Scalar) -> Scalar<'a, C, N, EccChip> {
        let assigned = self
            .scalar_chip()
            .assign_constant(&mut self.ctx_mut(), constant)
            .unwrap();
        self.scalar(Value::Assigned(assigned))
    }

    pub fn assign_scalar(
        self: &Rc<Self>,
        scalar: circuit::Value<EccChip::Scalar>,
    ) -> Scalar<'a, C, N, EccChip> {
        let assigned = self
            .scalar_chip()
            .assign_integer(&mut self.ctx_mut(), scalar)
            .unwrap();
        self.scalar(Value::Assigned(assigned))
    }

    pub(crate) fn scalar(
        self: &Rc<Self>,
        value: Value<C::Scalar, EccChip::AssignedScalar>,
    ) -> Scalar<'a, C, N, EccChip> {
        let index = *self.num_scalar.borrow();
        *self.num_scalar.borrow_mut() += 1;
        Scalar {
            loader: self.clone(),
            index,
            value,
        }
    }

    pub fn assign_const_ec_point(self: &Rc<Self>, constant: C) -> EcPoint<'a, C, N, EccChip> {
        let coordinates = constant.coordinates().unwrap();
        match self
            .const_ec_point
            .borrow_mut()
            .entry((*coordinates.x(), *coordinates.y()))
        {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let assigned = self
                    .ecc_chip
                    .borrow()
                    .assign_point(&mut self.ctx_mut(), circuit::Value::known(constant))
                    .unwrap();
                let ec_point = self.ec_point(assigned);
                entry.insert(ec_point).clone()
            }
        }
    }

    pub fn assign_ec_point(
        self: &Rc<Self>,
        ec_point: circuit::Value<C>,
    ) -> EcPoint<'a, C, N, EccChip> {
        let assigned = self
            .ecc_chip
            .borrow()
            .assign_point(&mut self.ctx_mut(), ec_point)
            .unwrap();
        self.ec_point(assigned)
    }

    fn ec_point(self: &Rc<Self>, assigned: EccChip::AssignedPoint) -> EcPoint<'a, C, N, EccChip> {
        let index = *self.num_ec_point.borrow();
        *self.num_ec_point.borrow_mut() += 1;
        EcPoint {
            loader: self.clone(),
            index,
            assigned,
        }
    }

    fn add(
        self: &Rc<Self>,
        lhs: &Scalar<'a, C, N, EccChip>,
        rhs: &Scalar<'a, C, N, EccChip>,
    ) -> Scalar<'a, C, N, EccChip> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs + rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => self
                .scalar_chip()
                .add_constant(
                    &mut self.ctx_mut(),
                    assigned,
                    &self.scalar_chip().integer(*constant),
                )
                .map(Value::Assigned)
                .unwrap(),
            (Value::Assigned(lhs), Value::Assigned(rhs)) => {
                IntegerInstructions::add(self.scalar_chip().deref(), &mut self.ctx_mut(), lhs, rhs)
                    .map(Value::Assigned)
                    .unwrap()
            }
        };
        self.scalar(output)
    }

    fn sub(
        self: &Rc<Self>,
        lhs: &Scalar<'a, C, N, EccChip>,
        rhs: &Scalar<'a, C, N, EccChip>,
    ) -> Scalar<'a, C, N, EccChip> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs - rhs),
            (Value::Constant(constant), Value::Assigned(assigned)) => {
                let neg = IntegerInstructions::neg(
                    self.scalar_chip().deref(),
                    &mut self.ctx_mut(),
                    assigned,
                )
                .unwrap();
                self.scalar_chip()
                    .add_constant(
                        &mut self.ctx_mut(),
                        &neg,
                        &self.scalar_chip().integer(*constant),
                    )
                    .map(Value::Assigned)
                    .unwrap()
            }
            (Value::Assigned(assigned), Value::Constant(constant)) => self
                .scalar_chip()
                .add_constant(
                    &mut self.ctx_mut(),
                    assigned,
                    &self.scalar_chip().integer(constant.neg()),
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
        lhs: &Scalar<'a, C, N, EccChip>,
        rhs: &Scalar<'a, C, N, EccChip>,
    ) -> Scalar<'a, C, N, EccChip> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs * rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => self
                .scalar_chip()
                .mul_constant(
                    &mut self.ctx_mut(),
                    assigned,
                    &self.scalar_chip().integer(*constant),
                )
                .map(Value::Assigned)
                .unwrap(),
            (Value::Assigned(lhs), Value::Assigned(rhs)) => {
                IntegerInstructions::mul(self.scalar_chip().deref(), &mut self.ctx_mut(), lhs, rhs)
                    .map(Value::Assigned)
                    .unwrap()
            }
        };
        self.scalar(output)
    }

    fn neg(self: &Rc<Self>, scalar: &Scalar<'a, C, N, EccChip>) -> Scalar<'a, C, N, EccChip> {
        let output = match &scalar.value {
            Value::Constant(constant) => Value::Constant(constant.neg()),
            Value::Assigned(assigned) => {
                IntegerInstructions::neg(self.scalar_chip().deref(), &mut self.ctx_mut(), assigned)
                    .map(Value::Assigned)
                    .unwrap()
            }
        };
        self.scalar(output)
    }

    fn invert(self: &Rc<Self>, scalar: &Scalar<'a, C, N, EccChip>) -> Scalar<'a, C, N, EccChip> {
        let output = match &scalar.value {
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
impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>>
    Halo2Loader<'a, C, N, EccChip>
{
    fn start_row_metering(self: &Rc<Self>, identifier: &str) {
        self.row_meterings
            .borrow_mut()
            .push((identifier.to_string(), self.ctx.borrow().offset()))
    }

    fn end_row_metering(self: &Rc<Self>) {
        let mut row_meterings = self.row_meterings.borrow_mut();
        let (_, row) = row_meterings.last_mut().unwrap();
        *row = self.ctx.borrow().offset() - *row;
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

#[derive(Clone)]
pub struct Scalar<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> {
    loader: Rc<Halo2Loader<'a, C, N, EccChip>>,
    index: usize,
    value: Value<C::Scalar, EccChip::AssignedScalar>,
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Scalar<'a, C, N, EccChip> {
    pub fn loader(&self) -> &Rc<Halo2Loader<'a, C, N, EccChip>> {
        &self.loader
    }

    pub(crate) fn assigned(&self) -> EccChip::AssignedScalar {
        match &self.value {
            Value::Constant(constant) => self.loader.assign_const_scalar(*constant).assigned(),
            Value::Assigned(assigned) => assigned.clone(),
        }
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> PartialEq
    for Scalar<'a, C, N, EccChip>
{
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> LoadedScalar<C::Scalar>
    for Scalar<'a, C, N, EccChip>
{
    type Loader = Rc<Halo2Loader<'a, C, N, EccChip>>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Debug
    for Scalar<'a, C, N, EccChip>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar")
            .field("value", &self.value)
            .finish()
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> FieldOps
    for Scalar<'a, C, N, EccChip>
{
    fn invert(&self) -> Option<Self> {
        Some(self.loader.invert(self))
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Add
    for Scalar<'a, C, N, EccChip>
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Halo2Loader::add(&self.loader, &self, &rhs)
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Sub
    for Scalar<'a, C, N, EccChip>
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Halo2Loader::sub(&self.loader, &self, &rhs)
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Mul
    for Scalar<'a, C, N, EccChip>
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Halo2Loader::mul(&self.loader, &self, &rhs)
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Neg
    for Scalar<'a, C, N, EccChip>
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Halo2Loader::neg(&self.loader, &self)
    }
}

impl<'a, 'b, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Add<&'b Self>
    for Scalar<'a, C, N, EccChip>
{
    type Output = Self;

    fn add(self, rhs: &'b Self) -> Self::Output {
        Halo2Loader::add(&self.loader, &self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Sub<&'b Self>
    for Scalar<'a, C, N, EccChip>
{
    type Output = Self;

    fn sub(self, rhs: &'b Self) -> Self::Output {
        Halo2Loader::sub(&self.loader, &self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Mul<&'b Self>
    for Scalar<'a, C, N, EccChip>
{
    type Output = Self;

    fn mul(self, rhs: &'b Self) -> Self::Output {
        Halo2Loader::mul(&self.loader, &self, rhs)
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> AddAssign
    for Scalar<'a, C, N, EccChip>
{
    fn add_assign(&mut self, rhs: Self) {
        *self = Halo2Loader::add(&self.loader, self, &rhs)
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> SubAssign
    for Scalar<'a, C, N, EccChip>
{
    fn sub_assign(&mut self, rhs: Self) {
        *self = Halo2Loader::sub(&self.loader, self, &rhs)
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> MulAssign
    for Scalar<'a, C, N, EccChip>
{
    fn mul_assign(&mut self, rhs: Self) {
        *self = Halo2Loader::mul(&self.loader, self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> AddAssign<&'b Self>
    for Scalar<'a, C, N, EccChip>
{
    fn add_assign(&mut self, rhs: &'b Self) {
        *self = Halo2Loader::add(&self.loader, self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> SubAssign<&'b Self>
    for Scalar<'a, C, N, EccChip>
{
    fn sub_assign(&mut self, rhs: &'b Self) {
        *self = Halo2Loader::sub(&self.loader, self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> MulAssign<&'b Self>
    for Scalar<'a, C, N, EccChip>
{
    fn mul_assign(&mut self, rhs: &'b Self) {
        *self = Halo2Loader::mul(&self.loader, self, rhs)
    }
}

#[derive(Clone)]
pub struct EcPoint<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> {
    loader: Rc<Halo2Loader<'a, C, N, EccChip>>,
    index: usize,
    assigned: EccChip::AssignedPoint,
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> EcPoint<'a, C, N, EccChip> {
    pub fn assigned(&self) -> EccChip::AssignedPoint {
        self.assigned.clone()
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> PartialEq
    for EcPoint<'a, C, N, EccChip>
{
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> LoadedEcPoint<C>
    for EcPoint<'a, C, N, EccChip>
{
    type Loader = Rc<Halo2Loader<'a, C, N, EccChip>>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }

    fn multi_scalar_multiplication(
        pairs: impl IntoIterator<Item = (Scalar<'a, C, N, EccChip>, Self)>,
    ) -> Self {
        let pairs = pairs.into_iter().collect_vec();
        let loader = &pairs[0].0.loader;

        let (non_scaled, scaled) = pairs.iter().fold(
            (Vec::new(), Vec::new()),
            |(mut non_scaled, mut scaled), (scalar, ec_point)| {
                if matches!(scalar.value, Value::Constant(constant) if constant == C::Scalar::one())
                {
                    non_scaled.push(ec_point.assigned());
                } else {
                    scaled.push((ec_point.assigned(), scalar.assigned()))
                }
                (non_scaled, scaled)
            },
        );

        let output = iter::empty()
            .chain(if scaled.is_empty() {
                None
            } else {
                let aux_generator = C::CurveExt::random(OsRng).to_affine();
                loader
                    .ecc_chip
                    .borrow_mut()
                    .assign_aux_generator(
                        &mut loader.ctx.borrow_mut(),
                        circuit::Value::known(aux_generator),
                    )
                    .unwrap();
                loader
                    .ecc_chip
                    .borrow_mut()
                    .assign_aux(&mut loader.ctx.borrow_mut(), WINDOW_SIZE, scaled.len())
                    .unwrap();
                Some(
                    loader
                        .ecc_chip
                        .borrow()
                        .mul_batch_1d_horizontal(&mut loader.ctx.borrow_mut(), scaled, WINDOW_SIZE)
                        .unwrap(),
                )
            })
            .chain(non_scaled)
            .reduce(|acc, ec_point| {
                EccInstructions::add(
                    loader.ecc_chip().deref(),
                    &mut loader.ctx.borrow_mut(),
                    &acc,
                    &ec_point,
                )
                .unwrap()
            })
            .map(|output| {
                loader
                    .ecc_chip()
                    .normalize(&mut loader.ctx_mut(), &output)
                    .unwrap()
            })
            .unwrap();

        loader.ec_point(output)
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Debug
    for EcPoint<'a, C, N, EccChip>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPoint")
            .field("index", &self.index)
            .field("assigned", &self.assigned)
            .finish()
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> ScalarLoader<C::Scalar>
    for Rc<Halo2Loader<'a, C, N, EccChip>>
{
    type LoadedScalar = Scalar<'a, C, N, EccChip>;

    fn load_const(&self, value: &C::Scalar) -> Scalar<'a, C, N, EccChip> {
        self.scalar(Value::Constant(*value))
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> EcPointLoader<C>
    for Rc<Halo2Loader<'a, C, N, EccChip>>
{
    type LoadedEcPoint = EcPoint<'a, C, N, EccChip>;

    fn ec_point_load_const(&self, ec_point: &C) -> EcPoint<'a, C, N, EccChip> {
        self.assign_const_ec_point(*ec_point)
    }
}

impl<'a, C: CurveAffine, N: FieldExt, EccChip: EccInstructions<C, N>> Loader<C>
    for Rc<Halo2Loader<'a, C, N, EccChip>>
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
