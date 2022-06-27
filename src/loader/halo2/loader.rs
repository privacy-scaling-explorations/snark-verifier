use crate::{
    loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, ScalarLoader},
    util::{Curve, Field, FieldOps, Group},
};
use halo2_curves::CurveAffine;
use halo2_proofs::circuit;
use halo2_wrong_ecc::{
    integer::{
        rns::{Integer, Rns},
        IntegerInstructions, Range,
    },
    AssignedPoint, BaseFieldEccChip, EccConfig,
};
use halo2_wrong_maingate::{
    Assigned, AssignedValue, CombinationOptionCommon, MainGate, MainGateInstructions, RegionCtx,
    Term,
};
use rand::rngs::OsRng;
use std::{
    cell::RefCell,
    fmt::{self, Debug},
    iter,
    ops::{Add, AddAssign, Deref, Mul, MulAssign, Neg, Sub, SubAssign},
    rc::Rc,
};

const MAIN_GATE_WIDTH: usize = 5;
const WINDOW_SIZE: usize = 3;

#[derive(Clone, Debug)]
pub enum Value<T, L> {
    Constant(T),
    Assigned(L),
}

pub struct Halo2Loader<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> {
    rns: Rc<Rns<C::Base, C::Scalar, LIMBS, BITS>>,
    ecc_chip: RefCell<BaseFieldEccChip<C, LIMBS, BITS>>,
    main_gate: MainGate<C::Scalar>,
    ctx: RefCell<RegionCtx<'a, 'b, C::Scalar>>,
    num_ec_point: RefCell<usize>,
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize>
    Halo2Loader<'a, 'b, C, LIMBS, BITS>
{
    pub fn new(ecc_config: EccConfig, ctx: RegionCtx<'a, 'b, C::Scalar>) -> Self {
        let ecc_chip = BaseFieldEccChip::new(ecc_config);
        let main_gate = ecc_chip.main_gate();
        Self {
            rns: Rc::new(Rns::construct()),
            ecc_chip: RefCell::new(ecc_chip),
            main_gate,
            ctx: RefCell::new(ctx),
            num_ec_point: RefCell::new(0),
        }
    }

    pub fn rns(&self) -> Rc<Rns<C::Base, C::Scalar, LIMBS, BITS>> {
        self.rns.clone()
    }

    pub fn ecc_chip(&self) -> impl Deref<Target = BaseFieldEccChip<C, LIMBS, BITS>> + '_ {
        self.ecc_chip.borrow()
    }

    pub fn ctx(&self) -> &RefCell<RegionCtx<'a, 'b, C::Scalar>> {
        &self.ctx
    }

    pub fn assign_const_scalar(
        self: &Rc<Self>,
        scalar: C::Scalar,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let assigned = self
            .main_gate
            .assign_constant(&mut self.ctx.borrow_mut(), scalar)
            .unwrap();
        self.scalar(Value::Assigned(assigned))
    }

    pub fn assign_scalar(
        self: &Rc<Self>,
        scalar: circuit::Value<C::Scalar>,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let assigned = self
            .main_gate
            .assign_value(&mut self.ctx.borrow_mut(), &scalar.into())
            .unwrap();
        self.scalar(Value::Assigned(assigned))
    }

    pub fn scalar(
        self: &Rc<Self>,
        value: Value<C::Scalar, AssignedValue<C::Scalar>>,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        Scalar {
            loader: self.clone(),
            value,
        }
    }

    pub fn assign_const_ec_point(self: &Rc<Self>, ec_point: C) -> EcPoint<'a, 'b, C, LIMBS, BITS> {
        let assigned = self
            .ecc_chip
            .borrow()
            .assign_constant(&mut self.ctx.borrow_mut(), ec_point)
            .unwrap();
        self.ec_point(assigned)
    }

    pub fn assign_ec_point(
        self: &Rc<Self>,
        ec_point: circuit::Value<C>,
    ) -> EcPoint<'a, 'b, C, LIMBS, BITS> {
        let assigned = self
            .ecc_chip
            .borrow()
            .assign_point(&mut self.ctx.borrow_mut(), ec_point)
            .unwrap();
        self.ec_point(assigned)
    }

    pub fn assign_ec_point_from_limbs(
        self: &Rc<Self>,
        x_limbs: [AssignedValue<C::Scalar>; LIMBS],
        y_limbs: [AssignedValue<C::Scalar>; LIMBS],
    ) -> EcPoint<'a, 'b, C, LIMBS, BITS> {
        let [x, y] = [x_limbs, y_limbs]
            .map(|limbs| {
                limbs.iter().enumerate().fold(
                    circuit::Value::known([C::Scalar::zero(); LIMBS]),
                    |acc, (idx, limb)| {
                        acc.zip(limb.value()).map(|(mut acc, limb)| {
                            acc[idx] = limb;
                            acc
                        })
                    },
                )
            })
            .map(|limbs| {
                self.ecc_chip
                    .borrow()
                    .integer_chip()
                    .assign_integer(
                        &mut self.ctx().borrow_mut(),
                        limbs
                            .map(|limbs| Integer::from_limbs(&limbs, self.rns.clone()))
                            .into(),
                        Range::Remainder,
                    )
                    .unwrap()
            });

        let ec_point = AssignedPoint::new(x, y);
        self.ecc_chip()
            .assert_is_on_curve(&mut self.ctx().borrow_mut(), &ec_point)
            .unwrap();

        for (src, dst) in x_limbs.iter().chain(y_limbs.iter()).zip(
            ec_point
                .get_x()
                .limbs()
                .iter()
                .chain(ec_point.get_y().limbs().iter()),
        ) {
            self.ctx
                .borrow_mut()
                .constrain_equal(src.cell(), dst.cell())
                .unwrap();
        }

        self.ec_point(ec_point)
    }

    pub fn ec_point(
        self: &Rc<Self>,
        assigned: AssignedPoint<C::Base, C::Scalar, LIMBS, BITS>,
    ) -> EcPoint<'a, 'b, C, LIMBS, BITS> {
        let index = *self.num_ec_point.borrow();
        *self.num_ec_point.borrow_mut() += 1;
        EcPoint {
            loader: self.clone(),
            index,
            assigned,
        }
    }

    pub fn ec_point_nomalize(
        self: &Rc<Self>,
        assigned: &AssignedPoint<C::Base, C::Scalar, LIMBS, BITS>,
    ) -> AssignedPoint<C::Base, C::Scalar, LIMBS, BITS> {
        self.ecc_chip()
            .normalize(&mut self.ctx.borrow_mut(), assigned)
            .unwrap()
    }

    fn add(
        self: &Rc<Self>,
        lhs: &Scalar<'a, 'b, C, LIMBS, BITS>,
        rhs: &Scalar<'a, 'b, C, LIMBS, BITS>,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs + rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => {
                MainGateInstructions::add_constant(
                    &self.main_gate,
                    &mut self.ctx.borrow_mut(),
                    assigned,
                    *constant,
                )
                .map(Value::Assigned)
                .unwrap()
            }
            (Value::Assigned(lhs), Value::Assigned(rhs)) => {
                MainGateInstructions::add(&self.main_gate, &mut self.ctx.borrow_mut(), lhs, rhs)
                    .map(Value::Assigned)
                    .unwrap()
            }
        };
        self.scalar(output)
    }

    fn sub(
        self: &Rc<Self>,
        lhs: &Scalar<'a, 'b, C, LIMBS, BITS>,
        rhs: &Scalar<'a, 'b, C, LIMBS, BITS>,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs - rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => {
                MainGateInstructions::add_constant(
                    &self.main_gate,
                    &mut self.ctx.borrow_mut(),
                    assigned,
                    constant.neg(),
                )
                .map(Value::Assigned)
                .unwrap()
            }
            (Value::Assigned(lhs), Value::Assigned(rhs)) => {
                MainGateInstructions::sub(&self.main_gate, &mut self.ctx.borrow_mut(), lhs, rhs)
                    .map(Value::Assigned)
                    .unwrap()
            }
        };
        self.scalar(output)
    }

    fn mul(
        self: &Rc<Self>,
        lhs: &Scalar<'a, 'b, C, LIMBS, BITS>,
        rhs: &Scalar<'a, 'b, C, LIMBS, BITS>,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs * rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => {
                let mut terms = [(); MAIN_GATE_WIDTH].map(|_| Term::Zero);
                terms[0] = Term::Assigned(*assigned, *constant);
                terms[1] = Term::Unassigned(
                    assigned.value().map(|assigned| assigned * constant),
                    -C::Scalar::one(),
                );
                MainGateInstructions::apply(
                    &self.main_gate,
                    &mut self.ctx.borrow_mut(),
                    &terms,
                    C::Scalar::zero(),
                    CombinationOptionCommon::OneLinerAdd.into(),
                )
                .map(|[_, output, ..]| Value::Assigned(output))
                .unwrap()
            }
            (Value::Assigned(lhs), Value::Assigned(rhs)) => {
                MainGateInstructions::mul(&self.main_gate, &mut self.ctx.borrow_mut(), lhs, rhs)
                    .map(Value::Assigned)
                    .unwrap()
            }
        };
        self.scalar(output)
    }

    fn neg(
        self: &Rc<Self>,
        scalar: &Scalar<'a, 'b, C, LIMBS, BITS>,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let output = match &scalar.value {
            Value::Constant(constant) => Value::Constant(constant.neg()),
            Value::Assigned(assigned) => MainGateInstructions::neg_with_constant(
                &self.main_gate,
                &mut self.ctx.borrow_mut(),
                assigned,
                C::Scalar::zero(),
            )
            .map(Value::Assigned)
            .unwrap(),
        };
        self.scalar(output)
    }

    fn invert(
        self: &Rc<Self>,
        scalar: &Scalar<'a, 'b, C, LIMBS, BITS>,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let output = match &scalar.value {
            Value::Constant(constant) => Value::Constant(Field::invert(constant).unwrap()),
            Value::Assigned(assigned) => {
                let (inv, non_invertable) = MainGateInstructions::invert(
                    &self.main_gate,
                    &mut self.ctx.borrow_mut(),
                    assigned,
                )
                .unwrap();
                self.main_gate
                    .assert_zero(&mut self.ctx.borrow_mut(), &non_invertable.into())
                    .unwrap();
                Value::Assigned(inv)
            }
        };
        self.scalar(output)
    }
}

#[derive(Clone)]
pub struct Scalar<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> {
    loader: Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
    value: Value<C::Scalar, AssignedValue<C::Scalar>>,
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Scalar<'a, 'b, C, LIMBS, BITS> {
    pub fn assigned(&self) -> AssignedValue<C::Scalar> {
        match &self.value {
            Value::Constant(constant) => self.loader.assign_const_scalar(*constant).assigned(),
            Value::Assigned(assigned) => *assigned,
        }
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> LoadedScalar<C::Scalar>
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    type Loader = Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Debug
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar")
            .field("value", &self.value)
            .finish()
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> FieldOps
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    fn invert(&self) -> Option<Self> {
        Some((&self.loader).invert(self))
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Add
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        (&self.loader).add(&self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Sub
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        (&self.loader).sub(&self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Mul
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        (&self.loader).mul(&self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Neg
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        (&self.loader).neg(&self)
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> Add<&'c Self>
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn add(self, rhs: &'c Self) -> Self::Output {
        (&self.loader).add(&self, rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> Sub<&'c Self>
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn sub(self, rhs: &'c Self) -> Self::Output {
        (&self.loader).sub(&self, rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> Mul<&'c Self>
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn mul(self, rhs: &'c Self) -> Self::Output {
        (&self.loader).mul(&self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> AddAssign
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    fn add_assign(&mut self, rhs: Self) {
        *self = (&self.loader).add(self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> SubAssign
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    fn sub_assign(&mut self, rhs: Self) {
        *self = (&self.loader).sub(self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> MulAssign
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    fn mul_assign(&mut self, rhs: Self) {
        *self = (&self.loader).mul(self, &rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> AddAssign<&'c Self>
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    fn add_assign(&mut self, rhs: &'c Self) {
        *self = (&self.loader).add(self, rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> SubAssign<&'c Self>
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    fn sub_assign(&mut self, rhs: &'c Self) {
        *self = (&self.loader).sub(self, rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> MulAssign<&'c Self>
    for Scalar<'a, 'b, C, LIMBS, BITS>
{
    fn mul_assign(&mut self, rhs: &'c Self) {
        *self = (&self.loader).mul(self, rhs)
    }
}

#[derive(Clone)]
pub struct EcPoint<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> {
    loader: Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
    index: usize,
    assigned: AssignedPoint<C::Base, C::Scalar, LIMBS, BITS>,
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize>
    EcPoint<'a, 'b, C, LIMBS, BITS>
{
    pub fn assigned(&self) -> AssignedPoint<C::Base, C::Scalar, LIMBS, BITS> {
        self.assigned.clone()
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> PartialEq
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> LoadedEcPoint<C::CurveExt>
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    type Loader = Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }

    fn multi_scalar_multiplication(
        pairs: impl IntoIterator<Item = (Scalar<'a, 'b, C, LIMBS, BITS>, Self)>,
    ) -> Self {
        let pairs = pairs.into_iter().collect::<Vec<_>>();
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
                let aux_generator = <C as CurveAffine>::CurveExt::random(OsRng).to_affine();
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
                (loader.ecc_chip().deref())
                    .add(&mut loader.ctx.borrow_mut(), &acc, &ec_point)
                    .unwrap()
            })
            .unwrap();
        loader.ec_point(output)
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Debug
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPoint")
            .field("index", &self.index)
            .field("assigned", &self.assigned)
            .finish()
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Add
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn add(self, _: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Sub
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn sub(self, _: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> Neg
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> Add<&'c Self>
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn add(self, rhs: &'c Self) -> Self::Output {
        self + rhs.clone()
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> Sub<&'c Self>
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    type Output = Self;

    fn sub(self, rhs: &'c Self) -> Self::Output {
        self - rhs.clone()
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> AddAssign
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> SubAssign
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> AddAssign<&'c Self>
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    fn add_assign(&mut self, rhs: &'c Self) {
        *self = self.clone() + rhs
    }
}

impl<'a, 'b, 'c, C: CurveAffine, const LIMBS: usize, const BITS: usize> SubAssign<&'c Self>
    for EcPoint<'a, 'b, C, LIMBS, BITS>
{
    fn sub_assign(&mut self, rhs: &'c Self) {
        *self = self.clone() - rhs
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> ScalarLoader<C::Scalar>
    for Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>
{
    type LoadedScalar = Scalar<'a, 'b, C, LIMBS, BITS>;

    fn load_const(&self, value: &C::Scalar) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        self.scalar(Value::Constant(*value))
    }
}

impl<'a, 'b, C: CurveAffine, const LIMBS: usize, const BITS: usize> EcPointLoader<C::CurveExt>
    for Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>
{
    type LoadedEcPoint = EcPoint<'a, 'b, C, LIMBS, BITS>;

    fn ec_point_load_const(&self, ec_point: &C::CurveExt) -> EcPoint<'a, 'b, C, LIMBS, BITS> {
        self.assign_const_ec_point(ec_point.to_affine())
    }
}
