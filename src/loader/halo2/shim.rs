use halo2_curves::{CurveAffine, FieldExt};
use halo2_proofs::{circuit::Value, plonk::Error};
use halo2_wrong_ecc::{
    maingate::{
        AssignedValue, CombinationOptionCommon, MainGate, MainGateInstructions, RegionCtx, Term,
    },
    AssignedPoint, BaseFieldEccChip,
};
use std::fmt::Debug;

// TODO: Use `IntegerInstructions` in `halo2_wrong` when ecc chips are refactored to take it.
pub trait IntegerInstructions<W: FieldExt, N: FieldExt>: Clone + Debug {
    type Integer: Clone + Debug;
    type AssignedInteger: Clone + Debug;

    fn integer(&self, fe: W) -> Self::Integer;

    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        integer: Value<Self::Integer>,
    ) -> Result<Self::AssignedInteger, Error>;

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        integer: W,
    ) -> Result<Self::AssignedInteger, Error>;

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::Integer,
    ) -> Result<Self::AssignedInteger, Error>;

    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    fn mul_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
        b: &Self::Integer,
    ) -> Result<Self::AssignedInteger, Error>;

    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;
}

pub trait EccInstructions<C: CurveAffine, N: FieldExt>: Clone + Debug {
    type ScalarChip: IntegerInstructions<
        C::Scalar,
        N,
        Integer = Self::Scalar,
        AssignedInteger = Self::AssignedScalar,
    >;
    type AssignedPoint: Clone + Debug;
    type Scalar: Clone + Debug;
    type AssignedScalar: Clone + Debug;

    fn scalar_chip(&self) -> &Self::ScalarChip;

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: C,
    ) -> Result<Self::AssignedPoint, Error>;

    fn assign_point(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: Value<C>,
    ) -> Result<Self::AssignedPoint, Error>;

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p0: &Self::AssignedPoint,
        p1: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error>;

    fn assign_aux_generator(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        aux_generator: Value<C>,
    ) -> Result<(), Error>;

    fn assign_aux(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        window_size: usize,
        number_of_pairs: usize,
    ) -> Result<(), Error>;

    fn mul_batch_1d_horizontal(
        &self,
        region: &mut RegionCtx<'_, N>,
        pairs: Vec<(Self::AssignedPoint, Self::AssignedScalar)>,
        window_size: usize,
    ) -> Result<Self::AssignedPoint, Error>;

    fn normalize(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error>;
}

impl<F: FieldExt> IntegerInstructions<F, F> for MainGate<F> {
    type Integer = F;
    type AssignedInteger = AssignedValue<F>;

    fn integer(&self, fe: F) -> Self::Integer {
        fe
    }

    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        integer: Value<Self::Integer>,
    ) -> Result<Self::AssignedInteger, Error> {
        self.assign_value(ctx, integer)
    }

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        integer: F,
    ) -> Result<Self::AssignedInteger, Error> {
        MainGateInstructions::assign_constant(self, ctx, integer)
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error> {
        MainGateInstructions::add(self, ctx, a, b)
    }

    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &Self::AssignedInteger,
        b: &Self::Integer,
    ) -> Result<Self::AssignedInteger, Error> {
        MainGateInstructions::add_constant(self, ctx, a, *b)
    }

    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error> {
        MainGateInstructions::sub(self, ctx, a, b)
    }

    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error> {
        MainGateInstructions::neg_with_constant(self, ctx, a, F::zero())
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &Self::AssignedInteger,
        b: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error> {
        MainGateInstructions::mul(self, ctx, a, b)
    }

    fn mul_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &Self::AssignedInteger,
        b: &Self::Integer,
    ) -> Result<Self::AssignedInteger, Error> {
        Ok(MainGateInstructions::apply(
            self,
            ctx,
            [
                Term::Assigned(a, *b),
                Term::unassigned_to_sub(a.value().map(|a| *a * b)),
            ],
            F::zero(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?
        .swap_remove(1))
    }

    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error> {
        MainGateInstructions::invert_unsafe(self, ctx, a)
    }
}

// TODO: Use `EccInstructions` in `halo2_wrong` when it's implemented.
impl<C: CurveAffine, const LIMBS: usize, const BITS: usize> EccInstructions<C, C::Scalar>
    for BaseFieldEccChip<C, LIMBS, BITS>
{
    type ScalarChip = MainGate<C::Scalar>;
    type AssignedPoint = AssignedPoint<C::Base, C::Scalar, LIMBS, BITS>;
    type Scalar = C::Scalar;
    type AssignedScalar = AssignedValue<C::Scalar>;

    fn scalar_chip(&self) -> &Self::ScalarChip {
        self.main_gate()
    }

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: C,
    ) -> Result<Self::AssignedPoint, Error> {
        self.assign_constant(ctx, point)
    }

    fn assign_point(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: Value<C>,
    ) -> Result<Self::AssignedPoint, Error> {
        self.assign_point(ctx, point)
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        p0: &Self::AssignedPoint,
        p1: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        self.add(ctx, p0, p1)
    }

    fn assign_aux_generator(
        &mut self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        aux_generator: Value<C>,
    ) -> Result<(), Error> {
        self.assign_aux_generator(ctx, aux_generator)
    }

    fn assign_aux(
        &mut self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        window_size: usize,
        number_of_pairs: usize,
    ) -> Result<(), Error> {
        self.assign_aux(ctx, window_size, number_of_pairs)
    }

    fn mul_batch_1d_horizontal(
        &self,
        region: &mut RegionCtx<'_, C::Scalar>,
        pairs: Vec<(Self::AssignedPoint, Self::AssignedScalar)>,
        window_size: usize,
    ) -> Result<Self::AssignedPoint, Error> {
        self.mul_batch_1d_horizontal(region, pairs, window_size)
    }

    fn normalize(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Error> {
        self.normalize(ctx, point)
    }
}
