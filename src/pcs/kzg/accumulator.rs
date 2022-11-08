use crate::{loader::Loader, util::arithmetic::CurveAffine};
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct KzgAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub lhs: L::LoadedEcPoint,
    pub rhs: L::LoadedEcPoint,
}

impl<C, L> KzgAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub fn new(lhs: L::LoadedEcPoint, rhs: L::LoadedEcPoint) -> Self {
        Self { lhs, rhs }
    }
}

/// `AccumulatorEncoding` that encodes `Accumulator` into limbs.
///
/// Since in circuit everything are in scalar field, but `Accumulator` might contain base field elements, so we split them into limbs.
/// The const generic `LIMBS` and `BITS` respectively represents how many limbs
/// a base field element are split into and how many bits each limbs could have.
#[derive(Clone, Debug)]
pub struct LimbsEncoding<const LIMBS: usize, const BITS: usize>;

mod native {
    use crate::{
        loader::native::NativeLoader,
        pcs::{
            kzg::{KzgAccumulator, LimbsEncoding},
            AccumulatorEncoding, PolynomialCommitmentScheme,
        },
        util::{
            arithmetic::{fe_from_limbs, CurveAffine},
            Itertools,
        },
        Error,
    };

    impl<C, PCS, const LIMBS: usize, const BITS: usize> AccumulatorEncoding<C, NativeLoader, PCS>
        for LimbsEncoding<LIMBS, BITS>
    where
        C: CurveAffine,
        PCS: PolynomialCommitmentScheme<
            C,
            NativeLoader,
            Accumulator = KzgAccumulator<C, NativeLoader>,
        >,
    {
        fn from_repr(limbs: &[&C::Scalar]) -> Result<PCS::Accumulator, Error> {
            assert_eq!(limbs.len(), 4 * LIMBS);

            let [lhs_x, lhs_y, rhs_x, rhs_y]: [_; 4] = limbs
                .chunks(LIMBS)
                .into_iter()
                .map(|limbs| {
                    fe_from_limbs::<_, _, LIMBS, BITS>(
                        limbs
                            .iter()
                            .map(|limb| **limb)
                            .collect_vec()
                            .try_into()
                            .unwrap(),
                    )
                })
                .collect_vec()
                .try_into()
                .unwrap();
            let accumulator = KzgAccumulator::new(
                C::from_xy(lhs_x, lhs_y).unwrap(),
                C::from_xy(rhs_x, rhs_y).unwrap(),
            );

            Ok(accumulator)
        }
    }
}

#[cfg(feature = "loader_evm")]
mod evm {
    use crate::{
        loader::evm::{EvmLoader, Scalar},
        pcs::{
            kzg::{KzgAccumulator, LimbsEncoding},
            AccumulatorEncoding, PolynomialCommitmentScheme,
        },
        util::{
            arithmetic::{CurveAffine, PrimeField},
            Itertools,
        },
        Error,
    };
    use std::rc::Rc;

    impl<C, PCS, const LIMBS: usize, const BITS: usize> AccumulatorEncoding<C, Rc<EvmLoader>, PCS>
        for LimbsEncoding<LIMBS, BITS>
    where
        C: CurveAffine,
        C::Scalar: PrimeField<Repr = [u8; 0x20]>,
        PCS: PolynomialCommitmentScheme<
            C,
            Rc<EvmLoader>,
            Accumulator = KzgAccumulator<C, Rc<EvmLoader>>,
        >,
    {
        fn from_repr(limbs: &[&Scalar]) -> Result<PCS::Accumulator, Error> {
            assert_eq!(limbs.len(), 4 * LIMBS);

            let loader = limbs[0].loader();

            let [lhs_x, lhs_y, rhs_x, rhs_y]: [[_; LIMBS]; 4] = limbs
                .chunks(LIMBS)
                .into_iter()
                .map(|limbs| limbs.to_vec().try_into().unwrap())
                .collect_vec()
                .try_into()
                .unwrap();
            let accumulator = KzgAccumulator::new(
                loader.ec_point_from_limbs::<LIMBS, BITS>(lhs_x, lhs_y),
                loader.ec_point_from_limbs::<LIMBS, BITS>(rhs_x, rhs_y),
            );

            Ok(accumulator)
        }
    }
}

#[cfg(feature = "loader_halo2")]
pub use halo2::LimbsEncodingInstructions;

#[cfg(feature = "loader_halo2")]
mod halo2 {
    use crate::{
        loader::halo2::{EccInstructions, Halo2Loader, Scalar, Valuetools},
        pcs::{
            kzg::{KzgAccumulator, LimbsEncoding},
            AccumulatorEncoding, PolynomialCommitmentScheme,
        },
        util::{
            arithmetic::{fe_from_limbs, CurveAffine},
            Itertools,
        },
        Error,
    };
    use halo2_proofs::{circuit::Value, plonk};
    use std::{iter, ops::Deref, rc::Rc};

    fn ec_point_from_limbs<C: CurveAffine, const LIMBS: usize, const BITS: usize>(
        limbs: &[Value<&C::Scalar>],
    ) -> Value<C> {
        assert_eq!(limbs.len(), 2 * LIMBS);

        let [x, y] = [&limbs[..LIMBS], &limbs[LIMBS..]].map(|limbs| {
            limbs
                .iter()
                .cloned()
                .fold_zipped(Vec::new(), |mut acc, limb| {
                    acc.push(*limb);
                    acc
                })
                .map(|limbs| fe_from_limbs::<_, _, LIMBS, BITS>(limbs.try_into().unwrap()))
        });

        x.zip(y).map(|(x, y)| C::from_xy(x, y).unwrap())
    }

    pub trait LimbsEncodingInstructions<'a, C: CurveAffine, const LIMBS: usize, const BITS: usize>:
        EccInstructions<'a, C>
    {
        fn assign_ec_point_from_limbs(
            &self,
            ctx: &mut Self::Context,
            limbs: &[impl Deref<Target = Self::AssignedScalar>],
        ) -> Result<Self::AssignedEcPoint, plonk::Error>;

        fn assign_ec_point_to_limbs(
            &self,
            ctx: &mut Self::Context,
            ec_point: impl Deref<Target = Self::AssignedEcPoint>,
        ) -> Result<Vec<Self::AssignedCell>, plonk::Error>;
    }

    impl<'a, C, PCS, EccChip, const LIMBS: usize, const BITS: usize>
        AccumulatorEncoding<C, Rc<Halo2Loader<'a, C, EccChip>>, PCS> for LimbsEncoding<LIMBS, BITS>
    where
        C: CurveAffine,
        PCS: PolynomialCommitmentScheme<
            C,
            Rc<Halo2Loader<'a, C, EccChip>>,
            Accumulator = KzgAccumulator<C, Rc<Halo2Loader<'a, C, EccChip>>>,
        >,
        EccChip: LimbsEncodingInstructions<'a, C, LIMBS, BITS>,
    {
        fn from_repr(limbs: &[&Scalar<'a, C, EccChip>]) -> Result<PCS::Accumulator, Error> {
            assert_eq!(limbs.len(), 4 * LIMBS);

            let loader = limbs[0].loader();

            let [lhs, rhs] = [&limbs[..2 * LIMBS], &limbs[2 * LIMBS..]].map(|limbs| {
                let assigned = loader
                    .ecc_chip()
                    .assign_ec_point_from_limbs(
                        &mut loader.ctx_mut(),
                        &limbs.iter().map(|limb| limb.assigned()).collect_vec(),
                    )
                    .unwrap();
                loader.ec_point_from_assigned(assigned)
            });

            Ok(KzgAccumulator::new(lhs, rhs))
        }
    }

    mod halo2_wrong {
        use super::*;
        use halo2_wrong_ecc::BaseFieldEccChip;

        impl<'a, C: CurveAffine, const LIMBS: usize, const BITS: usize>
            LimbsEncodingInstructions<'a, C, LIMBS, BITS> for BaseFieldEccChip<C, LIMBS, BITS>
        {
            fn assign_ec_point_from_limbs(
                &self,
                ctx: &mut Self::Context,
                limbs: &[impl Deref<Target = Self::AssignedScalar>],
            ) -> Result<Self::AssignedEcPoint, plonk::Error> {
                assert_eq!(limbs.len(), 2 * LIMBS);

                let ec_point = self.assign_point(
                    ctx,
                    ec_point_from_limbs::<_, LIMBS, BITS>(
                        &limbs.iter().map(|limb| limb.value()).collect_vec(),
                    ),
                )?;

                for (src, dst) in limbs.iter().zip_eq(
                    iter::empty()
                        .chain(ec_point.x().limbs())
                        .chain(ec_point.y().limbs()),
                ) {
                    ctx.constrain_equal(src.cell(), dst.as_ref().cell())?;
                }

                Ok(ec_point)
            }

            fn assign_ec_point_to_limbs(
                &self,
                _: &mut Self::Context,
                ec_point: impl Deref<Target = Self::AssignedEcPoint>,
            ) -> Result<Vec<Self::AssignedCell>, plonk::Error> {
                Ok(iter::empty()
                    .chain(ec_point.x().limbs())
                    .chain(ec_point.y().limbs())
                    .map(|limb| limb.as_ref())
                    .cloned()
                    .collect())
            }
        }
    }
}
