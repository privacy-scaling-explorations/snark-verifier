use crate::{loader::Loader, util::arithmetic::CurveAffine};
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct Accumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub lhs: L::LoadedEcPoint,
    pub rhs: L::LoadedEcPoint,
}

impl<C, L> Accumulator<C, L>
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
            kzg::accumulator::{Accumulator, LimbsEncoding},
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
        PCS:
            PolynomialCommitmentScheme<C, NativeLoader, Accumulator = Accumulator<C, NativeLoader>>,
    {
        fn from_repr(limbs: Vec<C::Scalar>) -> Result<PCS::Accumulator, Error> {
            assert_eq!(limbs.len(), 4 * LIMBS);

            let [lhs_x, lhs_y, rhs_x, rhs_y]: [_; 4] = limbs
                .chunks(4)
                .into_iter()
                .map(|limbs| fe_from_limbs::<_, _, LIMBS, BITS>(limbs.try_into().unwrap()))
                .collect_vec()
                .try_into()
                .unwrap();
            let accumulator = Accumulator::new(
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
            kzg::accumulator::{Accumulator, LimbsEncoding},
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
            Accumulator = Accumulator<C, Rc<EvmLoader>>,
        >,
    {
        fn from_repr(limbs: Vec<Scalar>) -> Result<PCS::Accumulator, Error> {
            assert_eq!(limbs.len(), 4 * LIMBS);

            let loader = limbs[0].loader();

            let [lhs_x, lhs_y, rhs_x, rhs_y]: [[_; LIMBS]; 4] = limbs
                .chunks(4)
                .into_iter()
                .map(|limbs| limbs.to_vec().try_into().unwrap())
                .collect_vec()
                .try_into()
                .unwrap();
            let accumulator = Accumulator::new(
                loader.ec_point_from_limbs::<LIMBS, BITS>(lhs_x, lhs_y),
                loader.ec_point_from_limbs::<LIMBS, BITS>(rhs_x, rhs_y),
            );

            Ok(accumulator)
        }
    }
}

#[cfg(feature = "loader_halo2")]
mod halo2 {
    use crate::{
        loader::halo2::{EccInstructions, Halo2Loader, Scalar, Valuetools},
        pcs::{
            kzg::accumulator::{Accumulator, LimbsEncoding},
            AccumulatorEncoding, PolynomialCommitmentScheme,
        },
        util::{
            arithmetic::{fe_from_limbs, CurveAffine},
            Itertools,
        },
        Error,
    };
    use halo2_proofs::circuit::Value;
    use halo2_wrong_ecc::{maingate::AssignedValue, AssignedPoint};
    use std::{iter, rc::Rc};

    fn ec_point_from_assigned_limbs<C: CurveAffine, const LIMBS: usize, const BITS: usize>(
        limbs: &[AssignedValue<C::Scalar>],
    ) -> Value<C> {
        assert_eq!(limbs.len(), 2 * LIMBS);

        let [x, y] = [&limbs[..LIMBS], &limbs[LIMBS..]].map(|limbs| {
            limbs
                .iter()
                .map(|assigned| assigned.value())
                .fold_zipped(Vec::new(), |mut acc, limb| {
                    acc.push(*limb);
                    acc
                })
                .map(|limbs| fe_from_limbs::<_, _, LIMBS, BITS>(limbs.try_into().unwrap()))
        });

        x.zip(y).map(|(x, y)| C::from_xy(x, y).unwrap())
    }

    impl<'a, C, PCS, EccChip, const LIMBS: usize, const BITS: usize>
        AccumulatorEncoding<C, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>, PCS>
        for LimbsEncoding<LIMBS, BITS>
    where
        C: CurveAffine,
        PCS: PolynomialCommitmentScheme<
            C,
            Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>,
            Accumulator = Accumulator<C, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>>,
        >,
        EccChip: EccInstructions<
            C,
            C::Scalar,
            AssignedPoint = AssignedPoint<<C as CurveAffine>::Base, C::Scalar, LIMBS, BITS>,
            AssignedScalar = AssignedValue<C::Scalar>,
        >,
    {
        fn from_repr(
            limbs: Vec<Scalar<'a, C, C::Scalar, EccChip>>,
        ) -> Result<PCS::Accumulator, Error> {
            assert_eq!(limbs.len(), 4 * LIMBS);

            let loader = limbs[0].loader();

            let assigned_limbs = limbs.iter().map(|limb| limb.assigned()).collect_vec();
            let [lhs, rhs] = [&assigned_limbs[..2 * LIMBS], &assigned_limbs[2 * LIMBS..]].map(
                |assigned_limbs| {
                    let ec_point = ec_point_from_assigned_limbs::<_, LIMBS, BITS>(assigned_limbs);
                    loader.assign_ec_point(ec_point)
                },
            );

            for (src, dst) in assigned_limbs.iter().zip(
                iter::empty()
                    .chain(lhs.assigned().x().limbs())
                    .chain(lhs.assigned().y().limbs())
                    .chain(rhs.assigned().x().limbs())
                    .chain(rhs.assigned().y().limbs()),
            ) {
                loader
                    .ctx_mut()
                    .constrain_equal(src.cell(), dst.as_ref().cell())
                    .unwrap();
            }
            let accumulator = Accumulator::new(lhs, rhs);

            Ok(accumulator)
        }
    }
}
