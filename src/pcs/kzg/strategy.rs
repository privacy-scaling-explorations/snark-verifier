use std::marker::PhantomData;

/// `AccumulationStrategy` that only implements `finalize`.
#[derive(Clone, Debug)]
pub struct KzgDecider<M, PCS>(PhantomData<(M, PCS)>);

/// `AccumulationStrategy` that does accumulation with KZG on the same curve.
///
/// Since in circuit everything are in scalar field, but while doing elliptic
/// curve operation we need to operate in base field, so we need to emulate
/// base field in scalar field.
/// The const generic `LIMBS` and `BITS` respectively represents how many limbs
/// a base field element are split into and how many bits each limbs could have.
#[derive(Clone, Debug)]
pub struct KzgOnSameCurve<M, PCS, const LIMBS: usize, const BITS: usize>(PhantomData<(M, PCS)>);

mod native {
    use crate::{
        loader::native::NativeLoader,
        pcs::{
            kzg::{Accumulator, KzgDecider, KzgOnSameCurve, PreAccumulator},
            AccumulationStrategy, PolynomialCommitmentScheme,
        },
        util::{
            arithmetic::{fe_from_limbs, CurveAffine, Group, MillerLoopResult, MultiMillerLoop},
            Itertools,
        },
        Error,
    };
    use std::fmt::Debug;

    impl<M, PCS> AccumulationStrategy<M::G1Affine, NativeLoader, PCS> for KzgDecider<M, PCS>
    where
        M: MultiMillerLoop + Debug,
        PCS: PolynomialCommitmentScheme<
            M::G1Affine,
            NativeLoader,
            DecidingKey = (M::G2Affine, M::G2Affine),
            PreAccumulator = PreAccumulator<M::G1Affine, NativeLoader>,
            Accumulator = Accumulator<M::G1Affine, NativeLoader>,
        >,
    {
        type Output = bool;

        fn finalize(
            &(g2, s_g2): &(M::G2Affine, M::G2Affine),
            Accumulator { lhs, rhs }: Accumulator<M::G1Affine, NativeLoader>,
        ) -> Result<bool, Error> {
            let terms = [(&lhs, &g2.into()), (&rhs, &(-s_g2).into())];
            Ok(M::multi_miller_loop(&terms)
                .final_exponentiation()
                .is_identity()
                .into())
        }
    }

    impl<M, PCS, const LIMBS: usize, const BITS: usize>
        AccumulationStrategy<M::G1Affine, NativeLoader, PCS> for KzgOnSameCurve<M, PCS, LIMBS, BITS>
    where
        M: MultiMillerLoop + Debug,
        PCS: PolynomialCommitmentScheme<
            M::G1Affine,
            NativeLoader,
            DecidingKey = (M::G2Affine, M::G2Affine),
            PreAccumulator = PreAccumulator<M::G1Affine, NativeLoader>,
            Accumulator = Accumulator<M::G1Affine, NativeLoader>,
        >,
    {
        type Output = bool;

        fn extract_accumulators(
            accumulator_indices: &[Vec<(usize, usize)>],
            instances: &[Vec<M::Scalar>],
        ) -> Result<Vec<PCS::Accumulator>, Error> {
            let accumulators = accumulator_indices
                .iter()
                .map(|indices| {
                    assert_eq!(indices.len(), 4 * LIMBS);
                    let [lhs_x, lhs_y, rhs_x, rhs_y]: [_; 4] = indices
                        .chunks(4)
                        .into_iter()
                        .map(|indices| {
                            fe_from_limbs::<_, _, LIMBS, BITS>(
                                indices
                                    .iter()
                                    .map(|index| instances[index.0][index.1])
                                    .collect_vec()
                                    .try_into()
                                    .unwrap(),
                            )
                        })
                        .collect_vec()
                        .try_into()
                        .unwrap();
                    let lhs = M::G1Affine::from_xy(lhs_x, lhs_y).unwrap();
                    let rhs = M::G1Affine::from_xy(rhs_x, rhs_y).unwrap();
                    Accumulator::new(lhs, rhs)
                })
                .collect_vec();

            Ok(accumulators)
        }

        fn finalize(
            dk: &(M::G2Affine, M::G2Affine),
            accumulator: Accumulator<M::G1Affine, NativeLoader>,
        ) -> Result<bool, Error> {
            KzgDecider::<M, PCS>::finalize(dk, accumulator)
        }
    }
}

#[cfg(feature = "loader_evm")]
mod evm {
    use crate::{
        loader::evm::{EvmLoader, Scalar},
        pcs::{
            kzg::{Accumulator, KzgDecider, KzgOnSameCurve, PreAccumulator},
            AccumulationStrategy, PolynomialCommitmentScheme,
        },
        util::{
            arithmetic::{CurveAffine, MultiMillerLoop, PrimeField},
            Itertools,
        },
        Error,
    };
    use ethereum_types::U256;
    use std::{fmt::Debug, rc::Rc};

    impl<M, PCS> AccumulationStrategy<M::G1Affine, Rc<EvmLoader>, PCS> for KzgDecider<M, PCS>
    where
        M: MultiMillerLoop + Debug,
        M::Scalar: PrimeField<Repr = [u8; 0x20]>,
        PCS: PolynomialCommitmentScheme<
            M::G1Affine,
            Rc<EvmLoader>,
            DecidingKey = (M::G2Affine, M::G2Affine),
            PreAccumulator = PreAccumulator<M::G1Affine, Rc<EvmLoader>>,
            Accumulator = Accumulator<M::G1Affine, Rc<EvmLoader>>,
        >,
    {
        type Output = ();

        fn finalize(
            &(g2, s_g2): &(M::G2Affine, M::G2Affine),
            Accumulator { lhs, rhs }: Accumulator<M::G1Affine, Rc<EvmLoader>>,
        ) -> Result<(), Error> {
            let loader = lhs.loader();
            let [g2, minus_s_g2] = [g2, -s_g2].map(|ec_point| {
                let coordinates = ec_point.coordinates().unwrap();
                let x = coordinates.x().to_repr();
                let y = coordinates.y().to_repr();
                (
                    U256::from_little_endian(&x.as_ref()[32..]),
                    U256::from_little_endian(&x.as_ref()[..32]),
                    U256::from_little_endian(&y.as_ref()[32..]),
                    U256::from_little_endian(&y.as_ref()[..32]),
                )
            });
            loader.pairing(&lhs, g2, &rhs, minus_s_g2);
            Ok(())
        }
    }

    impl<M, PCS, const LIMBS: usize, const BITS: usize>
        AccumulationStrategy<M::G1Affine, Rc<EvmLoader>, PCS>
        for KzgOnSameCurve<M, PCS, LIMBS, BITS>
    where
        M: MultiMillerLoop + Debug,
        M::Scalar: PrimeField<Repr = [u8; 0x20]>,
        PCS: PolynomialCommitmentScheme<
            M::G1Affine,
            Rc<EvmLoader>,
            DecidingKey = (M::G2Affine, M::G2Affine),
            PreAccumulator = PreAccumulator<M::G1Affine, Rc<EvmLoader>>,
            Accumulator = Accumulator<M::G1Affine, Rc<EvmLoader>>,
        >,
    {
        type Output = ();

        fn extract_accumulators(
            accumulator_indices: &[Vec<(usize, usize)>],
            instances: &[Vec<Scalar>],
        ) -> Result<Vec<PCS::Accumulator>, Error> {
            let num_instances = instances
                .iter()
                .map(|instances| instances.len())
                .collect_vec();

            let accumulators = accumulator_indices
                .iter()
                .map(|indices| {
                    assert_eq!(indices.len(), 4 * LIMBS);
                    assert!(indices
                        .iter()
                        .enumerate()
                        .all(|(idx, index)| indices[0] == (index.0, index.1 - idx)));
                    let loader = instances[0][0].loader();
                    let offset =
                        (num_instances[..indices[0].0].iter().sum::<usize>() + indices[0].1) * 0x20;
                    let lhs = loader.calldataload_ec_point_from_limbs::<LIMBS, BITS>(offset);
                    let rhs =
                        loader.calldataload_ec_point_from_limbs::<LIMBS, BITS>(offset + 0x100);
                    Accumulator::new(lhs, rhs)
                })
                .collect_vec();

            Ok(accumulators)
        }

        fn finalize(
            dk: &(M::G2Affine, M::G2Affine),
            accumulator: Accumulator<M::G1Affine, Rc<EvmLoader>>,
        ) -> Result<(), Error> {
            KzgDecider::<M, PCS>::finalize(dk, accumulator)
        }
    }
}

#[cfg(feature = "loader_halo2")]
pub mod halo2 {
    use crate::{
        loader::halo2::{EccInstructions, Halo2Loader, Scalar, Valuetools},
        pcs::{
            kzg::{Accumulator, KzgOnSameCurve, PreAccumulator},
            AccumulationStrategy, PolynomialCommitmentScheme,
        },
        util::{
            arithmetic::{fe_from_limbs, CurveAffine, MultiMillerLoop},
            Itertools,
        },
        Error,
    };
    use halo2_proofs::circuit::Value;
    use halo2_wrong_ecc::{maingate::AssignedValue, AssignedPoint};
    use std::{fmt::Debug, iter, rc::Rc};

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

    impl<'a, M, EccChip, PCS, const LIMBS: usize, const BITS: usize>
        AccumulationStrategy<M::G1Affine, Rc<Halo2Loader<'a, M::G1Affine, M::Scalar, EccChip>>, PCS>
        for KzgOnSameCurve<M, PCS, LIMBS, BITS>
    where
        M: MultiMillerLoop + Debug,
        EccChip: EccInstructions<
            M::G1Affine,
            M::Scalar,
            AssignedPoint = AssignedPoint<
                <M::G1Affine as CurveAffine>::Base,
                M::Scalar,
                LIMBS,
                BITS,
            >,
            AssignedScalar = AssignedValue<M::Scalar>,
        >,
        PCS: PolynomialCommitmentScheme<
            M::G1Affine,
            Rc<Halo2Loader<'a, M::G1Affine, M::Scalar, EccChip>>,
            PreAccumulator = PreAccumulator<
                M::G1Affine,
                Rc<Halo2Loader<'a, M::G1Affine, M::Scalar, EccChip>>,
            >,
            Accumulator = Accumulator<
                M::G1Affine,
                Rc<Halo2Loader<'a, M::G1Affine, M::Scalar, EccChip>>,
            >,
        >,
    {
        type Output = ();

        fn extract_accumulators(
            accumulator_indices: &[Vec<(usize, usize)>],
            instances: &[Vec<Scalar<'a, M::G1Affine, M::Scalar, EccChip>>],
        ) -> Result<Vec<PCS::Accumulator>, Error> {
            let accumulators = accumulator_indices
                .iter()
                .map(|indices| {
                    assert_eq!(indices.len(), 4 * LIMBS);
                    let loader = instances[0][0].loader();

                    let assigned_limbs = indices
                        .iter()
                        .map(|index| instances[index.0][index.1].assigned())
                        .collect_vec();
                    let [lhs, rhs] = [&assigned_limbs[..2 * LIMBS], &assigned_limbs[2 * LIMBS..]]
                        .map(|assigned_limbs| {
                            let ec_point =
                                ec_point_from_assigned_limbs::<_, LIMBS, BITS>(assigned_limbs);
                            loader.assign_ec_point(ec_point)
                        });

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

                    Accumulator::new(lhs, rhs)
                })
                .collect_vec();

            Ok(accumulators)
        }
    }
}
