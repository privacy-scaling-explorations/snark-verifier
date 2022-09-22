mod native {
    use crate::{
        loader::native::NativeLoader,
        pcs::{
            kzg::{accumulator::Accumulator, Bdfg21, Gwc19},
            Decider,
        },
        util::arithmetic::{Group, MillerLoopResult, MultiMillerLoop},
    };

    macro_rules! impl_native_decider {
        ($pcs:ty) => {
            impl<M> Decider<M::G1Affine, NativeLoader> for $pcs
            where
                M: MultiMillerLoop,
            {
                type DecidingKey = (M::G2Affine, M::G2Affine);
                type Output = bool;

                fn decide(
                    &(g2, s_g2): &Self::DecidingKey,
                    accumulator: Accumulator<M::G1Affine, NativeLoader>,
                ) -> bool {
                    let terms = [
                        (&accumulator.lhs, &g2.into()),
                        (&accumulator.rhs, &(-s_g2).into()),
                    ];
                    M::multi_miller_loop(&terms)
                        .final_exponentiation()
                        .is_identity()
                        .into()
                }

                fn decide_all(
                    dk: &Self::DecidingKey,
                    accumulators: Vec<Accumulator<M::G1Affine, NativeLoader>>,
                ) -> bool {
                    !accumulators
                        .into_iter()
                        .any(|accumulator| !Self::decide(dk, accumulator))
                }
            }
        };
    }

    impl_native_decider!(Gwc19<M>);
    impl_native_decider!(Bdfg21<M>);
}

#[cfg(feature = "loader_evm")]
mod evm {
    use crate::{
        loader::{
            evm::{loader::Value, EvmLoader},
            LoadedScalar,
        },
        pcs::{
            kzg::{Accumulator, Bdfg21, Gwc19},
            Decider,
        },
        util::{
            arithmetic::{CurveAffine, MultiMillerLoop, PrimeField},
            msm::Msm,
        },
    };
    use ethereum_types::U256;
    use std::rc::Rc;

    macro_rules! impl_evm_decider {
        ($pcs:ty) => {
            impl<M> Decider<M::G1Affine, Rc<EvmLoader>> for $pcs
            where
                M: MultiMillerLoop,
                M::Scalar: PrimeField<Repr = [u8; 0x20]>,
            {
                type DecidingKey = (M::G2Affine, M::G2Affine);
                type Output = ();

                fn decide(
                    &(g2, s_g2): &Self::DecidingKey,
                    accumulator: Accumulator<M::G1Affine, Rc<EvmLoader>>,
                ) {
                    let loader = accumulator.lhs.loader();
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
                    loader.pairing(&accumulator.lhs, g2, &accumulator.rhs, minus_s_g2);
                }

                fn decide_all(
                    dk: &Self::DecidingKey,
                    mut accumulators: Vec<Accumulator<M::G1Affine, Rc<EvmLoader>>>,
                ) {
                    assert!(accumulators.len() > 0);

                    let accumulator = if accumulators.len() == 1 {
                        accumulators.pop().unwrap()
                    } else {
                        let loader = accumulators[0].lhs.loader();
                        let (lhs, rhs) = accumulators
                            .iter()
                            .map(|accumulator| {
                                let [lhs, rhs] = [&accumulator.lhs, &accumulator.rhs]
                                    .map(|ec_point| loader.dup_ec_point(ec_point));
                                (lhs, rhs)
                            })
                            .unzip::<_, _, Vec<_>, Vec<_>>();

                        let hash_ptr = loader.keccak256(lhs[0].ptr(), lhs.len() * 0x80);
                        let challenge_ptr = loader.allocate(0x20);
                        loader
                            .code_mut()
                            .push(loader.scalar_modulus())
                            .push(hash_ptr)
                            .mload()
                            .r#mod()
                            .push(challenge_ptr)
                            .mstore();
                        let challenge = loader.scalar(Value::Memory(challenge_ptr));

                        let powers_of_challenge =
                            LoadedScalar::<M::Scalar>::powers(&challenge, lhs.len());
                        let [lhs, rhs] = [lhs, rhs].map(|msms| {
                            msms.into_iter()
                                .zip(powers_of_challenge.iter())
                                .map(|(msm, power_of_challenge)| {
                                    Msm::<M::G1Affine, Rc<EvmLoader>>::base(msm)
                                        * power_of_challenge
                                })
                                .sum::<Msm<_, _>>()
                                .evaluate(None)
                        });

                        Accumulator::new(lhs, rhs)
                    };

                    Self::decide(dk, accumulator)
                }
            }
        };
    }

    impl_evm_decider!(Gwc19<M>);
    impl_evm_decider!(Bdfg21<M>);
}
