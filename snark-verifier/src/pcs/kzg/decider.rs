use crate::{pcs::kzg::KzgSuccinctVerifyingKey, util::arithmetic::MultiMillerLoop};
use std::marker::PhantomData;

/// KZG deciding key.
#[derive(Debug, Clone, Copy)]
pub struct KzgDecidingKey<M: MultiMillerLoop> {
    /// KZG succinct verifying key.
    pub svk: KzgSuccinctVerifyingKey<M::G1Affine>,
    /// Generator on G2.
    pub g2: M::G2Affine,
    /// Generator to the trusted-setup secret on G2.
    pub s_g2: M::G2Affine,
    _marker: PhantomData<M>,
}

impl<M: MultiMillerLoop> KzgDecidingKey<M> {
    /// Initialize a [`KzgDecidingKey`]
    pub fn new(
        svk: impl Into<KzgSuccinctVerifyingKey<M::G1Affine>>,
        g2: M::G2Affine,
        s_g2: M::G2Affine,
    ) -> Self {
        Self {
            svk: svk.into(),
            g2,
            s_g2,
            _marker: PhantomData,
        }
    }
}

impl<M: MultiMillerLoop> From<(M::G1Affine, M::G2Affine, M::G2Affine)> for KzgDecidingKey<M> {
    fn from((g1, g2, s_g2): (M::G1Affine, M::G2Affine, M::G2Affine)) -> KzgDecidingKey<M> {
        KzgDecidingKey::new(g1, g2, s_g2)
    }
}

impl<M: MultiMillerLoop> AsRef<KzgSuccinctVerifyingKey<M::G1Affine>> for KzgDecidingKey<M> {
    fn as_ref(&self) -> &KzgSuccinctVerifyingKey<M::G1Affine> {
        &self.svk
    }
}

mod native {
    use crate::{
        loader::native::NativeLoader,
        pcs::{
            kzg::{KzgAccumulator, KzgAs, KzgDecidingKey},
            AccumulationDecider,
        },
        util::{
            arithmetic::{Group, MillerLoopResult, MultiMillerLoop, PrimeField},
            Itertools,
        },
        Error,
    };
    use std::fmt::Debug;

    impl<M, MOS> AccumulationDecider<M::G1Affine, NativeLoader> for KzgAs<M, MOS>
    where
        M: MultiMillerLoop,
        M::Scalar: PrimeField,
        MOS: Clone + Debug,
    {
        type DecidingKey = KzgDecidingKey<M>;

        fn decide(
            dk: &Self::DecidingKey,
            KzgAccumulator { lhs, rhs }: KzgAccumulator<M::G1Affine, NativeLoader>,
        ) -> Result<(), Error> {
            let terms = [(&lhs, &dk.g2.into()), (&rhs, &(-dk.s_g2).into())];
            bool::from(
                M::multi_miller_loop(&terms)
                    .final_exponentiation()
                    .is_identity(),
            )
            .then_some(())
            .ok_or_else(|| Error::AssertionFailure("e(lhs, g2)·e(rhs, -s_g2) == O".to_string()))
        }

        fn decide_all(
            dk: &Self::DecidingKey,
            accumulators: Vec<KzgAccumulator<M::G1Affine, NativeLoader>>,
        ) -> Result<(), Error> {
            accumulators
                .into_iter()
                .map(|accumulator| Self::decide(dk, accumulator))
                .try_collect::<_, Vec<_>, _>()?;
            Ok(())
        }
    }
}

#[cfg(feature = "loader_evm")]
mod evm {
    use crate::{
        loader::{
            evm::{loader::Value, EvmLoader, U256},
            LoadedScalar,
        },
        pcs::{
            kzg::{KzgAccumulator, KzgAs, KzgDecidingKey},
            AccumulationDecider,
        },
        util::{
            arithmetic::{CurveAffine, MultiMillerLoop, PrimeField},
            msm::Msm,
        },
        Error,
    };
    use std::{fmt::Debug, rc::Rc};

    impl<M, MOS> AccumulationDecider<M::G1Affine, Rc<EvmLoader>> for KzgAs<M, MOS>
    where
        M: MultiMillerLoop,
        M::Scalar: PrimeField<Repr = [u8; 0x20]>,
        MOS: Clone + Debug,
    {
        type DecidingKey = KzgDecidingKey<M>;

        fn decide(
            dk: &Self::DecidingKey,
            KzgAccumulator { lhs, rhs }: KzgAccumulator<M::G1Affine, Rc<EvmLoader>>,
        ) -> Result<(), Error> {
            let loader = lhs.loader();
            let [g2, minus_s_g2] = [dk.g2, -dk.s_g2].map(|ec_point| {
                let coordinates = ec_point.coordinates().unwrap();
                let x = coordinates.x().to_repr();
                let y = coordinates.y().to_repr();
                (
                    U256::try_from_le_slice(&x.as_ref()[32..]).unwrap(),
                    U256::try_from_le_slice(&x.as_ref()[..32]).unwrap(),
                    U256::try_from_le_slice(&y.as_ref()[32..]).unwrap(),
                    U256::try_from_le_slice(&y.as_ref()[..32]).unwrap(),
                )
            });
            loader.pairing(&lhs, g2, &rhs, minus_s_g2);
            Ok(())
        }

        fn decide_all(
            dk: &Self::DecidingKey,
            mut accumulators: Vec<KzgAccumulator<M::G1Affine, Rc<EvmLoader>>>,
        ) -> Result<(), Error> {
            assert!(!accumulators.is_empty());

            let accumulator = if accumulators.len() == 1 {
                accumulators.pop().unwrap()
            } else {
                let loader = accumulators[0].lhs.loader();
                let (lhs, rhs) = accumulators
                    .iter()
                    .map(|KzgAccumulator { lhs, rhs }| {
                        let [lhs, rhs] = [&lhs, &rhs].map(|ec_point| loader.dup_ec_point(ec_point));
                        (lhs, rhs)
                    })
                    .unzip::<_, _, Vec<_>, Vec<_>>();

                let hash_ptr = loader.keccak256(lhs[0].ptr(), lhs.len() * 0x80);
                let challenge_ptr = loader.allocate(0x20);
                let code = format!("mstore({challenge_ptr}, mod(mload({hash_ptr}), f_q))");
                loader.code_mut().runtime_append(code);
                let challenge = loader.scalar(Value::Memory(challenge_ptr));

                let powers_of_challenge = LoadedScalar::<M::Scalar>::powers(&challenge, lhs.len());
                let [lhs, rhs] = [lhs, rhs].map(|msms| {
                    msms.iter()
                        .zip(powers_of_challenge.iter())
                        .map(|(msm, power_of_challenge)| {
                            Msm::<M::G1Affine, Rc<EvmLoader>>::base(msm) * power_of_challenge
                        })
                        .sum::<Msm<_, _>>()
                        .evaluate(None)
                });

                KzgAccumulator::new(lhs, rhs)
            };

            <Self as AccumulationDecider<M::G1Affine, Rc<EvmLoader>>>::decide(dk, accumulator)
        }
    }
}
