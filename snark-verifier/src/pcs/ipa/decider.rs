#[derive(Clone, Debug)]
pub struct IpaDecidingKey<C> {
    pub g: Vec<C>,
}

impl<C> IpaDecidingKey<C> {
    pub fn new(g: Vec<C>) -> Self {
        Self { g }
    }
}

impl<C> From<Vec<C>> for IpaDecidingKey<C> {
    fn from(g: Vec<C>) -> IpaDecidingKey<C> {
        IpaDecidingKey::new(g)
    }
}

mod native {
    use crate::{
        loader::native::NativeLoader,
        pcs::{
            ipa::{h_coeffs, Ipa, IpaAccumulator, IpaDecidingKey},
            Decider,
        },
        util::{
            arithmetic::{Curve, CurveAffine, Field},
            msm::multi_scalar_multiplication,
        },
    };
    use std::fmt::Debug;

    impl<C, MOS> Decider<C, NativeLoader> for Ipa<C, MOS>
    where
        C: CurveAffine,
        MOS: Clone + Debug,
    {
        type DecidingKey = IpaDecidingKey<C>;
        type Output = bool;

        fn decide(
            dk: &Self::DecidingKey,
            IpaAccumulator { u, xi }: IpaAccumulator<C, NativeLoader>,
        ) -> bool {
            let h = h_coeffs(&xi, C::Scalar::one());
            u == multi_scalar_multiplication(&h, &dk.g).to_affine()
        }

        fn decide_all(
            dk: &Self::DecidingKey,
            accumulators: Vec<IpaAccumulator<C, NativeLoader>>,
        ) -> bool {
            !accumulators
                .into_iter()
                .any(|accumulator| !Self::decide(dk, accumulator))
        }
    }
}
