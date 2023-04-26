use crate::{pcs::ipa::IpaSuccinctVerifyingKey, util::arithmetic::CurveAffine};

/// Inner product argument deciding key.
#[derive(Clone, Debug)]
pub struct IpaDecidingKey<C: CurveAffine> {
    svk: IpaSuccinctVerifyingKey<C>,
    /// Committing key.
    g: Vec<C>,
}

impl<C: CurveAffine> IpaDecidingKey<C> {
    /// Initialize an [`IpaDecidingKey`].
    pub fn new(svk: IpaSuccinctVerifyingKey<C>, g: Vec<C>) -> Self {
        Self { svk, g }
    }
}

impl<C: CurveAffine> AsRef<IpaSuccinctVerifyingKey<C>> for IpaDecidingKey<C> {
    fn as_ref(&self) -> &IpaSuccinctVerifyingKey<C> {
        &self.svk
    }
}

mod native {
    use crate::{
        loader::native::NativeLoader,
        pcs::{
            ipa::{h_coeffs, IpaAccumulator, IpaAs, IpaDecidingKey},
            AccumulationDecider,
        },
        util::{
            arithmetic::{Curve, CurveAffine, Field},
            msm::multi_scalar_multiplication,
            Itertools,
        },
        Error,
    };
    use std::fmt::Debug;

    impl<C, MOS> AccumulationDecider<C, NativeLoader> for IpaAs<C, MOS>
    where
        C: CurveAffine,
        MOS: Clone + Debug,
    {
        type DecidingKey = IpaDecidingKey<C>;

        fn decide(
            dk: &Self::DecidingKey,
            IpaAccumulator { u, xi }: IpaAccumulator<C, NativeLoader>,
        ) -> Result<(), Error> {
            let h = h_coeffs(&xi, C::Scalar::ONE);
            (u == multi_scalar_multiplication(&h, &dk.g).to_affine())
                .then_some(())
                .ok_or_else(|| Error::AssertionFailure("U == commit(G, h)".to_string()))
        }

        fn decide_all(
            dk: &Self::DecidingKey,
            accumulators: Vec<IpaAccumulator<C, NativeLoader>>,
        ) -> Result<(), Error> {
            accumulators
                .into_iter()
                .map(|accumulator| Self::decide(dk, accumulator))
                .try_collect::<_, Vec<_>, _>()?;
            Ok(())
        }
    }
}
