pub mod ipa {
    use crate::util::arithmetic::CurveAffine;
    use halo2_proofs::{
        plonk::Error,
        poly::{
            commitment::MSM,
            ipa::{
                commitment::{IPACommitmentScheme, ParamsIPA},
                msm::MSMIPA,
                multiopen::VerifierIPA,
                strategy::GuardIPA,
            },
            VerificationStrategy,
        },
    };

    #[derive(Clone, Debug)]
    pub struct SingleStrategy<'a, C: CurveAffine> {
        msm: MSMIPA<'a, C>,
    }

    impl<'a, C: CurveAffine> VerificationStrategy<'a, IPACommitmentScheme<C>, VerifierIPA<'a, C>>
        for SingleStrategy<'a, C>
    {
        type Output = C;

        fn new(params: &'a ParamsIPA<C>) -> Self {
            SingleStrategy {
                msm: MSMIPA::new(params),
            }
        }

        fn process(
            self,
            f: impl FnOnce(MSMIPA<'a, C>) -> Result<GuardIPA<'a, C>, Error>,
        ) -> Result<Self::Output, Error> {
            let guard = f(self.msm)?;

            let g = guard.compute_g();
            let (msm, _) = guard.use_g(g);

            if msm.check() {
                Ok(g)
            } else {
                Err(Error::ConstraintSystemFailure)
            }
        }

        fn finalize(self) -> bool {
            unreachable!()
        }
    }
}
