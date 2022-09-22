use crate::{
    loader::{native::NativeLoader, LoadedScalar, Loader},
    pcs::{
        kzg::Accumulator, AccumulationScheme, AccumulationSchemeProver, PolynomialCommitmentScheme,
    },
    util::{
        arithmetic::{Curve, CurveAffine, Field},
        msm::Msm,
        transcript::{TranscriptRead, TranscriptWrite},
    },
    Error,
};
use rand::Rng;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct KzgAccumulation<PCS>(PhantomData<PCS>);

impl<C, L, PCS> AccumulationScheme<C, L, PCS> for KzgAccumulation<PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L, Accumulator = Accumulator<C, L>>,
{
    type VerifyingKey = ();
    type Proof = KzgAccumulationProof<C, L, PCS>;

    fn read_proof<T>(
        zk: bool,
        instances: &[PCS::Accumulator],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>,
    {
        KzgAccumulationProof::read(zk, instances, transcript)
    }

    fn verify(
        _: &Self::VerifyingKey,
        instances: &[PCS::Accumulator],
        proof: &Self::Proof,
    ) -> Result<PCS::Accumulator, Error> {
        let (lhs, rhs) = instances
            .iter()
            .cloned()
            .map(|accumulator| (accumulator.lhs, accumulator.rhs))
            .chain(proof.blind.clone())
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let separators = proof.separator.powers(lhs.len());
        let [lhs, rhs] = [lhs, rhs].map(|msms| {
            msms.into_iter()
                .zip(separators.iter())
                .map(|(msm, separator)| Msm::<C, L>::base(msm) * separator)
                .sum::<Msm<_, _>>()
                .evaluate(None)
        });

        Ok(Accumulator::new(lhs, rhs))
    }
}

#[derive(Clone, Debug)]
pub struct KzgAccumulationProof<C, L, PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L, Accumulator = Accumulator<C, L>>,
{
    blind: Option<(L::LoadedEcPoint, L::LoadedEcPoint)>,
    separator: L::LoadedScalar,
    _marker: PhantomData<PCS>,
}

impl<C, L, PCS> KzgAccumulationProof<C, L, PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L, Accumulator = Accumulator<C, L>>,
{
    fn read<T>(zk: bool, instances: &[PCS::Accumulator], transcript: &mut T) -> Result<Self, Error>
    where
        T: TranscriptRead<C, L>,
    {
        assert!(instances.len() > 1);

        for accumulator in instances {
            transcript.common_ec_point(&accumulator.lhs)?;
            transcript.common_ec_point(&accumulator.rhs)?;
        }

        let blind = zk
            .then(|| Ok((transcript.read_ec_point()?, transcript.read_ec_point()?)))
            .transpose()?;

        let separator = transcript.squeeze_challenge();

        Ok(Self {
            blind,
            separator,
            _marker: PhantomData,
        })
    }
}

impl<C, PCS> AccumulationSchemeProver<C, PCS> for KzgAccumulation<PCS>
where
    C: CurveAffine,
    PCS: PolynomialCommitmentScheme<C, NativeLoader, Accumulator = Accumulator<C, NativeLoader>>,
{
    type ProvingKey = (C, C);

    fn create_proof<T, R>(
        zk: bool,
        (g, s_g): &(C, C),
        instances: &[PCS::Accumulator],
        transcript: &mut T,
        rng: R,
    ) -> Result<PCS::Accumulator, Error>
    where
        T: TranscriptWrite<C>,
        R: Rng,
    {
        assert!(instances.len() > 1);

        for accumulator in instances {
            transcript.common_ec_point(&accumulator.lhs)?;
            transcript.common_ec_point(&accumulator.rhs)?;
        }

        let blind = zk
            .then(|| {
                let s = C::Scalar::random(rng);
                let lhs = (*s_g * s).to_affine();
                let rhs = (*g * s).to_affine();
                transcript.write_ec_point(lhs)?;
                transcript.write_ec_point(rhs)?;
                Ok((lhs, rhs))
            })
            .transpose()?;

        let separator = transcript.squeeze_challenge();

        let (lhs, rhs) = instances
            .iter()
            .cloned()
            .map(|accumulator| (accumulator.lhs, accumulator.rhs))
            .chain(blind)
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let separators = separator.powers(lhs.len());
        let [lhs, rhs] = [lhs, rhs].map(|msms| {
            msms.into_iter()
                .zip(separators.iter())
                .map(|(msm, separator)| Msm::<C, NativeLoader>::base(msm) * separator)
                .sum::<Msm<_, _>>()
                .evaluate(None)
        });

        Ok(Accumulator::new(lhs, rhs))
    }
}
