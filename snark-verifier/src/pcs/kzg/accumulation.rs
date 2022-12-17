use crate::{
    loader::{native::NativeLoader, LoadedScalar, Loader},
    pcs::{
        kzg::KzgAccumulator, AccumulationScheme, AccumulationSchemeProver,
        PolynomialCommitmentScheme,
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
pub struct KzgAs<PCS>(PhantomData<PCS>);

impl<C, L, PCS> AccumulationScheme<C, L, PCS> for KzgAs<PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L, Accumulator = KzgAccumulator<C, L>>,
{
    type VerifyingKey = KzgAsVerifyingKey;
    type Proof = KzgAsProof<C, L, PCS>;

    fn read_proof<T>(
        vk: &Self::VerifyingKey,
        instances: &[PCS::Accumulator],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>,
    {
        KzgAsProof::read(vk, instances, transcript)
    }

    fn verify(
        _: &Self::VerifyingKey,
        instances: &[PCS::Accumulator],
        proof: &Self::Proof,
    ) -> Result<PCS::Accumulator, Error> {
        let (lhs, rhs) = instances
            .iter()
            .map(|accumulator| (&accumulator.lhs, &accumulator.rhs))
            .chain(proof.blind.as_ref().map(|(lhs, rhs)| (lhs, rhs)))
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let powers_of_r = proof.r.powers(lhs.len());
        let [lhs, rhs] = [lhs, rhs].map(|bases| {
            bases
                .into_iter()
                .zip(powers_of_r.iter())
                .map(|(base, r)| Msm::<C, L>::base(base) * r)
                .sum::<Msm<_, _>>()
                .evaluate(None)
        });

        Ok(KzgAccumulator::new(lhs, rhs))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KzgAsProvingKey<C>(pub Option<(C, C)>);

impl<C: Clone> KzgAsProvingKey<C> {
    pub fn new(g: Option<(C, C)>) -> Self {
        Self(g)
    }

    pub fn zk(&self) -> bool {
        self.0.is_some()
    }

    pub fn vk(&self) -> KzgAsVerifyingKey {
        KzgAsVerifyingKey(self.zk())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KzgAsVerifyingKey(bool);

impl KzgAsVerifyingKey {
    pub fn zk(&self) -> bool {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct KzgAsProof<C, L, PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L, Accumulator = KzgAccumulator<C, L>>,
{
    blind: Option<(L::LoadedEcPoint, L::LoadedEcPoint)>,
    r: L::LoadedScalar,
    _marker: PhantomData<PCS>,
}

impl<C, L, PCS> KzgAsProof<C, L, PCS>
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L, Accumulator = KzgAccumulator<C, L>>,
{
    fn read<T>(
        vk: &KzgAsVerifyingKey,
        instances: &[PCS::Accumulator],
        transcript: &mut T,
    ) -> Result<Self, Error>
    where
        T: TranscriptRead<C, L>,
    {
        assert!(!instances.is_empty());

        for accumulator in instances {
            transcript.common_ec_point(&accumulator.lhs)?;
            transcript.common_ec_point(&accumulator.rhs)?;
        }

        let blind = vk
            .zk()
            .then(|| Ok((transcript.read_ec_point()?, transcript.read_ec_point()?)))
            .transpose()?;

        let r = transcript.squeeze_challenge();

        Ok(Self {
            blind,
            r,
            _marker: PhantomData,
        })
    }
}

impl<C, PCS> AccumulationSchemeProver<C, PCS> for KzgAs<PCS>
where
    C: CurveAffine,
    PCS: PolynomialCommitmentScheme<C, NativeLoader, Accumulator = KzgAccumulator<C, NativeLoader>>,
{
    type ProvingKey = KzgAsProvingKey<C>;

    fn create_proof<T, R>(
        pk: &Self::ProvingKey,
        instances: &[PCS::Accumulator],
        transcript: &mut T,
        rng: R,
    ) -> Result<PCS::Accumulator, Error>
    where
        T: TranscriptWrite<C>,
        R: Rng,
    {
        assert!(!instances.is_empty());

        for accumulator in instances {
            transcript.common_ec_point(&accumulator.lhs)?;
            transcript.common_ec_point(&accumulator.rhs)?;
        }

        let blind = pk
            .zk()
            .then(|| {
                let s = C::Scalar::random(rng);
                let (g, s_g) = pk.0.unwrap();
                let lhs = (s_g * s).to_affine();
                let rhs = (g * s).to_affine();
                transcript.write_ec_point(lhs)?;
                transcript.write_ec_point(rhs)?;
                Ok((lhs, rhs))
            })
            .transpose()?;

        let r = transcript.squeeze_challenge();

        let (lhs, rhs) = instances
            .iter()
            .cloned()
            .map(|accumulator| (accumulator.lhs, accumulator.rhs))
            .chain(blind)
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let powers_of_r = r.powers(lhs.len());
        let [lhs, rhs] = [lhs, rhs].map(|msms| {
            msms.iter()
                .zip(powers_of_r.iter())
                .map(|(msm, power_of_r)| Msm::<C, NativeLoader>::base(msm) * power_of_r)
                .sum::<Msm<_, _>>()
                .evaluate(None)
        });

        Ok(KzgAccumulator::new(lhs, rhs))
    }
}
