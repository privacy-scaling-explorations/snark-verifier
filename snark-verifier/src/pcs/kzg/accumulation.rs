use crate::{
    loader::{native::NativeLoader, LoadedScalar, Loader},
    pcs::{kzg::KzgAccumulator, AccumulationScheme, AccumulationSchemeProver},
    util::{
        arithmetic::{Curve, CurveAffine, Field, MultiMillerLoop, PrimeField},
        msm::Msm,
        transcript::{TranscriptRead, TranscriptWrite},
    },
    Error,
};
use rand::Rng;
use std::{fmt::Debug, marker::PhantomData};

/// KZG accumulation scheme. The second generic `MOS` stands for different kind
/// of multi-open scheme.
#[derive(Clone, Debug)]
pub struct KzgAs<M, MOS>(PhantomData<(M, MOS)>);

impl<M, L, MOS> AccumulationScheme<M::G1Affine, L> for KzgAs<M, MOS>
where
    M: MultiMillerLoop,
    M::Scalar: PrimeField,
    L: Loader<M::G1Affine>,
    MOS: Clone + Debug,
{
    type Accumulator = KzgAccumulator<M::G1Affine, L>;
    type VerifyingKey = KzgAsVerifyingKey;
    type Proof = KzgAsProof<M::G1Affine, L>;

    fn read_proof<T>(
        vk: &Self::VerifyingKey,
        instances: &[Self::Accumulator],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<M::G1Affine, L>,
    {
        KzgAsProof::read(vk, instances, transcript)
    }

    fn verify(
        _: &Self::VerifyingKey,
        instances: &[Self::Accumulator],
        proof: &Self::Proof,
    ) -> Result<Self::Accumulator, Error> {
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
                .map(|(base, r)| Msm::<M::G1Affine, L>::base(base) * r)
                .sum::<Msm<_, _>>()
                .evaluate(None)
        });

        Ok(KzgAccumulator::new(lhs, rhs))
    }
}

/// KZG accumulation scheme proving key.
#[derive(Clone, Copy, Debug, Default)]
pub struct KzgAsProvingKey<C>(pub Option<(C, C)>);

impl<C: Clone> KzgAsProvingKey<C> {
    /// Initialize a [`KzgAsProvingKey`].
    pub fn new(g: Option<(C, C)>) -> Self {
        Self(g)
    }

    /// Returns if it supports zero-knowledge or not.
    pub fn zk(&self) -> bool {
        self.0.is_some()
    }

    /// Returns [`KzgAsVerifyingKey`].
    pub fn vk(&self) -> KzgAsVerifyingKey {
        KzgAsVerifyingKey(self.zk())
    }
}

/// KZG accumulation scheme verifying key.
#[derive(Clone, Copy, Debug, Default)]
pub struct KzgAsVerifyingKey(bool);

impl KzgAsVerifyingKey {
    /// Returns if it supports zero-knowledge or not.
    pub fn zk(&self) -> bool {
        self.0
    }
}

/// KZG accumulation scheme proof.
#[derive(Clone, Debug)]
pub struct KzgAsProof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    blind: Option<(L::LoadedEcPoint, L::LoadedEcPoint)>,
    r: L::LoadedScalar,
}

impl<C, L> KzgAsProof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn read<T>(
        vk: &KzgAsVerifyingKey,
        instances: &[KzgAccumulator<C, L>],
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

        Ok(Self { blind, r })
    }
}

impl<M, MOS> AccumulationSchemeProver<M::G1Affine> for KzgAs<M, MOS>
where
    M: MultiMillerLoop,
    M::Scalar: PrimeField,
    MOS: Clone + Debug,
{
    type ProvingKey = KzgAsProvingKey<M::G1Affine>;

    fn create_proof<T, R>(
        pk: &Self::ProvingKey,
        instances: &[KzgAccumulator<M::G1Affine, NativeLoader>],
        transcript: &mut T,
        rng: R,
    ) -> Result<KzgAccumulator<M::G1Affine, NativeLoader>, Error>
    where
        T: TranscriptWrite<M::G1Affine>,
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
                let s = M::Scalar::random(rng);
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
                .map(|(msm, power_of_r)| Msm::<M::G1Affine, NativeLoader>::base(msm) * power_of_r)
                .sum::<Msm<_, _>>()
                .evaluate(None)
        });

        Ok(KzgAccumulator::new(lhs, rhs))
    }
}
