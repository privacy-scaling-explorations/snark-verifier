use crate::{
    loader::Loader,
    pcs::{Decider, MultiOpenScheme},
    util::{arithmetic::CurveAffine, transcript::TranscriptRead},
    Error, Protocol,
};
use std::fmt::Debug;

mod plonk;

pub use plonk::{Plonk, PlonkProof};

pub trait PlonkVerifier<C, L, MOS>
where
    C: CurveAffine,
    L: Loader<C>,
    MOS: MultiOpenScheme<C, L>,
{
    type Proof: Clone + Debug;

    fn read_proof<T>(
        svk: &MOS::SuccinctVerifyingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>;

    fn succinct_verify(
        svk: &MOS::SuccinctVerifyingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<Vec<MOS::Accumulator>, Error>;

    fn verify(
        svk: &MOS::SuccinctVerifyingKey,
        dk: &MOS::DecidingKey,
        protocol: &Protocol<C>,
        instances: &[Vec<L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Result<MOS::Output, Error>
    where
        MOS: Decider<C, L>,
    {
        let accumulators = Self::succinct_verify(svk, protocol, instances, proof)?;
        let output = MOS::decide_all(dk, accumulators);
        Ok(output)
    }
}
