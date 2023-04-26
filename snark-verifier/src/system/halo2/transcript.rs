//! Transcripts implemented with both `halo2_proofs::transcript` and
//! `crate::util::transcript`.
use crate::{
    loader::native::{self, NativeLoader},
    util::{
        arithmetic::{CurveAffine, FromUniformBytes},
        transcript::{Transcript, TranscriptRead, TranscriptWrite},
    },
    Error,
};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use std::io::{Read, Write};

#[cfg(feature = "loader_evm")]
pub mod evm;

#[cfg(feature = "loader_halo2")]
pub mod halo2;

impl<C: CurveAffine, R: Read> Transcript<C, NativeLoader> for Blake2bRead<R, C, Challenge255<C>>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn loader(&self) -> &NativeLoader {
        &native::LOADER
    }

    fn squeeze_challenge(&mut self) -> C::Scalar {
        *halo2_proofs::transcript::Transcript::squeeze_challenge_scalar::<C::Scalar>(self)
    }

    fn common_ec_point(&mut self, ec_point: &C) -> Result<(), Error> {
        halo2_proofs::transcript::Transcript::common_point(self, *ec_point)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        halo2_proofs::transcript::Transcript::common_scalar(self, *scalar)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }
}

impl<C: CurveAffine, R: Read> TranscriptRead<C, NativeLoader> for Blake2bRead<R, C, Challenge255<C>>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn read_scalar(&mut self) -> Result<C::Scalar, Error> {
        halo2_proofs::transcript::TranscriptRead::read_scalar(self)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }

    fn read_ec_point(&mut self) -> Result<C, Error> {
        halo2_proofs::transcript::TranscriptRead::read_point(self)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }
}

impl<C: CurveAffine, W: Write> Transcript<C, NativeLoader> for Blake2bWrite<W, C, Challenge255<C>>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn loader(&self) -> &NativeLoader {
        &native::LOADER
    }

    fn squeeze_challenge(&mut self) -> C::Scalar {
        *halo2_proofs::transcript::Transcript::squeeze_challenge_scalar::<C::Scalar>(self)
    }

    fn common_ec_point(&mut self, ec_point: &C) -> Result<(), Error> {
        halo2_proofs::transcript::Transcript::common_point(self, *ec_point)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        halo2_proofs::transcript::Transcript::common_scalar(self, *scalar)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }
}

impl<C: CurveAffine> TranscriptWrite<C> for Blake2bWrite<Vec<u8>, C, Challenge255<C>>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<(), Error> {
        halo2_proofs::transcript::TranscriptWrite::write_scalar(self, scalar)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }

    fn write_ec_point(&mut self, ec_point: C) -> Result<(), Error>
    where
        C::Scalar: FromUniformBytes<64>,
    {
        halo2_proofs::transcript::TranscriptWrite::write_point(self, ec_point)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }
}
