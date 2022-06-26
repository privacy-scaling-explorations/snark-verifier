use crate::{
    loader::native::NativeLoader,
    util::{Curve, PrimeCurveAffine, PrimeField, Transcript, TranscriptRead, UncompressedEncoding},
    Error,
};
use halo2_proofs::{
    arithmetic::{CurveAffine, CurveExt},
    transcript::{Blake2bRead, Challenge255},
};
use std::{io::Read, iter};

pub mod halo2;

#[cfg(feature = "evm")]
pub mod evm;

impl<C: CurveExt> UncompressedEncoding for C
where
    <C::AffineExt as CurveAffine>::Base: PrimeField<Repr = [u8; 32]>,
{
    type Uncompressed = [u8; 64];

    fn to_uncompressed(&self) -> [u8; 64] {
        let coordinates = self.to_affine().coordinates().unwrap();
        iter::empty()
            .chain(coordinates.x().to_repr().as_ref())
            .chain(coordinates.y().to_repr().as_ref())
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn from_uncompressed(uncompressed: [u8; 64]) -> Option<Self> {
        let x = Option::from(<C::AffineExt as CurveAffine>::Base::from_repr(
            uncompressed[..32].to_vec().try_into().unwrap(),
        ))?;
        let y = Option::from(<C::AffineExt as CurveAffine>::Base::from_repr(
            uncompressed[32..].to_vec().try_into().unwrap(),
        ))?;
        C::AffineExt::from_xy(x, y)
            .map(|ec_point| ec_point.to_curve())
            .into()
    }
}

impl<R: Read, C: CurveAffine> Transcript<C::CurveExt, NativeLoader>
    for Blake2bRead<R, C, Challenge255<C>>
{
    fn squeeze_challenge(&mut self) -> C::Scalar {
        *halo2_proofs::transcript::Transcript::squeeze_challenge_scalar::<C::Scalar>(self)
    }

    fn common_ec_point(&mut self, ec_point: &C::CurveExt) -> Result<(), Error> {
        halo2_proofs::transcript::Transcript::common_point(self, ec_point.to_affine())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        halo2_proofs::transcript::Transcript::common_scalar(self, *scalar)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }
}

impl<R: Read, C: CurveAffine> TranscriptRead<C::CurveExt, NativeLoader>
    for Blake2bRead<R, C, Challenge255<C>>
{
    fn read_scalar(&mut self) -> Result<C::Scalar, Error> {
        halo2_proofs::transcript::TranscriptRead::read_scalar(self)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }

    fn read_ec_point(&mut self) -> Result<C::CurveExt, Error> {
        halo2_proofs::transcript::TranscriptRead::read_point(self)
            .map(|ec_point| ec_point.to_curve())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }
}
