use crate::{
    loader::native::NativeLoader,
    util::{Group, PrimeField, Transcript},
    Error,
};
use blake2b_simd::{Params, State};
use halo2_proofs::halo2curves::{Coordinates, CurveAffine, CurveExt, FieldExt};
use std::{
    io::{self, Read},
    marker::PhantomData,
};

const BLAKE2B_PREFIX_CHALLENGE: u8 = 0;
const BLAKE2B_PREFIX_EC_POINT: u8 = 1;
const BLAKE2B_PREFIX_SCALAR: u8 = 2;

#[derive(Debug, Clone)]
pub struct Blake2bTranscript<R: Read, C: CurveExt> {
    state: State,
    reader: R,
    _marker: PhantomData<C>,
}

impl<R: Read, C: CurveExt> Blake2bTranscript<R, C> {
    pub fn new(reader: R) -> Self {
        Self {
            state: Params::new()
                .hash_length(64)
                .personal(b"Halo2-Transcript")
                .to_state(),
            reader,
            _marker: PhantomData,
        }
    }
}

impl<R: Read, C: CurveExt> Transcript<C, NativeLoader> for Blake2bTranscript<R, C> {
    fn read_scalar(&mut self) -> Result<<C as Group>::Scalar, Error> {
        let mut data = <<C as Group>::Scalar as PrimeField>::Repr::default();
        self.reader
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        let scalar = <C as Group>::Scalar::from_repr_vartime(data).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid scalar encoding in proof".to_string(),
            )
        })?;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<C, Error> {
        let mut compressed = C::Repr::default();
        self.reader
            .read_exact(compressed.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        let point = Option::from(C::from_bytes(&compressed)).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid elliptic curve point encoding in proof".to_string(),
            )
        })?;
        self.common_ec_point(&point)?;
        Ok(point)
    }

    fn squeeze_challenge(&mut self) -> <C as Group>::Scalar {
        self.state.update(&[BLAKE2B_PREFIX_CHALLENGE]);
        let hasher = self.state.clone();
        let result: [u8; 64] = hasher.finalize().as_bytes().try_into().unwrap();
        <C as Group>::Scalar::from_bytes_wide(&result)
    }

    fn common_ec_point(&mut self, value: &C) -> Result<(), Error> {
        self.state.update(&[BLAKE2B_PREFIX_EC_POINT]);
        let coords: Coordinates<C::AffineExt> = Option::from(value.to_affine().coordinates())
            .ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Cannot write elliptic curve point at infinity to the transcript".to_string(),
                )
            })?;
        self.state.update(coords.x().to_repr().as_ref());
        self.state.update(coords.y().to_repr().as_ref());
        Ok(())
    }

    fn common_scalar(&mut self, value: &<C as Group>::Scalar) -> Result<(), Error> {
        self.state.update(&[BLAKE2B_PREFIX_SCALAR]);
        self.state.update(value.to_repr().as_ref());
        Ok(())
    }
}
