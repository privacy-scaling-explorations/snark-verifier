use crate::{
    transcript::Transcript,
    util::{
        loader::{
            evm::{EcPoint, EvmLoader, Pointer, Scalar},
            native::NativeLoader,
            Loader,
        },
        u256_to_field, Curve, Group, PrimeField, UncompressedEncoding,
    },
    Error,
};
use ethereum_types::U256;
use sha3::{Digest, Keccak256};
use std::{
    io::{self, Read},
    marker::PhantomData,
    rc::Rc,
};

pub struct EvmTranscript<C: Curve, L: Loader<C>, R, B> {
    loader: L,
    reader: R,
    buf: B,
    _marker: PhantomData<C>,
}

impl<C> EvmTranscript<C, Rc<EvmLoader>, (), (Pointer<32>, usize)>
where
    C: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    pub fn new(loader: Rc<EvmLoader>) -> Self {
        let ptr = loader.allocate();
        assert_eq!(ptr.memory_address(), 0);
        Self {
            loader,
            reader: (),
            buf: (ptr, 0x20),
            _marker: PhantomData,
        }
    }
}

impl<C> Transcript<C, Rc<EvmLoader>> for EvmTranscript<C, Rc<EvmLoader>, (), (Pointer<32>, usize)>
where
    C: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn read_scalar(&mut self) -> Result<Scalar, Error> {
        let scalar = self.loader.calldataload_scalar();
        Transcript::<C, _>::common_scalar(self, &scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<EcPoint, Error> {
        let ec_point = self.loader.calldataload_ec_point();
        Transcript::<C, _>::common_ec_point(self, &ec_point)?;
        Ok(ec_point)
    }

    fn squeeze_challenge(&mut self) -> Scalar {
        let scalar = self.loader.squeeze_challenge(&mut self.buf.0, self.buf.1);
        self.buf.1 = 0x20;
        scalar
    }

    fn common_ec_point(&mut self, value: &EcPoint) -> Result<(), Error> {
        if value.is_const() {
            unreachable!()
        } else {
            assert_eq!(
                self.buf.0.memory_address() + self.buf.1,
                value.memory_address()
            );
            self.buf.1 += 0x40;
        }
        Ok(())
    }

    fn common_scalar(&mut self, value: &Scalar) -> Result<(), Error> {
        if value.is_const() {
            if self.buf.0.memory_address() == 0 {
                self.loader.copy_scalar(value, &self.buf.0);
            } else {
                unreachable!()
            }
        } else {
            assert_eq!(
                self.buf.0.memory_address() + self.buf.1,
                value.memory_address()
            );
            self.buf.1 += 0x20;
        };
        Ok(())
    }
}

impl<C, R: Read> EvmTranscript<C, NativeLoader, R, Vec<u8>>
where
    C: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    pub fn new(reader: R) -> Self {
        Self {
            loader: NativeLoader,
            reader,
            buf: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<C, R: Read> Transcript<C, NativeLoader> for EvmTranscript<C, NativeLoader, R, Vec<u8>>
where
    C: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn read_scalar(&mut self) -> Result<C::Scalar, Error> {
        let mut data = [0; 32];
        self.reader
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        data.reverse();
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
        let mut data = [0; 64];
        self.reader
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        data.as_mut_slice()[..32].reverse();
        data.as_mut_slice()[32..].reverse();
        let ec_point = C::from_uncompressed(data).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid elliptic curve point encoding in proof".to_string(),
            )
        })?;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }

    fn squeeze_challenge(&mut self) -> C::Scalar {
        let data = self
            .buf
            .iter()
            .cloned()
            .chain(if self.buf.len() == 0x20 {
                Some(1)
            } else {
                None
            })
            .collect::<Vec<_>>();
        let hash: [u8; 32] = Keccak256::digest(data).into();
        self.buf = hash.to_vec();
        u256_to_field(U256::from_big_endian(hash.as_slice()))
    }

    fn common_ec_point(&mut self, value: &C) -> Result<(), Error> {
        let uncopressed = value.to_uncompressed();
        self.buf.extend(uncopressed[..32].iter().rev().cloned());
        self.buf.extend(uncopressed[32..].iter().rev().cloned());

        Ok(())
    }

    fn common_scalar(&mut self, value: &C::Scalar) -> Result<(), Error> {
        self.buf.extend(value.to_repr().as_ref().iter().rev());

        Ok(())
    }
}
