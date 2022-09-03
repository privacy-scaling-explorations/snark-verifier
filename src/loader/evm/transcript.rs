use crate::{
    loader::{
        evm::{
            loader::{EcPoint, EvmLoader, Scalar, Value},
            u256_to_fe,
        },
        native::{self, NativeLoader},
        Loader,
    },
    util::{
        arithmetic::{Coordinates, CurveAffine, PrimeField},
        transcript::{Transcript, TranscriptRead},
        Itertools,
    },
    Error,
};
use ethereum_types::U256;
use sha3::{Digest, Keccak256};
use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    rc::Rc,
};

pub struct MemoryChunk {
    ptr: usize,
    len: usize,
}

impl MemoryChunk {
    fn new(ptr: usize) -> Self {
        Self { ptr, len: 0x20 }
    }

    fn reset(&mut self, ptr: usize) {
        self.ptr = ptr;
        self.len = 0x20;
    }

    fn include(&self, ptr: usize, size: usize) -> bool {
        let range = self.ptr..=self.ptr + self.len;
        range.contains(&ptr) && range.contains(&(ptr + size))
    }

    fn extend(&mut self, ptr: usize, size: usize) {
        if !self.include(ptr, size) {
            assert_eq!(self.ptr + self.len, ptr);
            self.len += size;
        }
    }
}

pub struct EvmTranscript<C: CurveAffine, L: Loader<C>, S, B> {
    loader: L,
    stream: S,
    buf: B,
    _marker: PhantomData<C>,
}

impl<C> EvmTranscript<C, Rc<EvmLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    pub fn new(loader: Rc<EvmLoader>) -> Self {
        let ptr = loader.allocate(0x20);
        assert_eq!(ptr, 0);
        Self {
            loader,
            stream: 0,
            buf: MemoryChunk::new(ptr),
            _marker: PhantomData,
        }
    }
}

impl<C> Transcript<C, Rc<EvmLoader>> for EvmTranscript<C, Rc<EvmLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn loader(&self) -> &Rc<EvmLoader> {
        &self.loader
    }

    fn squeeze_challenge(&mut self) -> Scalar {
        let (ptr, scalar) = self.loader.squeeze_challenge(self.buf.ptr, self.buf.len);
        self.buf.reset(ptr);
        scalar
    }

    fn common_ec_point(&mut self, ec_point: &EcPoint) -> Result<(), Error> {
        if let Value::Memory(ptr) = ec_point.value() {
            self.buf.extend(ptr, 0x40);
        } else {
            unreachable!()
        }
        Ok(())
    }

    fn common_scalar(&mut self, scalar: &Scalar) -> Result<(), Error> {
        match scalar.value() {
            Value::Constant(_) if self.buf.ptr == 0 => {
                self.loader.copy_scalar(scalar, self.buf.ptr);
            }
            Value::Memory(ptr) => {
                self.buf.extend(ptr, 0x20);
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl<C> TranscriptRead<C, Rc<EvmLoader>> for EvmTranscript<C, Rc<EvmLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn read_scalar(&mut self) -> Result<Scalar, Error> {
        let scalar = self.loader.calldataload_scalar(self.stream);
        self.stream += 0x20;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<EcPoint, Error> {
        let ec_point = self.loader.calldataload_ec_point(self.stream);
        self.stream += 0x40;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<C, S> EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
{
    pub fn new(stream: S) -> Self {
        Self {
            loader: NativeLoader,
            stream,
            buf: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<C, S> Transcript<C, NativeLoader> for EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn loader(&self) -> &NativeLoader {
        &native::LOADER
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
            .collect_vec();
        let hash: [u8; 32] = Keccak256::digest(data).into();
        self.buf = hash.to_vec();
        u256_to_fe(U256::from_big_endian(hash.as_slice()))
    }

    fn common_ec_point(&mut self, ec_point: &C) -> Result<(), Error> {
        let coordinates =
            Option::<Coordinates<C>>::from(ec_point.coordinates()).ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Cannot write points at infinity to the transcript".to_string(),
                )
            })?;

        [coordinates.x(), coordinates.y()].map(|coordinate| {
            self.buf
                .extend(coordinate.to_repr().as_ref().iter().rev().cloned());
        });

        Ok(())
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        self.buf.extend(scalar.to_repr().as_ref().iter().rev());

        Ok(())
    }
}

impl<C, S> TranscriptRead<C, NativeLoader> for EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
    S: Read,
{
    fn read_scalar(&mut self) -> Result<C::Scalar, Error> {
        let mut data = [0; 32];
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        data.reverse();
        let scalar = C::Scalar::from_repr_vartime(data).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid scalar encoding in proof".to_string(),
            )
        })?;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<C, Error> {
        let [mut x, mut y] = [<C::Base as PrimeField>::Repr::default(); 2];
        for repr in [&mut x, &mut y] {
            self.stream
                .read_exact(repr.as_mut())
                .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
            repr.as_mut().reverse();
        }
        let x = Option::from(<C::Base as PrimeField>::from_repr(x));
        let y = Option::from(<C::Base as PrimeField>::from_repr(y));
        let ec_point = x
            .zip(y)
            .and_then(|(x, y)| Option::from(C::from_xy(x, y)))
            .ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Invalid elliptic curve point encoding in proof".to_string(),
                )
            })?;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<C, S> EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    S: Write,
{
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn finalize(self) -> S {
        self.stream
    }
}
