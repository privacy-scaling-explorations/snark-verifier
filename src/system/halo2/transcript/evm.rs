use crate::{
    loader::{
        evm::{loader::Value, u256_to_fe, EcPoint, EvmLoader, MemoryChunk, Scalar},
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
use halo2_proofs::transcript::EncodedChallenge;
use sha3::{Digest, Keccak256};
use std::{
    io::{self, Read, Write},
    iter,
    marker::PhantomData,
    rc::Rc,
};
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
        let mut buf = MemoryChunk::new(ptr);
        buf.extend(0x20);
        Self {
            loader,
            stream: 0,
            buf,
            _marker: PhantomData,
        }
    }

    pub fn load_instances(&mut self, num_instance: Vec<usize>) -> Vec<Vec<Scalar>> {
        num_instance
            .into_iter()
            .map(|len| {
                iter::repeat_with(|| {
                    let scalar = self.loader.calldataload_scalar(self.stream);
                    self.stream += 0x20;
                    scalar
                })
                .take(len)
                .collect_vec()
            })
            .collect()
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
        let len = if self.buf.len() == 0x20 {
            assert_eq!(self.loader.ptr(), self.buf.end());
            self.loader
                .code_mut()
                .push(1)
                .push(self.buf.end())
                .mstore8();
            0x21
        } else {
            self.buf.len()
        };
        let hash_ptr = self.loader.keccak256(self.buf.ptr(), len);

        let challenge_ptr = self.loader.allocate(0x20);
        let dup_hash_ptr = self.loader.allocate(0x20);
        self.loader
            .code_mut()
            .push(hash_ptr)
            .mload()
            .push(self.loader.scalar_modulus())
            .dup(1)
            .r#mod()
            .push(challenge_ptr)
            .mstore()
            .push(dup_hash_ptr)
            .mstore();

        self.buf.reset(dup_hash_ptr);
        self.buf.extend(0x20);

        self.loader.scalar(Value::Memory(challenge_ptr))
    }

    fn common_ec_point(&mut self, ec_point: &EcPoint) -> Result<(), Error> {
        if let Value::Memory(ptr) = ec_point.value() {
            assert_eq!(self.buf.end(), ptr);
            self.buf.extend(0x40);
        } else {
            unreachable!()
        }
        Ok(())
    }

    fn common_scalar(&mut self, scalar: &Scalar) -> Result<(), Error> {
        match scalar.value() {
            Value::Constant(_) if self.buf.ptr() == 0 => {
                self.loader.copy_scalar(scalar, self.buf.ptr());
            }
            Value::Memory(ptr) => {
                assert_eq!(self.buf.end(), ptr);
                self.buf.extend(0x20);
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

pub struct ChallengeEvm<C>(C::Scalar)
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>;

impl<C> EncodedChallenge<C> for ChallengeEvm<C>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    type Input = [u8; 32];

    fn new(challenge_input: &[u8; 32]) -> Self {
        ChallengeEvm(u256_to_fe(U256::from_big_endian(challenge_input)))
    }

    fn get_scalar(&self) -> C::Scalar {
        self.0
    }
}

impl<C, S> halo2_proofs::transcript::Transcript<C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn squeeze_challenge(&mut self) -> ChallengeEvm<C> {
        ChallengeEvm(Transcript::squeeze_challenge(self))
    }

    fn common_point(&mut self, ec_point: C) -> io::Result<()> {
        match Transcript::common_ec_point(self, &ec_point) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            _ => Ok(()),
        }
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        match Transcript::common_scalar(self, &scalar) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            _ => Ok(()),
        }
    }
}

impl<C, R: Read> halo2_proofs::transcript::TranscriptRead<C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, R, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn read_point(&mut self) -> io::Result<C> {
        match TranscriptRead::read_ec_point(self) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            Ok(value) => Ok(value),
        }
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        match TranscriptRead::read_scalar(self) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            Ok(value) => Ok(value),
        }
    }
}

impl<C, R: Read> halo2_proofs::transcript::TranscriptReadBuffer<R, C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, R, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn init(reader: R) -> Self {
        Self::new(reader)
    }
}

impl<C, W: Write> halo2_proofs::transcript::TranscriptWrite<C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, W, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn write_point(&mut self, ec_point: C) -> io::Result<()> {
        halo2_proofs::transcript::Transcript::<C, ChallengeEvm<C>>::common_point(self, ec_point)?;
        let coords: Coordinates<C> = Option::from(ec_point.coordinates()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Cannot write points at infinity to the transcript",
            )
        })?;
        let mut x = coords.x().to_repr();
        let mut y = coords.y().to_repr();
        x.as_mut().reverse();
        y.as_mut().reverse();
        self.stream_mut().write_all(x.as_ref())?;
        self.stream_mut().write_all(y.as_ref())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        halo2_proofs::transcript::Transcript::<C, ChallengeEvm<C>>::common_scalar(self, scalar)?;
        let mut data = scalar.to_repr();
        data.as_mut().reverse();
        self.stream_mut().write_all(data.as_ref())
    }
}

impl<C, W: Write> halo2_proofs::transcript::TranscriptWriterBuffer<W, C, ChallengeEvm<C>>
    for EvmTranscript<C, NativeLoader, W, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn init(writer: W) -> Self {
        Self::new(writer)
    }

    fn finalize(self) -> W {
        self.finalize()
    }
}
