use crate::{
    loader::{
        evm::{u256_to_fe, EvmTranscript},
        native::NativeLoader,
    },
    util::{self, Curve, PrimeField, UncompressedEncoding},
    Error,
};
use ethereum_types::U256;
use halo2_curves::{Coordinates, CurveAffine};
use halo2_proofs::transcript::{
    EncodedChallenge, Transcript, TranscriptRead, TranscriptReadBuffer, TranscriptWrite,
    TranscriptWriterBuffer,
};
use std::io::{self, Read, Write};

pub struct ChallengeEvm<C: CurveAffine>(C::Scalar)
where
    C::CurveExt: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>;

impl<C: CurveAffine> EncodedChallenge<C> for ChallengeEvm<C>
where
    C::CurveExt: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
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

impl<C: CurveAffine, S> Transcript<C, ChallengeEvm<C>>
    for EvmTranscript<C::CurveExt, NativeLoader, S, Vec<u8>>
where
    C::CurveExt: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn squeeze_challenge(&mut self) -> ChallengeEvm<C> {
        ChallengeEvm(util::Transcript::squeeze_challenge(self))
    }

    fn common_point(&mut self, ec_point: C) -> io::Result<()> {
        match util::Transcript::common_ec_point(self, &ec_point.to_curve()) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            _ => Ok(()),
        }
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        match util::Transcript::common_scalar(self, &scalar) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            _ => Ok(()),
        }
    }
}

impl<C: CurveAffine, R: Read> TranscriptRead<C, ChallengeEvm<C>>
    for EvmTranscript<C::CurveExt, NativeLoader, R, Vec<u8>>
where
    C::CurveExt: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn read_point(&mut self) -> io::Result<C> {
        match util::TranscriptRead::read_ec_point(self) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            Ok(value) => Ok(value.to_affine()),
        }
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        match util::TranscriptRead::read_scalar(self) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            Ok(value) => Ok(value),
        }
    }
}

impl<C: CurveAffine, R: Read> TranscriptReadBuffer<R, C, ChallengeEvm<C>>
    for EvmTranscript<C::CurveExt, NativeLoader, R, Vec<u8>>
where
    C::CurveExt: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn init(reader: R) -> Self {
        Self::new(reader)
    }
}

impl<C: CurveAffine, W: Write> TranscriptWrite<C, ChallengeEvm<C>>
    for EvmTranscript<C::CurveExt, NativeLoader, W, Vec<u8>>
where
    C::CurveExt: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn write_point(&mut self, ec_point: C) -> io::Result<()> {
        Transcript::<C, ChallengeEvm<C>>::common_point(self, ec_point)?;
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
        Transcript::<C, ChallengeEvm<C>>::common_scalar(self, scalar)?;
        let mut data = scalar.to_repr();
        data.as_mut().reverse();
        self.stream_mut().write_all(data.as_ref())
    }
}

impl<C: CurveAffine, W: Write> TranscriptWriterBuffer<W, C, ChallengeEvm<C>>
    for EvmTranscript<C::CurveExt, NativeLoader, W, Vec<u8>>
where
    C::CurveExt: Curve + UncompressedEncoding<Uncompressed = [u8; 64]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn init(writer: W) -> Self {
        Self::new(writer)
    }

    fn finalize(self) -> W {
        self.finalize()
    }
}
