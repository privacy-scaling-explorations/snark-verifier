use crate::{
    loader::{halo2::PoseidonTranscript, native::NativeLoader},
    util::{self, Curve, PrimeField},
    Error,
};
use halo2_curves::CurveAffine;
use halo2_proofs::transcript::{
    EncodedChallenge, Transcript, TranscriptRead, TranscriptReadBuffer, TranscriptWrite,
    TranscriptWriterBuffer,
};
use halo2_wrong_transcript::PointRepresentation;
use poseidon::Poseidon;
use std::io::{self, Read, Write};

pub struct ChallengeScalar<C: CurveAffine>(C::Scalar);

impl<C: CurveAffine> EncodedChallenge<C> for ChallengeScalar<C> {
    type Input = C::Scalar;

    fn new(challenge_input: &C::Scalar) -> Self {
        ChallengeScalar(*challenge_input)
    }

    fn get_scalar(&self) -> C::Scalar {
        self.0
    }
}

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar>,
        S,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > Transcript<C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        S,
        Poseidon<C::Scalar, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn squeeze_challenge(&mut self) -> ChallengeScalar<C> {
        ChallengeScalar::new(&util::Transcript::squeeze_challenge(self))
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

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar>,
        R: Read,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptRead<C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        R,
        Poseidon<C::Scalar, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
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

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar>,
        R: Read,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptReadBuffer<R, C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        R,
        Poseidon<C::Scalar, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn init(reader: R) -> Self {
        Self::new(reader)
    }
}

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar>,
        W: Write,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptWrite<C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        W,
        Poseidon<C::Scalar, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn write_point(&mut self, ec_point: C) -> io::Result<()> {
        Transcript::<C, ChallengeScalar<C>>::common_point(self, ec_point)?;
        let data = ec_point.to_bytes();
        self.stream_mut().write_all(data.as_ref())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        Transcript::<C, ChallengeScalar<C>>::common_scalar(self, scalar)?;
        let data = scalar.to_repr();
        self.stream_mut().write_all(data.as_ref())
    }
}

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar>,
        W: Write,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptWriterBuffer<W, C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        W,
        Poseidon<C::Scalar, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn init(writer: W) -> Self {
        Self::new(writer)
    }

    fn finalize(self) -> W {
        self.finalize()
    }
}
