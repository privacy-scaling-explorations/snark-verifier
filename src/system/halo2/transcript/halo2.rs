use crate::{
    loader::{
        halo2::{self, EcPoint, Halo2Loader, Scalar},
        native::{self, NativeLoader},
    },
    util::{
        arithmetic::{CurveAffine, FieldExt, PrimeField},
        transcript::{Transcript, TranscriptRead},
    },
    Error,
};
use halo2_proofs::{circuit::Value, transcript::EncodedChallenge};
use halo2_wrong_ecc::BaseFieldEccChip;
use halo2_wrong_transcript::{PointRepresentation, TranscriptChip};
use poseidon::{Poseidon, Spec};
use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    rc::Rc,
};

pub struct PoseidonTranscript<
    C: CurveAffine<ScalarExt = N>,
    N: FieldExt,
    E: PointRepresentation<C, N, LIMBS, BITS>,
    L,
    S,
    B,
    const LIMBS: usize,
    const BITS: usize,
    const T: usize,
    const RATE: usize,
    const R_F: usize,
    const R_P: usize,
> {
    loader: L,
    stream: S,
    buf: B,
    _marker: PhantomData<(C, N, E)>,
}

impl<
        'a,
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        R: Read,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    >
    PoseidonTranscript<
        C,
        C::Scalar,
        E,
        Rc<Halo2Loader<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>>,
        Value<R>,
        TranscriptChip<C, C::Scalar, E, LIMBS, BITS, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    pub fn new(
        loader: &Rc<Halo2Loader<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>>,
        stream: Value<R>,
    ) -> Self {
        let transcript_chip = TranscriptChip::new(
            &mut loader.ctx_mut(),
            &Spec::new(R_F, R_P),
            loader.ecc_chip().clone(),
            E::default(),
        )
        .unwrap();
        Self {
            loader: loader.clone(),
            stream,
            buf: transcript_chip,
            _marker: PhantomData,
        }
    }
}

impl<
        'a,
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        R: Read,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > Transcript<C, Rc<Halo2Loader<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        Rc<Halo2Loader<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>>,
        Value<R>,
        TranscriptChip<C, C::Scalar, E, LIMBS, BITS, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn loader(&self) -> &Rc<Halo2Loader<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>> {
        &self.loader
    }

    fn squeeze_challenge(&mut self) -> Scalar<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>> {
        let assigned = self.buf.squeeze(&mut self.loader.ctx_mut()).unwrap();
        self.loader.scalar(halo2::loader::Value::Assigned(assigned))
    }

    fn common_scalar(
        &mut self,
        scalar: &Scalar<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>,
    ) -> Result<(), Error> {
        self.buf.write_scalar(&scalar.assigned());
        Ok(())
    }

    fn common_ec_point(
        &mut self,
        ec_point: &EcPoint<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>,
    ) -> Result<(), Error> {
        self.buf
            .write_point(&mut self.loader.ctx_mut(), &ec_point.assigned())
            .unwrap();
        Ok(())
    }
}

impl<
        'a,
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        R: Read,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptRead<C, Rc<Halo2Loader<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        Rc<Halo2Loader<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>>,
        Value<R>,
        TranscriptChip<C, C::Scalar, E, LIMBS, BITS, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn read_scalar(
        &mut self,
    ) -> Result<Scalar<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>, Error> {
        let scalar = self.stream.as_mut().and_then(|stream| {
            let mut data = <C::Scalar as PrimeField>::Repr::default();
            if stream.read_exact(data.as_mut()).is_err() {
                return Value::unknown();
            }
            Option::<C::Scalar>::from(C::Scalar::from_repr(data))
                .map(Value::known)
                .unwrap_or_else(Value::unknown)
        });
        let scalar = self.loader.assign_scalar(scalar);
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(
        &mut self,
    ) -> Result<EcPoint<'a, C, C::Scalar, BaseFieldEccChip<C, LIMBS, BITS>>, Error> {
        let ec_point = self.stream.as_mut().and_then(|stream| {
            let mut compressed = C::Repr::default();
            if stream.read_exact(compressed.as_mut()).is_err() {
                return Value::unknown();
            }
            Option::<C>::from(C::from_bytes(&compressed))
                .map(Value::known)
                .unwrap_or_else(Value::unknown)
        });
        let ec_point = self.loader.assign_ec_point(ec_point);
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        S,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    >
    PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        S,
        Poseidon<C::Scalar, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    pub fn new(stream: S) -> Self {
        Self {
            loader: NativeLoader,
            stream,
            buf: Poseidon::new(R_F, R_P),
            _marker: PhantomData,
        }
    }
}

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        S,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > Transcript<C, NativeLoader>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        S,
        Poseidon<C::Scalar, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn loader(&self) -> &NativeLoader {
        &native::LOADER
    }

    fn squeeze_challenge(&mut self) -> C::Scalar {
        self.buf.squeeze()
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        self.buf.update(&[*scalar]);
        Ok(())
    }

    fn common_ec_point(&mut self, ec_point: &C) -> Result<(), Error> {
        E::encode(*ec_point)
            .map(|encoded| {
                self.buf.update(&encoded);
            })
            .ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Invalid elliptic curve point encoding in proof".to_string(),
                )
            })
    }
}

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        R: Read,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptRead<C, NativeLoader>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        R,
        Poseidon<C::Scalar, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn read_scalar(&mut self) -> Result<C::Scalar, Error> {
        let mut data = <C::Scalar as PrimeField>::Repr::default();
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
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
        let mut data = C::Repr::default();
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        let ec_point = Option::<C>::from(C::from_bytes(&data)).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid elliptic curve point encoding in proof".to_string(),
            )
        })?;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        W: Write,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    >
    PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        W,
        Poseidon<C::Scalar, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    pub fn stream_mut(&mut self) -> &mut W {
        &mut self.stream
    }

    pub fn finalize(self) -> W {
        self.stream
    }
}

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
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        S,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > halo2_proofs::transcript::Transcript<C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        S,
        Poseidon<C::Scalar, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn squeeze_challenge(&mut self) -> ChallengeScalar<C> {
        ChallengeScalar::new(&Transcript::squeeze_challenge(self))
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

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        R: Read,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > halo2_proofs::transcript::TranscriptRead<C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        R,
        Poseidon<C::Scalar, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
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

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        R: Read,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > halo2_proofs::transcript::TranscriptReadBuffer<R, C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        R,
        Poseidon<C::Scalar, T, RATE>,
        LIMBS,
        BITS,
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
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        W: Write,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > halo2_proofs::transcript::TranscriptWrite<C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        W,
        Poseidon<C::Scalar, T, RATE>,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn write_point(&mut self, ec_point: C) -> io::Result<()> {
        halo2_proofs::transcript::Transcript::<C, ChallengeScalar<C>>::common_point(
            self, ec_point,
        )?;
        let data = ec_point.to_bytes();
        self.stream_mut().write_all(data.as_ref())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        halo2_proofs::transcript::Transcript::<C, ChallengeScalar<C>>::common_scalar(self, scalar)?;
        let data = scalar.to_repr();
        self.stream_mut().write_all(data.as_ref())
    }
}

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar, LIMBS, BITS>,
        W: Write,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > halo2_proofs::transcript::TranscriptWriterBuffer<W, C, ChallengeScalar<C>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        NativeLoader,
        W,
        Poseidon<C::Scalar, T, RATE>,
        LIMBS,
        BITS,
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
