use crate::{
    loader::{
        halo2::loader::{EcPoint, Halo2Loader, Scalar, Value},
        native::NativeLoader,
    },
    util::{Curve, GroupEncoding, PrimeField, Transcript, TranscriptRead},
    Error,
};
use halo2_curves::{CurveAffine, FieldExt};
use halo2_proofs::circuit;
use halo2_wrong_ecc::{maingate::AssignedValue, EccInstructions};
use halo2_wrong_transcript::{PointRepresentation, TranscriptChip};
use poseidon::{Poseidon, Spec};
use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    rc::Rc,
};

pub struct PoseidonTranscript<
    C: CurveAffine,
    N: FieldExt,
    E: PointRepresentation<C, N>,
    L,
    S,
    B,
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
        E: PointRepresentation<C, C::Scalar, EccChip = EccChip>,
        EccChip: EccInstructions<
            C,
            C::Scalar,
            Scalar = C::Scalar,
            AssignedScalar = AssignedValue<C::Scalar>,
        >,
        R: Read,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    >
    PoseidonTranscript<
        C,
        C::Scalar,
        E,
        Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>,
        circuit::Value<R>,
        TranscriptChip<C, C::Scalar, EccChip, E, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    pub fn new(
        loader: &Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>,
        stream: circuit::Value<R>,
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
        E: PointRepresentation<C, C::Scalar, EccChip = EccChip>,
        EccChip: EccInstructions<
            C,
            C::Scalar,
            Scalar = C::Scalar,
            AssignedScalar = AssignedValue<C::Scalar>,
        >,
        R: Read,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > Transcript<C::CurveExt, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>,
        circuit::Value<R>,
        TranscriptChip<C, C::Scalar, EccChip, E, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn squeeze_challenge(&mut self) -> Scalar<'a, C, C::Scalar, EccChip> {
        let assigned = self.buf.squeeze(&mut self.loader.ctx_mut()).unwrap();
        self.loader.scalar(Value::Assigned(assigned))
    }

    fn common_scalar(&mut self, scalar: &Scalar<'a, C, C::Scalar, EccChip>) -> Result<(), Error> {
        self.buf.write_scalar(&scalar.assigned());
        Ok(())
    }

    fn common_ec_point(
        &mut self,
        ec_point: &EcPoint<'a, C, C::Scalar, EccChip>,
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
        E: PointRepresentation<C, C::Scalar, EccChip = EccChip>,
        EccChip: EccInstructions<
            C,
            C::Scalar,
            Scalar = C::Scalar,
            AssignedScalar = AssignedValue<C::Scalar>,
        >,
        R: Read,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptRead<C::CurveExt, Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>>
    for PoseidonTranscript<
        C,
        C::Scalar,
        E,
        Rc<Halo2Loader<'a, C, C::Scalar, EccChip>>,
        circuit::Value<R>,
        TranscriptChip<C, C::Scalar, EccChip, E, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn read_scalar(&mut self) -> Result<Scalar<'a, C, C::Scalar, EccChip>, Error> {
        let scalar = self.stream.as_mut().and_then(|stream| {
            let mut data = <C::Scalar as PrimeField>::Repr::default();
            if stream.read_exact(data.as_mut()).is_err() {
                return circuit::Value::unknown();
            }
            Option::<C::Scalar>::from(C::Scalar::from_repr(data))
                .map(circuit::Value::known)
                .unwrap_or_else(circuit::Value::unknown)
        });
        let scalar = self.loader.assign_scalar(scalar);
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<EcPoint<'a, C, C::Scalar, EccChip>, Error> {
        let ec_point = self.stream.as_mut().and_then(|stream| {
            let mut compressed = C::Repr::default();
            if stream.read_exact(compressed.as_mut()).is_err() {
                return circuit::Value::unknown();
            }
            Option::<C>::from(C::from_bytes(&compressed))
                .map(circuit::Value::known)
                .unwrap_or_else(circuit::Value::unknown)
        });
        let ec_point = self.loader.assign_ec_point(ec_point);
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
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
    >
    PoseidonTranscript<
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
        E: PointRepresentation<C, C::Scalar>,
        S,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > Transcript<C::CurveExt, NativeLoader>
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
    fn squeeze_challenge(&mut self) -> C::Scalar {
        self.buf.squeeze()
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        self.buf.update(&[*scalar]);
        Ok(())
    }

    fn common_ec_point(&mut self, ec_point: &C::CurveExt) -> Result<(), Error> {
        E::encode_plain(ec_point.to_affine())
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
        E: PointRepresentation<C, C::Scalar>,
        R: Read,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptRead<C::CurveExt, NativeLoader>
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

    fn read_ec_point(&mut self) -> Result<C::CurveExt, Error> {
        let mut data = C::Repr::default();
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        let ec_point = Option::<C::CurveExt>::from(
            <C as GroupEncoding>::from_bytes(&data).map(|ec_point| ec_point.to_curve()),
        )
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

impl<
        C: CurveAffine,
        E: PointRepresentation<C, C::Scalar>,
        W: Write,
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
