use crate::{
    loader::{
        halo2::loader::{EcPoint, Halo2Loader, Scalar, Value},
        native::NativeLoader,
    },
    util::{Curve, GroupEncoding, PrimeField, Transcript, TranscriptRead},
    Error,
};
use halo2_curves::{Coordinates, CurveAffine};
use halo2_proofs::circuit;
use halo2_wrong_ecc::integer::rns::{Common, Integer, Rns};
use halo2_wrong_transcript::{NativeRepresentation, PointRepresentation, TranscriptChip};
use poseidon::{Poseidon, Spec};
use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    rc::Rc,
};

pub struct PoseidonTranscript<
    C: CurveAffine,
    L,
    S,
    B,
    E: PointRepresentation<C, LIMBS, BITS>,
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
    rns: Rc<Rns<C::Base, C::Scalar, LIMBS, BITS>>,
    _marker: PhantomData<(C, E)>,
}

impl<
        'a,
        'b,
        C: CurveAffine,
        R: Read,
        E: PointRepresentation<C, LIMBS, BITS>,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    >
    PoseidonTranscript<
        C,
        Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
        circuit::Value<R>,
        TranscriptChip<E, C, LIMBS, BITS, T, RATE>,
        E,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    pub fn new(
        loader: &Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
        stream: circuit::Value<R>,
    ) -> Self {
        let transcript_chip = TranscriptChip::new(
            &mut loader.ctx_mut(),
            &Spec::new(R_F, R_P),
            loader.ecc_chip().clone(),
        )
        .unwrap();
        Self {
            loader: loader.clone(),
            stream,
            buf: transcript_chip,
            rns: Rc::new(Rns::<C::Base, C::Scalar, LIMBS, BITS>::construct()),
            _marker: PhantomData,
        }
    }
}

impl<
        'a,
        'b,
        C: CurveAffine,
        R: Read,
        E: PointRepresentation<C, LIMBS, BITS>,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > Transcript<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>
    for PoseidonTranscript<
        C,
        Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
        circuit::Value<R>,
        TranscriptChip<E, C, LIMBS, BITS, T, RATE>,
        E,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn squeeze_challenge(&mut self) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let assigned = self.buf.squeeze(&mut self.loader.ctx_mut()).unwrap();
        self.loader.scalar(Value::Assigned(assigned))
    }

    fn common_scalar(&mut self, scalar: &Scalar<'a, 'b, C, LIMBS, BITS>) -> Result<(), Error> {
        self.buf.write_scalar(&scalar.assigned());
        Ok(())
    }

    fn common_ec_point(&mut self, ec_point: &EcPoint<'a, 'b, C, LIMBS, BITS>) -> Result<(), Error> {
        self.buf
            .write_point(&mut self.loader.ctx_mut(), &ec_point.assigned())
            .unwrap();
        Ok(())
    }
}

impl<
        'a,
        'b,
        C: CurveAffine,
        R: Read,
        E: PointRepresentation<C, LIMBS, BITS>,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptRead<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>
    for PoseidonTranscript<
        C,
        Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
        circuit::Value<R>,
        TranscriptChip<E, C, LIMBS, BITS, T, RATE>,
        E,
        LIMBS,
        BITS,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn read_scalar(&mut self) -> Result<Scalar<'a, 'b, C, LIMBS, BITS>, Error> {
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

    fn read_ec_point(&mut self) -> Result<EcPoint<'a, 'b, C, LIMBS, BITS>, Error> {
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
        S,
        E: PointRepresentation<C, LIMBS, BITS>,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    >
    PoseidonTranscript<
        C,
        NativeLoader,
        S,
        Poseidon<C::Scalar, T, RATE>,
        E,
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
            rns: Rc::new(Rns::<C::Base, C::Scalar, LIMBS, BITS>::construct()),
            _marker: PhantomData,
        }
    }
}

impl<
        C: CurveAffine,
        S,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > Transcript<C::CurveExt, NativeLoader>
    for PoseidonTranscript<
        C,
        NativeLoader,
        S,
        Poseidon<C::Scalar, T, RATE>,
        NativeRepresentation,
        LIMBS,
        BITS,
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
        let coords: Coordinates<C> =
            Option::from(ec_point.to_affine().coordinates()).ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Cannot write points at infinity to the transcript".to_string(),
                )
            })?;
        let x = Integer::from_fe(*coords.x(), self.rns.clone());
        let y = Integer::from_fe(*coords.y(), self.rns.clone());
        self.buf.update(&[x.native(), y.native()]);
        Ok(())
    }
}

impl<
        C: CurveAffine,
        R: Read,
        const LIMBS: usize,
        const BITS: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptRead<C::CurveExt, NativeLoader>
    for PoseidonTranscript<
        C,
        NativeLoader,
        R,
        Poseidon<C::Scalar, T, RATE>,
        NativeRepresentation,
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
        NativeLoader,
        W,
        Poseidon<C::Scalar, T, RATE>,
        NativeRepresentation,
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
