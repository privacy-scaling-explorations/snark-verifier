use crate::{
    loader::{native::NativeLoader, Loader},
    {util::arithmetic::CurveAffine, Error},
};

pub trait Transcript<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn loader(&self) -> &L;

    fn squeeze_challenge(&mut self) -> L::LoadedScalar;

    fn squeeze_n_challenges(&mut self, n: usize) -> Vec<L::LoadedScalar> {
        (0..n).map(|_| self.squeeze_challenge()).collect()
    }

    fn common_ec_point(&mut self, ec_point: &L::LoadedEcPoint) -> Result<(), Error>;

    fn common_scalar(&mut self, scalar: &L::LoadedScalar) -> Result<(), Error>;
}

pub trait TranscriptRead<C, L>: Transcript<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn read_scalar(&mut self) -> Result<L::LoadedScalar, Error>;

    fn read_n_scalars(&mut self, n: usize) -> Result<Vec<L::LoadedScalar>, Error> {
        (0..n).map(|_| self.read_scalar()).collect()
    }

    fn read_ec_point(&mut self) -> Result<L::LoadedEcPoint, Error>;

    fn read_n_ec_points(&mut self, n: usize) -> Result<Vec<L::LoadedEcPoint>, Error> {
        (0..n).map(|_| self.read_ec_point()).collect()
    }
}

pub trait TranscriptWrite<C: CurveAffine>: Transcript<C, NativeLoader> {
    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<(), Error>;

    fn write_ec_point(&mut self, ec_point: C) -> Result<(), Error>;
}
