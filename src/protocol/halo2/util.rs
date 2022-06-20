use crate::util::{PrimeCurveAffine, PrimeField, UncompressedEncoding};
use halo2_proofs::arithmetic::{CurveAffine, CurveExt};
use std::iter;

impl<C: CurveExt> UncompressedEncoding for C
where
    <C::AffineExt as CurveAffine>::Base: PrimeField<Repr = [u8; 32]>,
{
    type Uncompressed = [u8; 64];

    fn to_uncompressed(&self) -> [u8; 64] {
        let coordinates = self.to_affine().coordinates().unwrap();
        iter::empty()
            .chain(coordinates.x().to_repr().as_ref())
            .chain(coordinates.y().to_repr().as_ref())
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn from_uncompressed(uncompressed: [u8; 64]) -> Option<Self> {
        let x = Option::from(<C::AffineExt as CurveAffine>::Base::from_repr(
            uncompressed[..32].to_vec().try_into().unwrap(),
        ))?;
        let y = Option::from(<C::AffineExt as CurveAffine>::Base::from_repr(
            uncompressed[32..].to_vec().try_into().unwrap(),
        ))?;
        C::AffineExt::from_xy(x, y)
            .map(|ec_point| ec_point.to_curve())
            .into()
    }
}
