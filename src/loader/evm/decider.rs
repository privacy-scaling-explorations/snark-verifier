use crate::{
    loader::{evm::loader::EvmLoader, EcPointLoader},
    scheme::kzg::{AccumulationStrategy, MSM},
    util::{PrimeCurveAffine, PrimeField, UncompressedEncoding},
    Error,
};
use ethereum_types::U256;
use halo2_curves::{pairing::MultiMillerLoop, CurveAffine};
use std::{ops::Neg, rc::Rc};

pub struct EvmDecider<M: MultiMillerLoop>
where
    M::Scalar: PrimeField<Repr = [u8; 32]>,
    M::G1: UncompressedEncoding<Uncompressed = [u8; 64]>,
{
    g1: M::G1Affine,
    g2: M::G2Affine,
    s_g2: M::G2Affine,
}

impl<M: MultiMillerLoop> EvmDecider<M>
where
    M::Scalar: PrimeField<Repr = [u8; 32]>,
    M::G1: UncompressedEncoding<Uncompressed = [u8; 64]>,
{
    pub fn new(g1: M::G1Affine, g2: M::G2Affine, s_g2: M::G2Affine) -> Self {
        EvmDecider { g1, g2, s_g2 }
    }
}

impl<M: MultiMillerLoop, P> AccumulationStrategy<M::G1, Rc<EvmLoader>, P> for EvmDecider<M>
where
    M::Scalar: PrimeField<Repr = [u8; 32]>,
    M::G1: UncompressedEncoding<Uncompressed = [u8; 64]>,
{
    type Output = Vec<u8>;

    fn process(
        &mut self,
        loader: &Rc<EvmLoader>,
        _: P,
        lhs: MSM<M::G1, Rc<EvmLoader>>,
        rhs: MSM<M::G1, Rc<EvmLoader>>,
    ) -> Result<Self::Output, Error> {
        let g1 = loader.ec_point_load_const(&self.g1.to_curve());
        let evaluated_lhs = lhs.evaluate(g1.clone());
        let evaluated_rhs = rhs.evaluate(g1);

        let [g2, minus_s_g2] = [self.g2, self.s_g2.neg()].map(|ec_point| {
            let coordinates = ec_point.coordinates().unwrap();
            let x = coordinates.x().to_repr();
            let y = coordinates.y().to_repr();
            (
                U256::from_little_endian(&x.as_ref()[32..]),
                U256::from_little_endian(&x.as_ref()[..32]),
                U256::from_little_endian(&y.as_ref()[32..]),
                U256::from_little_endian(&y.as_ref()[..32]),
            )
        });
        loader.pairing(&evaluated_lhs, g2, &evaluated_rhs, minus_s_g2);

        Ok(loader.code())
    }
}
