use crate::{
    loader::evm::loader::EvmLoader,
    scheme::kzg::{AccumulationStrategy, Accumulator},
    util::{PrimeField, Transcript, UncompressedEncoding},
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

impl<M: MultiMillerLoop, T, P> AccumulationStrategy<M::G1, Rc<EvmLoader>, T, P> for EvmDecider<M>
where
    M::Scalar: PrimeField<Repr = [u8; 32]>,
    M::G1: UncompressedEncoding<Uncompressed = [u8; 64]>,
    T: Transcript<M::G1, Rc<EvmLoader>>,
{
    type Output = Vec<u8>;

    fn process(
        &mut self,
        loader: &Rc<EvmLoader>,
        _: &mut T,
        _: P,
        accumulator: Accumulator<M::G1, Rc<EvmLoader>>,
    ) -> Result<Self::Output, Error> {
        let (lhs, rhs) = accumulator.evaluate(self.g1.into());

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
        loader.pairing(&lhs, g2, &rhs, minus_s_g2);

        Ok(loader.code())
    }
}
