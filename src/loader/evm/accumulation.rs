use crate::{
    loader::evm::loader::{EvmLoader, Scalar},
    protocol::Protocol,
    scheme::kzg::{AccumulationStrategy, Accumulator, SameCurveAccumulation, MSM},
    util::{Curve, Itertools, PrimeCurveAffine, PrimeField, Transcript, UncompressedEncoding},
    Error,
};
use ethereum_types::U256;
use halo2_curves::{
    bn256::{G1Affine, G2Affine, G1},
    CurveAffine, CurveExt,
};
use std::{iter, ops::Neg, rc::Rc};

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
            .collect_vec()
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

impl<const LIMBS: usize, const BITS: usize> SameCurveAccumulation<G1, Rc<EvmLoader>, LIMBS, BITS> {
    pub fn code(self, g1: G1Affine, g2: G2Affine, s_g2: G2Affine) -> Vec<u8> {
        let (lhs, rhs) = self.accumulator.unwrap().evaluate(g1.to_curve());
        let loader = lhs.loader();

        let [g2, minus_s_g2] = [g2, s_g2.neg()].map(|ec_point| {
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

        loader.code()
    }
}

impl<C: Curve, T, P, const LIMBS: usize, const BITS: usize>
    AccumulationStrategy<C, Rc<EvmLoader>, T, P>
    for SameCurveAccumulation<C, Rc<EvmLoader>, LIMBS, BITS>
where
    C::Scalar: PrimeField<Repr = [u8; 32]>,
    C: UncompressedEncoding<Uncompressed = [u8; 64]>,
    T: Transcript<C, Rc<EvmLoader>>,
{
    type Output = ();

    fn extract_accumulator(
        &self,
        protocol: &Protocol<C>,
        loader: &Rc<EvmLoader>,
        transcript: &mut T,
        statements: &[Vec<Scalar>],
    ) -> Option<Accumulator<C, Rc<EvmLoader>>> {
        let accumulator_indices = protocol.accumulator_indices.as_ref()?;

        let num_statements = statements
            .iter()
            .map(|statements| statements.len())
            .collect_vec();

        let challenges = transcript.squeeze_n_challenges(accumulator_indices.len());
        let accumulators = accumulator_indices
            .iter()
            .map(|indices| {
                assert_eq!(indices.len(), 4 * LIMBS);
                assert!(indices
                    .iter()
                    .enumerate()
                    .all(|(idx, index)| indices[0] == (index.0, index.1 - idx)));
                let offset =
                    (num_statements[..indices[0].0].iter().sum::<usize>() + indices[0].1) * 0x20;
                let lhs = loader.calldataload_ec_point_from_limbs::<LIMBS, BITS>(offset);
                let rhs = loader.calldataload_ec_point_from_limbs::<LIMBS, BITS>(offset + 0x100);
                Accumulator::new(MSM::base(lhs), MSM::base(rhs))
            })
            .collect_vec();

        Some(Accumulator::random_linear_combine(
            challenges.into_iter().zip(accumulators),
        ))
    }

    fn process(
        &mut self,
        _: &Rc<EvmLoader>,
        transcript: &mut T,
        _: P,
        accumulator: Accumulator<C, Rc<EvmLoader>>,
    ) -> Result<Self::Output, Error> {
        self.accumulator = Some(match self.accumulator.take() {
            Some(curr_accumulator) => {
                accumulator + curr_accumulator * &transcript.squeeze_challenge()
            }
            None => accumulator,
        });
        Ok(())
    }
}
