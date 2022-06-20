use crate::{
    loader::Loader,
    scheme::kzg::{accumulator::AccumulationStrategy, msm::MSM},
    util::Group,
    Error,
};
use halo2_curves::pairing::{MillerLoopResult, MultiMillerLoop};

pub struct NativeDecider<M: MultiMillerLoop> {
    g1: M::G1Affine,
    g2: M::G2Affine,
    s_g2: M::G2Affine,
}

impl<M: MultiMillerLoop> NativeDecider<M> {
    pub fn new(g1: M::G1Affine, g2: M::G2Affine, s_g2: M::G2Affine) -> Self {
        NativeDecider { g1, g2, s_g2 }
    }
}

impl<M, L, P> AccumulationStrategy<M::G1, L, P> for NativeDecider<M>
where
    M: MultiMillerLoop,
    L: Loader<M::G1, LoadedEcPoint = M::G1, LoadedScalar = M::Scalar>,
{
    type Output = bool;

    fn process(
        &mut self,
        loader: &L,
        _: P,
        lhs: MSM<M::G1, L>,
        rhs: MSM<M::G1, L>,
    ) -> Result<Self::Output, Error> {
        let g2 = M::G2Prepared::from(self.g2);
        let minus_s_g2 = M::G2Prepared::from(-self.s_g2);

        let lhs = lhs.evaluate(loader.ec_point_load_const(&self.g1.into()));
        let rhs = rhs.evaluate(loader.ec_point_load_const(&self.g1.into()));

        Ok(
            M::multi_miller_loop(&[(&lhs.into(), &g2), (&rhs.into(), &minus_s_g2)])
                .final_exponentiation()
                .is_identity()
                .into(),
        )
    }
}
