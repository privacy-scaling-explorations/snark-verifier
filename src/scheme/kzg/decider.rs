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
        let g1 = loader.ec_point_load_const(&self.g1.into());
        let evaluated_lhs = lhs.evaluate(g1);
        let evaluated_rhs = rhs.evaluate(g1);

        let g2 = M::G2Prepared::from(self.g2);
        let minus_s_g2 = M::G2Prepared::from(-self.s_g2);

        let terms = [
            (&evaluated_lhs.into(), &g2),
            (&evaluated_rhs.into(), &minus_s_g2),
        ];
        Ok(M::multi_miller_loop(&terms)
            .final_exponentiation()
            .is_identity()
            .into())
    }
}
