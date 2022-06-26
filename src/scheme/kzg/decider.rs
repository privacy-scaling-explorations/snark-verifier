use crate::{
    loader::Loader,
    scheme::kzg::accumulation::{AccumulationStrategy, Accumulator},
    util::{Group, Transcript},
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

impl<M, L, T, P> AccumulationStrategy<M::G1, L, T, P> for NativeDecider<M>
where
    M: MultiMillerLoop,
    L: Loader<M::G1, LoadedEcPoint = M::G1, LoadedScalar = M::Scalar>,
    T: Transcript<M::G1, L>,
{
    type Output = bool;

    fn process(
        &mut self,
        loader: &L,
        _: P,
        accumulator: Accumulator<M::G1, L>,
    ) -> Result<Self::Output, Error> {
        let g1 = loader.ec_point_load_const(&self.g1.into());
        let lhs = accumulator.lhs.evaluate(g1);
        let rhs = accumulator.rhs.evaluate(g1);

        let g2 = M::G2Prepared::from(self.g2);
        let minus_s_g2 = M::G2Prepared::from(-self.s_g2);

        let terms = [(&lhs.into(), &g2), (&rhs.into(), &minus_s_g2)];
        Ok(M::multi_miller_loop(&terms)
            .final_exponentiation()
            .is_identity()
            .into())
    }
}
