use crate::{
    collect_slice, halo2_native_accumulate, halo2_native_verify, halo2_prepare,
    loader::{halo2, native::NativeLoader},
    protocol::{
        halo2::{
            test::{MainGateWithRange, StandardPlonk, BITS, LIMBS},
            util::halo2::ChallengeScalar,
        },
        Protocol,
    },
    scheme::kzg::{self, AccumulationScheme, ShplonkAccumulationScheme},
    util::{fe_to_limbs, Curve, PrimeCurveAffine},
};
use halo2_curves::{
    bn256::{Fr, G1Affine, G1},
    CurveAffine,
};
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk,
    plonk::Circuit,
    poly::{
        commitment::ParamsProver,
        kzg::{
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::BatchVerifier,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use halo2_wrong_ecc;
use halo2_wrong_maingate::RegionCtx;
use halo2_wrong_transcript::NativeRepresentation;
use rand::RngCore;
use std::rc::Rc;

use super::MainGateWithRangeConfig;

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 57;

type BaseFieldEccChip<C> = halo2_wrong_ecc::BaseFieldEccChip<C, LIMBS, BITS>;
type Halo2Loader<'a, 'b, C> = halo2::Halo2Loader<'a, 'b, C, LIMBS, BITS>;
type PoseidonTranscript<C, L, S, B> =
    halo2::PoseidonTranscript<C, L, S, B, NativeRepresentation, LIMBS, BITS, T, RATE, R_F, R_P>;
type SameCurveAccumulation<C, L> = kzg::SameCurveAccumulation<C, L, LIMBS, BITS>;

pub struct Snark<C: CurveAffine> {
    protocol: Protocol<C::CurveExt>,
    statements: Vec<Vec<Value<C::Scalar>>>,
    proof: Value<Vec<u8>>,
}

impl<C: CurveAffine> Snark<C> {
    pub fn new(
        protocol: Protocol<C::CurveExt>,
        instances: Vec<Vec<C::Scalar>>,
        proof: Vec<u8>,
    ) -> Self {
        Snark {
            protocol,
            statements: instances
                .into_iter()
                .map(|instances| instances.into_iter().map(Value::known).collect::<Vec<_>>())
                .collect(),
            proof: Value::known(proof),
        }
    }

    pub fn without_witnesses(&self) -> Self {
        Snark {
            protocol: self.protocol.clone(),
            statements: self
                .statements
                .iter()
                .map(|statements| vec![Value::unknown(); statements.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }
}

pub struct OneLayerAccumulation {
    g1: G1Affine,
    snarks: Vec<Snark<G1Affine>>,
    instances: Vec<Fr>,
}

impl OneLayerAccumulation {
    pub fn rand<R: RngCore>(_: R) -> Self {
        const K: u32 = 9;
        const N: usize = 1;

        let (params, protocol1, instances1, proof1) = halo2_prepare!(
            [kzg],
            K, N, None, StandardPlonk::<_>,
            ProverSHPLONK<_>,
            VerifierSHPLONK<_>,
            BatchVerifier<_, _>,
            PoseidonTranscript<_, _, _, _>,
            PoseidonTranscript<_, _, _, _>,
            ChallengeScalar<_>
        );
        let (_, protocol2, instances2, proof2) = halo2_prepare!(
            [kzg],
            K, N, None, MainGateWithRange::<_>,
            ProverSHPLONK<_>,
            VerifierSHPLONK<_>,
            BatchVerifier<_, _>,
            PoseidonTranscript<_, _, _, _>,
            PoseidonTranscript<_, _, _, _>,
            ChallengeScalar<_>
        );

        let mut strategy = SameCurveAccumulation::<G1, NativeLoader>::default();
        halo2_native_accumulate!(
            [kzg],
            protocol1,
            instances1.clone(),
            ShplonkAccumulationScheme::default(),
            PoseidonTranscript::<G1Affine, _, _, _>::init(proof1.as_slice()),
            strategy
        );
        halo2_native_accumulate!(
            [kzg],
            protocol2,
            instances2.clone(),
            ShplonkAccumulationScheme::default(),
            PoseidonTranscript::<G1Affine, _, _, _>::init(proof2.as_slice()),
            strategy
        );

        let g1 = params.get_g()[0];
        let accumulator = strategy.finalize(g1.to_curve());
        let instances = [
            accumulator.0.to_affine().x,
            accumulator.0.to_affine().y,
            accumulator.1.to_affine().x,
            accumulator.1.to_affine().y,
        ]
        .map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .concat();

        Self {
            g1,
            snarks: vec![
                Snark::new(protocol1, instances1, proof1),
                Snark::new(protocol2, instances2, proof2),
            ],
            instances,
        }
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    fn accumulate<'a, 'b>(
        loader: &Rc<Halo2Loader<'a, 'b, G1Affine>>,
        stretagy: &mut SameCurveAccumulation<G1, Rc<Halo2Loader<'a, 'b, G1Affine>>>,
        snark: &Snark<G1Affine>,
    ) -> Result<(), plonk::Error> {
        let mut transcript = PoseidonTranscript::<_, Rc<Halo2Loader<G1Affine>>, _, _>::new(
            loader,
            snark.proof.as_ref().map(|proof| proof.as_slice()),
        );
        let statements = snark
            .statements
            .iter()
            .map(|statements| {
                statements
                    .iter()
                    .map(|statement| loader.assign_scalar(*statement))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        ShplonkAccumulationScheme::default()
            .accumulate(
                &snark.protocol,
                loader,
                statements,
                &mut transcript,
                stretagy,
            )
            .map_err(|_| plonk::Error::Synthesis)?;
        Ok(())
    }
}

impl Circuit<Fr> for OneLayerAccumulation {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            g1: self.g1,
            snarks: self.snarks.iter().map(Snark::without_witnesses).collect(),
            instances: Vec::new(),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        MainGateWithRangeConfig::configure::<Fr>(
            meta,
            BaseFieldEccChip::<G1Affine>::rns().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        config.load_table(&mut layouter, BITS / LIMBS)?;

        let (lhs, rhs) = layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;
                let ctx = RegionCtx::new(&mut region, &mut offset);

                let loader = Rc::new(Halo2Loader::<G1Affine>::new(config.ecc_config(), ctx));
                let mut stretagy = SameCurveAccumulation::default();
                for snark in self.snarks.iter() {
                    Self::accumulate(&loader, &mut stretagy, snark)?;
                }
                let (lhs, rhs) = stretagy.finalize(self.g1);

                dbg!(offset);

                Ok((lhs, rhs))
            },
        )?;

        let ecc_chip = BaseFieldEccChip::<G1Affine>::new(config.ecc_config());
        ecc_chip.expose_public(layouter.namespace(|| ""), lhs, 0)?;
        ecc_chip.expose_public(layouter.namespace(|| ""), rhs, 2 * LIMBS)?;

        Ok(())
    }
}

#[test]
#[ignore = "cause it requires 64GB ram to run"]
fn test_shplonk_halo2_one_layer_accumulation() {
    const K: u32 = 21;
    const N: usize = 1;

    let accumulator_indices = (0..4 * LIMBS).map(|idx| (0, idx)).collect();
    let (params, protocol, instances, proof) = halo2_prepare!(
        [kzg],
        K, N, Some(accumulator_indices), OneLayerAccumulation,
        ProverSHPLONK<_>,
        VerifierSHPLONK<_>,
        BatchVerifier<_, _>,
        Blake2bWrite<_, _, _>,
        Blake2bRead<_, _, _>,
        Challenge255<_>
    );

    halo2_native_verify!(
        [kzg],
        params,
        protocol,
        instances,
        ShplonkAccumulationScheme::default(),
        Blake2bRead::<_, G1Affine, _>::init(proof.as_slice())
    );
}
