// This is mostly a generalization of `snark_verifier::examples::evm-verifier-with-accumulators`
use super::PlonkSuccinctVerifier;
use crate::{SnarkWitness, BITS, LIMBS};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{self, Circuit, ConstraintSystem, Selector},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use halo2_wrong_ecc::{
    integer::rns::Rns,
    maingate::{
        MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
        RegionCtx,
    },
    EccConfig,
};
use halo2curves::{bn256::Fq, ff::PrimeField};
use itertools::Itertools;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use snark_verifier::util::arithmetic::fe_to_limbs;
use snark_verifier::{
    loader::{self, halo2::EccInstructions, native::NativeLoader},
    pcs::{
        kzg::{
            KzgAccumulator, KzgAsProvingKey, KzgAsVerifyingKey, KzgSuccinctVerifyingKey,
            LimbsEncodingInstructions,
        },
        AccumulationScheme, AccumulationSchemeProver, PolynomialCommitmentScheme,
    },
    verifier::SnarkVerifier,
};
use std::{fs::File, marker::PhantomData, path::Path, rc::Rc};

use super::{CircuitExt, PoseidonTranscript, Snark, POSEIDON_SPEC};

pub type Svk = KzgSuccinctVerifyingKey<G1Affine>;
pub type BaseFieldEccChip = halo2_wrong_ecc::BaseFieldEccChip<G1Affine, LIMBS, BITS>;
pub type Halo2Loader<'a> = loader::halo2::Halo2Loader<'a, G1Affine, BaseFieldEccChip>;

#[allow(clippy::type_complexity)]
/// Core function used in `synthesize` to aggregate multiple `snarks`.
///  
/// Returns the assigned instances of previous snarks and the new final pair that needs to be verified in a pairing check.
/// For each previous snark, we concatenate all instances into a single vector. We return a vector of vectors,
/// one vector per snark, for convenience.
///
/// # Assumptions
/// * `snarks` is not empty
pub fn aggregate<'a, AS>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    snarks: &[SnarkWitness],
    as_proof: Value<&'_ [u8]>,
) -> (
    Vec<Vec<<BaseFieldEccChip as EccInstructions<'a, G1Affine>>::AssignedCell>>, // this is Vec<Vec<AssignedCell<Fr, Fr>>>, but we note what the actual trait type is for future reference
    KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
)
where
    AS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            VerifyingKey = Svk,
            Output = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        > + AccumulationScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
            VerifyingKey = KzgAsVerifyingKey,
        >,
{
    assert!(!snarks.is_empty(), "trying to aggregate 0 snarks");
    let assign_instances = |instances: &[Vec<Value<Fr>>]| {
        instances
            .iter()
            .map(|instances| {
                instances
                    .iter()
                    .map(|instance| loader.assign_scalar(*instance))
                    .collect_vec()
            })
            .collect_vec()
    };

    let mut previous_instances = Vec::with_capacity(snarks.len());
    let mut accumulators = snarks
        .iter()
        .flat_map(|snark| {
            let protocol = snark.protocol.loaded(loader);
            let instances = assign_instances(&snark.instances);
            // read the transcript and perform Fiat-Shamir
            // run through verification computation and produce the final pair `succinct`
            let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::from_spec(
                loader,
                snark.proof(),
                POSEIDON_SPEC.clone(),
            );
            let proof = PlonkSuccinctVerifier::<AS>::read_proof(
                svk,
                &protocol,
                &instances,
                &mut transcript,
            )
            .unwrap();
            let accumulator =
                PlonkSuccinctVerifier::<AS>::verify(svk, &protocol, &instances, &proof).unwrap();

            previous_instances.push(
                instances
                    .into_iter()
                    .flatten()
                    .map(|scalar| scalar.into_assigned())
                    .collect(),
            );

            accumulator
        })
        .collect_vec();

    let accumulator = if accumulators.len() > 1 {
        let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::from_spec(
            loader,
            as_proof,
            POSEIDON_SPEC.clone(),
        );
        let proof = <AS as AccumulationScheme<_, _>>::read_proof(
            &Default::default(),
            &accumulators,
            &mut transcript,
        )
        .unwrap();
        <AS as AccumulationScheme<_, _>>::verify(&Default::default(), &accumulators, &proof)
            .unwrap()
    } else {
        accumulators.pop().unwrap()
    };

    (previous_instances, accumulator)
}

/// `AS` should be the [`AccumulationScheme`] and [`PolynomialCommitmentScheme`] used to create `snarks`.
/// Many things will fail if `AS` does not match how `snarks` were actually created.
///
/// In practice, `AS` is either `SHPLONK` or `GWC`.
#[derive(Clone)]
pub struct AggregationCircuit<AS> {
    svk: Svk,
    pub snarks: Vec<SnarkWitness>,
    instances: Vec<Fr>,
    as_proof: Value<Vec<u8>>,
    _as: PhantomData<AS>,
}

impl<AS> AggregationCircuit<AS>
// without unstable rust, I don't know how to make this where clause go away...
where
    for<'a> AS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            VerifyingKey = Svk,
            Output = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        > + AccumulationScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
            VerifyingKey = KzgAsVerifyingKey,
        > + PolynomialCommitmentScheme<
            G1Affine,
            NativeLoader,
            VerifyingKey = Svk,
            Output = KzgAccumulator<G1Affine, NativeLoader>,
        > + AccumulationScheme<
            G1Affine,
            NativeLoader,
            Accumulator = KzgAccumulator<G1Affine, NativeLoader>,
            VerifyingKey = KzgAsVerifyingKey,
        > + AccumulationSchemeProver<G1Affine, ProvingKey = KzgAsProvingKey<G1Affine>>,
{
    /// Given snarks, this creates a circuit and runs the `GateThreadBuilder` to verify all the snarks.
    /// By default, the returned circuit has public instances equal to the limbs of the pair of elliptic curve points, referred to as the `accumulator`, that need to be verified in a final pairing check.
    ///
    /// The user can optionally modify the circuit after calling this function to add more instances to `assigned_instances` to expose.
    ///
    /// Warning: will fail silently if `snarks` were created using a different multi-open scheme than `AS`
    /// where `AS` can be either [`crate::SHPLONK`] or [`crate::GWC`] (for original PLONK multi-open scheme)
    pub fn new(params: &ParamsKZG<Bn256>, snarks: impl IntoIterator<Item = Snark>) -> Self {
        let svk: Svk = params.get_g()[0].into();
        let snarks = snarks.into_iter().collect_vec();

        // TODO: the snarks can probably store these accumulators
        let accumulators = snarks
            .iter()
            .flat_map(|snark| {
                let mut transcript_read = PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(
                    snark.proof(),
                    POSEIDON_SPEC.clone(),
                );
                let proof = PlonkSuccinctVerifier::<AS>::read_proof(
                    &svk,
                    &snark.protocol,
                    &snark.instances,
                    &mut transcript_read,
                )
                .unwrap();
                PlonkSuccinctVerifier::<AS>::verify(&svk, &snark.protocol, &snark.instances, &proof)
                    .unwrap()
            })
            .collect_vec();

        let (accumulator, as_proof) = {
            let mut transcript_write = PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(
                vec![],
                POSEIDON_SPEC.clone(),
            );
            let rng = StdRng::from_entropy();
            let accumulator = AS::create_proof(
                &Default::default(),
                &accumulators,
                &mut transcript_write,
                rng,
            )
            .unwrap();
            (accumulator, transcript_write.finalize())
        };

        let KzgAccumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .concat();

        Self {
            svk,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
            as_proof: Value::known(as_proof),
            _as: PhantomData,
        }
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(|proof| proof.as_slice())
    }

    pub fn instance(&self) -> &[Fr] {
        &self.instances
    }

    /// In a single Halo2 region, aggregates previous snarks but does not expose public instances.
    ///
    /// Returns `(accumulator_limbs, prev_instances)` as `AssignedCell`s.
    ///
    /// The `accumulator_limbs` **must** be exposed as public instances.
    /// One can create a wrapper circuit around `Self` to expose more instances from `prev_instances` as necessary.
    ///
    /// # Assumptions
    /// * RangeChip lookup table has already been loaded
    #[allow(clippy::type_complexity)]
    pub fn aggregation_region(
        &self,
        config: AggregationConfig,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(Vec<AssignedCell<Fr, Fr>>, Vec<Vec<AssignedCell<Fr, Fr>>>), plonk::Error> {
        layouter.assign_region(
            || "",
            |region| {
                let ctx = RegionCtx::new(region, 0);

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::new(ecc_chip, ctx);
                let (prev_instances, accumulator) =
                    aggregate::<AS>(&self.svk, &loader, &self.snarks, self.as_proof());

                let accumulator_limbs = [accumulator.lhs, accumulator.rhs]
                    .iter()
                    .map(|ec_point| {
                        loader
                            .ecc_chip()
                            .assign_ec_point_to_limbs(&mut loader.ctx_mut(), ec_point.assigned())
                    })
                    .collect::<Result<Vec<_>, plonk::Error>>()?
                    .into_iter()
                    .flatten()
                    .collect_vec();

                Ok((accumulator_limbs, prev_instances))
            },
        )
    }
}

#[derive(Clone)]
pub struct AggregationConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl AggregationConfig {
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        composition_bits: Vec<usize>,
        overflow_bits: Vec<usize>,
    ) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        let range_config =
            RangeChip::<F>::configure(meta, &main_gate_config, composition_bits, overflow_bits);
        AggregationConfig {
            main_gate_config,
            range_config,
        }
    }

    pub fn main_gate(&self) -> MainGate<Fr> {
        MainGate::new(self.main_gate_config.clone())
    }

    pub fn range_chip(&self) -> RangeChip<Fr> {
        RangeChip::new(self.range_config.clone())
    }

    pub fn ecc_chip(&self) -> BaseFieldEccChip {
        BaseFieldEccChip::new(EccConfig::new(
            self.range_config.clone(),
            self.main_gate_config.clone(),
        ))
    }
}

impl<AS> Circuit<Fr> for AggregationCircuit<AS>
// without unstable rust, I don't know how to make this where clause go away...
where
    for<'a> AS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            VerifyingKey = Svk,
            Output = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        > + AccumulationScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
            VerifyingKey = KzgAsVerifyingKey,
        > + PolynomialCommitmentScheme<
            G1Affine,
            NativeLoader,
            VerifyingKey = Svk,
            Output = KzgAccumulator<G1Affine, NativeLoader>,
        > + AccumulationScheme<
            G1Affine,
            NativeLoader,
            Accumulator = KzgAccumulator<G1Affine, NativeLoader>,
            VerifyingKey = KzgAsVerifyingKey,
        > + AccumulationSchemeProver<G1Affine, ProvingKey = KzgAsProvingKey<G1Affine>>,
{
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "halo2_circuit_params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: Vec::new(),
            as_proof: Value::unknown(),
            _as: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        AggregationConfig::configure(
            meta,
            vec![BITS / LIMBS],
            Rns::<Fq, Fr, LIMBS, BITS>::construct().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        let main_gate = config.main_gate();
        let range_chip = config.range_chip();
        range_chip.load_table(&mut layouter)?;

        let (accumulator_limbs, _) = self.aggregation_region(config, &mut layouter)?;

        for (row, limb) in accumulator_limbs.into_iter().enumerate() {
            main_gate.expose_public(layouter.namespace(|| ""), limb, row)?;
        }
        // @dev: one could expose more instances here if necessary
        Ok(())
    }
}

impl<AS> CircuitExt<Fr> for AggregationCircuit<AS>
// without unstable rust, I don't know how to make this where clause go away...
where
    for<'a> AS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            VerifyingKey = Svk,
            Output = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        > + AccumulationScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
            VerifyingKey = KzgAsVerifyingKey,
        > + PolynomialCommitmentScheme<
            G1Affine,
            NativeLoader,
            VerifyingKey = Svk,
            Output = KzgAccumulator<G1Affine, NativeLoader>,
        > + AccumulationScheme<
            G1Affine,
            NativeLoader,
            Accumulator = KzgAccumulator<G1Affine, NativeLoader>,
            VerifyingKey = KzgAsVerifyingKey,
        > + AccumulationSchemeProver<G1Affine, ProvingKey = KzgAsProvingKey<G1Affine>>,
{
    fn num_instance(&self) -> Vec<usize> {
        vec![self.instances.len()]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
    }
}
