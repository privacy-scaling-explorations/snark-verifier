use crate::{util::arithmetic::CurveAffine, Protocol};
use halo2_proofs::circuit;
use std::rc::Rc;

pub(crate) mod loader;
mod shim;

#[cfg(test)]
pub(crate) mod test;

pub use loader::{EcPoint, Halo2Loader, Scalar};
pub use shim::{Context, EccInstructions, IntegerInstructions};
pub use util::Valuetools;

pub use halo2_wrong_ecc;

mod util {
    use halo2_proofs::circuit::Value;

    pub trait Valuetools<V>: Iterator<Item = Value<V>> {
        fn fold_zipped<B, F>(self, init: B, mut f: F) -> Value<B>
        where
            Self: Sized,
            F: FnMut(B, V) -> B,
        {
            self.fold(Value::known(init), |acc, value| {
                acc.zip(value).map(|(acc, value)| f(acc, value))
            })
        }
    }

    impl<V, I: Iterator<Item = Value<V>>> Valuetools<V> for I {}
}

impl<C> Protocol<C>
where
    C: CurveAffine,
{
    pub fn loaded_preprocessed_as_witness<'a, EccChip: EccInstructions<'a, C>>(
        &self,
        loader: &Rc<Halo2Loader<'a, C, EccChip>>,
    ) -> Protocol<C, Rc<Halo2Loader<'a, C, EccChip>>> {
        let preprocessed = self
            .preprocessed
            .iter()
            .map(|preprocessed| loader.assign_ec_point(circuit::Value::known(*preprocessed)))
            .collect();
        let transcript_initial_state =
            self.transcript_initial_state
                .as_ref()
                .map(|transcript_initial_state| {
                    loader.assign_scalar(circuit::Value::known(*transcript_initial_state))
                });
        Protocol {
            domain: self.domain.clone(),
            preprocessed,
            num_instance: self.num_instance.clone(),
            num_witness: self.num_witness.clone(),
            num_challenge: self.num_challenge.clone(),
            evaluations: self.evaluations.clone(),
            queries: self.queries.clone(),
            quotient: self.quotient.clone(),
            transcript_initial_state,
            instance_committing_key: self.instance_committing_key.clone(),
            linearization: self.linearization.clone(),
            accumulator_indices: self.accumulator_indices.clone(),
        }
    }
}
