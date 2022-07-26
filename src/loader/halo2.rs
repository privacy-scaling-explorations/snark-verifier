use halo2_proofs::circuit::Value;

mod accumulation;
mod loader;
mod transcript;

pub use loader::Halo2Loader;
pub use transcript::PoseidonTranscript;

pub trait Valuetools<V>: Iterator<Item = Value<V>> {
    fn fold_zipped<B, F>(self, init: B, mut f: F) -> Value<B>
    where
        Self: Sized,
        F: FnMut(B, V) -> B,
    {
        self.into_iter().fold(Value::known(init), |acc, value| {
            acc.zip(value).map(|(acc, value)| f(acc, value))
        })
    }
}

impl<V, I: Iterator<Item = Value<V>>> Valuetools<V> for I {}
