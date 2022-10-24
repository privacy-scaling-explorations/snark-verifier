use crate::{
    util::{arithmetic::CurveAffine, Itertools},
    Protocol,
};
use halo2_proofs::circuit::Value;

pub struct Snark<C: CurveAffine> {
    pub protocol: Protocol<C>,
    pub instances: Vec<Vec<C::Scalar>>,
    pub proof: Vec<u8>,
}

impl<C: CurveAffine> Snark<C> {
    pub fn new(protocol: Protocol<C>, instances: Vec<Vec<C::Scalar>>, proof: Vec<u8>) -> Self {
        assert_eq!(
            protocol.num_instance,
            instances
                .iter()
                .map(|instances| instances.len())
                .collect_vec()
        );
        Snark {
            protocol,
            instances,
            proof,
        }
    }
}

pub struct SnarkWitness<C: CurveAffine> {
    pub protocol: Protocol<C>,
    pub instances: Vec<Vec<Value<C::Scalar>>>,
    pub proof: Value<Vec<u8>>,
}

impl<C: CurveAffine> From<Snark<C>> for SnarkWitness<C> {
    fn from(snark: Snark<C>) -> Self {
        Self {
            protocol: snark.protocol,
            instances: snark
                .instances
                .into_iter()
                .map(|instances| instances.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

impl<C: CurveAffine> SnarkWitness<C> {
    pub fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            instances: self
                .instances
                .iter()
                .map(|instances| vec![Value::unknown(); instances.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }

    pub fn proof(&self) -> Value<&[u8]> {
        self.proof.as_ref().map(Vec::as_slice)
    }
}
