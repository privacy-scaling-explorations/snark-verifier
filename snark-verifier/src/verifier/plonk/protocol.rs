use crate::{
    loader::{native::NativeLoader, LoadedScalar, Loader},
    util::{
        arithmetic::{CurveAffine, Domain, Field, Fraction, Rotation},
        Itertools,
    },
};
use num_traits::One;
use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    iter::{self, Sum},
    ops::{Add, Mul, Neg, Sub},
};

/// Protocol specifying configuration of a PLONK.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive_serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PlonkProtocol<C, L = NativeLoader>
where
    C: CurveAffine,
    L: Loader<C>,
{
    #[cfg_attr(
        feature = "derive_serde",
        serde(bound(
            serialize = "C::Scalar: serde::Serialize",
            deserialize = "C::Scalar: serde::Deserialize<'de>"
        ))
    )]
    /// Working domain.
    pub domain: Domain<C::Scalar>,
    #[cfg_attr(
        feature = "derive_serde",
        serde(bound(
            serialize = "L::LoadedEcPoint: serde::Serialize",
            deserialize = "L::LoadedEcPoint: serde::Deserialize<'de>"
        ))
    )]
    /// Commitments of preprocessed polynomials.
    pub preprocessed: Vec<L::LoadedEcPoint>,
    /// Number of instances in each instance polynomial.
    pub num_instance: Vec<usize>,
    /// Number of witness polynomials in each phase.
    pub num_witness: Vec<usize>,
    /// Number of challenges to squeeze from transcript after each phase.
    pub num_challenge: Vec<usize>,
    /// Evaluations to read from transcript.
    pub evaluations: Vec<Query>,
    /// [`crate::pcs::PolynomialCommitmentScheme`] queries to verify.
    pub queries: Vec<Query>,
    /// Structure of quotient polynomial.
    pub quotient: QuotientPolynomial<C::Scalar>,
    #[cfg_attr(
        feature = "derive_serde",
        serde(bound(
            serialize = "L::LoadedScalar: serde::Serialize",
            deserialize = "L::LoadedScalar: serde::Deserialize<'de>"
        ))
    )]
    /// Prover and verifier common initial state to write to transcript if any.
    pub transcript_initial_state: Option<L::LoadedScalar>,
    /// Instance polynomials commiting key if any.
    pub instance_committing_key: Option<InstanceCommittingKey<C>>,
    /// Linearization strategy.
    pub linearization: Option<LinearizationStrategy>,
    /// Indices (instance polynomial index, row) of encoded
    /// [`crate::pcs::AccumulationScheme::Accumulator`]s.
    pub accumulator_indices: Vec<Vec<(usize, usize)>>,
}

impl<C, L> PlonkProtocol<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub(super) fn langranges(&self) -> impl IntoIterator<Item = i32> {
        let instance_eval_lagrange = self.instance_committing_key.is_none().then(|| {
            let queries = {
                let offset = self.preprocessed.len();
                let range = offset..offset + self.num_instance.len();
                self.quotient
                    .numerator
                    .used_query()
                    .into_iter()
                    .filter(move |query| range.contains(&query.poly))
            };
            let (min_rotation, max_rotation) = queries.fold((0, 0), |(min, max), query| {
                if query.rotation.0 < min {
                    (query.rotation.0, max)
                } else if query.rotation.0 > max {
                    (min, query.rotation.0)
                } else {
                    (min, max)
                }
            });
            let max_instance_len = self.num_instance.iter().max().copied().unwrap_or_default();
            -max_rotation..max_instance_len as i32 + min_rotation.abs()
        });
        self.quotient
            .numerator
            .used_langrange()
            .into_iter()
            .chain(instance_eval_lagrange.into_iter().flatten())
    }
}
impl<C> PlonkProtocol<C>
where
    C: CurveAffine,
{
    /// Loaded `PlonkProtocol` with `preprocessed` and
    /// `transcript_initial_state` loaded as constant.
    pub fn loaded<L: Loader<C>>(&self, loader: &L) -> PlonkProtocol<C, L> {
        let preprocessed = self
            .preprocessed
            .iter()
            .map(|preprocessed| loader.ec_point_load_const(preprocessed))
            .collect();
        let transcript_initial_state = self
            .transcript_initial_state
            .as_ref()
            .map(|transcript_initial_state| loader.load_const(transcript_initial_state));
        PlonkProtocol {
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
            linearization: self.linearization,
            accumulator_indices: self.accumulator_indices.clone(),
        }
    }
}

#[cfg(feature = "loader_halo2")]
mod halo2 {
    use crate::{
        loader::halo2::{EccInstructions, Halo2Loader},
        util::arithmetic::CurveAffine,
        verifier::plonk::PlonkProtocol,
    };
    use halo2_proofs::circuit;
    use std::rc::Rc;

    impl<C> PlonkProtocol<C>
    where
        C: CurveAffine,
    {
        /// Loaded `PlonkProtocol` with `preprocessed` and
        /// `transcript_initial_state` loaded as witness, which is useful when
        /// doing recursion.
        pub fn loaded_preprocessed_as_witness<'a, EccChip: EccInstructions<'a, C>>(
            &self,
            loader: &Rc<Halo2Loader<'a, C, EccChip>>,
        ) -> PlonkProtocol<C, Rc<Halo2Loader<'a, C, EccChip>>> {
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
            PlonkProtocol {
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
                linearization: self.linearization,
                accumulator_indices: self.accumulator_indices.clone(),
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive_serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CommonPolynomial {
    Identity,
    Lagrange(i32),
}

#[derive(Clone, Debug)]
pub struct CommonPolynomialEvaluation<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    zn: L::LoadedScalar,
    zn_minus_one: L::LoadedScalar,
    zn_minus_one_inv: Fraction<L::LoadedScalar>,
    identity: L::LoadedScalar,
    lagrange: BTreeMap<i32, Fraction<L::LoadedScalar>>,
}

impl<C, L> CommonPolynomialEvaluation<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub fn new(
        domain: &Domain<C::Scalar>,
        langranges: impl IntoIterator<Item = i32>,
        z: &L::LoadedScalar,
    ) -> Self {
        let loader = z.loader();

        let zn = z.pow_const(domain.n as u64);
        let langranges = langranges.into_iter().sorted().dedup().collect_vec();

        let one = loader.load_one();
        let zn_minus_one = zn.clone() - &one;
        let zn_minus_one_inv = Fraction::one_over(zn_minus_one.clone());

        let n_inv = loader.load_const(&domain.n_inv);
        let numer = zn_minus_one.clone() * &n_inv;
        let omegas = langranges
            .iter()
            .map(|&i| loader.load_const(&domain.rotate_scalar(C::Scalar::ONE, Rotation(i))))
            .collect_vec();
        let lagrange_evals = omegas
            .iter()
            .map(|omega| Fraction::new(numer.clone() * omega, z.clone() - omega))
            .collect_vec();

        Self {
            zn,
            zn_minus_one,
            zn_minus_one_inv,
            identity: z.clone(),
            lagrange: langranges.into_iter().zip(lagrange_evals).collect(),
        }
    }

    pub fn zn(&self) -> &L::LoadedScalar {
        &self.zn
    }

    pub fn zn_minus_one(&self) -> &L::LoadedScalar {
        &self.zn_minus_one
    }

    pub fn zn_minus_one_inv(&self) -> &L::LoadedScalar {
        self.zn_minus_one_inv.evaluated()
    }

    pub fn get(&self, poly: CommonPolynomial) -> &L::LoadedScalar {
        match poly {
            CommonPolynomial::Identity => &self.identity,
            CommonPolynomial::Lagrange(i) => self.lagrange.get(&i).unwrap().evaluated(),
        }
    }

    pub fn denoms(&mut self) -> impl IntoIterator<Item = &'_ mut L::LoadedScalar> {
        self.lagrange
            .iter_mut()
            .map(|(_, value)| value.denom_mut())
            .chain(iter::once(self.zn_minus_one_inv.denom_mut()))
            .flatten()
    }

    pub fn evaluate(&mut self) {
        self.lagrange
            .iter_mut()
            .map(|(_, value)| value)
            .chain(iter::once(&mut self.zn_minus_one_inv))
            .for_each(Fraction::evaluate)
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive_serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QuotientPolynomial<F: Clone> {
    pub chunk_degree: usize,
    // Note that `num_chunk` might be larger than necessary, due to the degree
    // calculation of the constraint system (e.g. halo2 has minimum degree 3).
    pub num_chunk: usize,
    pub numerator: Expression<F>,
}

impl<F: Clone> QuotientPolynomial<F> {
    pub fn num_chunk(&self) -> usize {
        self.num_chunk
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "derive_serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Query {
    pub poly: usize,
    pub rotation: Rotation,
}

impl Query {
    pub fn new<R: Into<Rotation>>(poly: usize, rotation: R) -> Self {
        Self {
            poly,
            rotation: rotation.into(),
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive_serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Expression<F> {
    Constant(F),
    CommonPolynomial(CommonPolynomial),
    Polynomial(Query),
    Challenge(usize),
    Negated(Box<Expression<F>>),
    Sum(Box<Expression<F>>, Box<Expression<F>>),
    Product(Box<Expression<F>>, Box<Expression<F>>),
    Scaled(Box<Expression<F>>, F),
    DistributePowers(Vec<Expression<F>>, Box<Expression<F>>),
}

impl<F: Clone> Expression<F> {
    pub fn evaluate<T: Clone>(
        &self,
        constant: &impl Fn(F) -> T,
        common_poly: &impl Fn(CommonPolynomial) -> T,
        poly: &impl Fn(Query) -> T,
        challenge: &impl Fn(usize) -> T,
        negated: &impl Fn(T) -> T,
        sum: &impl Fn(T, T) -> T,
        product: &impl Fn(T, T) -> T,
        scaled: &impl Fn(T, F) -> T,
    ) -> T {
        let evaluate = |expr: &Expression<F>| {
            expr.evaluate(
                constant,
                common_poly,
                poly,
                challenge,
                negated,
                sum,
                product,
                scaled,
            )
        };
        match self {
            Expression::Constant(scalar) => constant(scalar.clone()),
            Expression::CommonPolynomial(poly) => common_poly(*poly),
            Expression::Polynomial(query) => poly(*query),
            Expression::Challenge(index) => challenge(*index),
            Expression::Negated(a) => {
                let a = evaluate(a);
                negated(a)
            }
            Expression::Sum(a, b) => {
                let a = evaluate(a);
                let b = evaluate(b);
                sum(a, b)
            }
            Expression::Product(a, b) => {
                let a = evaluate(a);
                let b = evaluate(b);
                product(a, b)
            }
            Expression::Scaled(a, scalar) => {
                let a = evaluate(a);
                scaled(a, scalar.clone())
            }
            Expression::DistributePowers(exprs, scalar) => {
                assert!(!exprs.is_empty());
                if exprs.len() == 1 {
                    return evaluate(exprs.first().unwrap());
                }
                let mut exprs = exprs.iter();
                let first = evaluate(exprs.next().unwrap());
                let scalar = evaluate(scalar);
                exprs.fold(first, |acc, expr| {
                    sum(product(acc, scalar.clone()), evaluate(expr))
                })
            }
        }
    }

    pub fn degree(&self) -> usize {
        match self {
            Expression::Constant(_) => 0,
            Expression::CommonPolynomial(_) => 1,
            Expression::Polynomial { .. } => 1,
            Expression::Challenge { .. } => 0,
            Expression::Negated(a) => a.degree(),
            Expression::Sum(a, b) => max(a.degree(), b.degree()),
            Expression::Product(a, b) => a.degree() + b.degree(),
            Expression::Scaled(a, _) => a.degree(),
            Expression::DistributePowers(a, b) => a
                .iter()
                .chain(Some(b.as_ref()))
                .map(Self::degree)
                .max()
                .unwrap_or_default(),
        }
    }

    pub fn used_langrange(&self) -> BTreeSet<i32> {
        self.evaluate(
            &|_| None,
            &|poly| match poly {
                CommonPolynomial::Lagrange(i) => Some(BTreeSet::from_iter([i])),
                _ => None,
            },
            &|_| None,
            &|_| None,
            &|a| a,
            &merge_left_right,
            &merge_left_right,
            &|a, _| a,
        )
        .unwrap_or_default()
    }

    pub fn used_query(&self) -> BTreeSet<Query> {
        self.evaluate(
            &|_| None,
            &|_| None,
            &|query| Some(BTreeSet::from_iter([query])),
            &|_| None,
            &|a| a,
            &merge_left_right,
            &merge_left_right,
            &|a, _| a,
        )
        .unwrap_or_default()
    }
}

impl<F: Clone> From<Query> for Expression<F> {
    fn from(query: Query) -> Self {
        Self::Polynomial(query)
    }
}

impl<F: Clone> From<CommonPolynomial> for Expression<F> {
    fn from(common_poly: CommonPolynomial) -> Self {
        Self::CommonPolynomial(common_poly)
    }
}

macro_rules! impl_expression_ops {
    ($trait:ident, $op:ident, $variant:ident, $rhs:ty, $rhs_expr:expr) => {
        impl<F: Clone> $trait<$rhs> for Expression<F> {
            type Output = Expression<F>;
            fn $op(self, rhs: $rhs) -> Self::Output {
                Expression::$variant((self).into(), $rhs_expr(rhs).into())
            }
        }
        impl<F: Clone> $trait<$rhs> for &Expression<F> {
            type Output = Expression<F>;
            fn $op(self, rhs: $rhs) -> Self::Output {
                Expression::$variant((self.clone()).into(), $rhs_expr(rhs).into())
            }
        }
        impl<F: Clone> $trait<&$rhs> for Expression<F> {
            type Output = Expression<F>;
            fn $op(self, rhs: &$rhs) -> Self::Output {
                Expression::$variant((self).into(), $rhs_expr(rhs.clone()).into())
            }
        }
        impl<F: Clone> $trait<&$rhs> for &Expression<F> {
            type Output = Expression<F>;
            fn $op(self, rhs: &$rhs) -> Self::Output {
                Expression::$variant((self.clone()).into(), $rhs_expr(rhs.clone()).into())
            }
        }
    };
}

impl_expression_ops!(Mul, mul, Product, Expression<F>, std::convert::identity);
impl_expression_ops!(Mul, mul, Scaled, F, std::convert::identity);
impl_expression_ops!(Add, add, Sum, Expression<F>, std::convert::identity);
impl_expression_ops!(Sub, sub, Sum, Expression<F>, Neg::neg);

impl<F: Clone> Neg for Expression<F> {
    type Output = Expression<F>;
    fn neg(self) -> Self::Output {
        Expression::Negated(Box::new(self))
    }
}

impl<F: Clone> Neg for &Expression<F> {
    type Output = Expression<F>;
    fn neg(self) -> Self::Output {
        Expression::Negated(Box::new(self.clone()))
    }
}

impl<F: Clone + Default> Sum for Expression<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, item| acc + item)
            .unwrap_or_else(|| Expression::Constant(F::default()))
    }
}

impl<F: Field> One for Expression<F> {
    fn one() -> Self {
        Expression::Constant(F::ONE)
    }
}

fn merge_left_right<T: Ord>(a: Option<BTreeSet<T>>, b: Option<BTreeSet<T>>) -> Option<BTreeSet<T>> {
    match (a, b) {
        (Some(a), None) | (None, Some(a)) => Some(a),
        (Some(mut a), Some(b)) => {
            a.extend(b);
            Some(a)
        }
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive_serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LinearizationStrategy {
    /// Older linearization strategy of GWC19, which has linearization
    /// polynomial that doesn't evaluate to 0, and requires prover to send extra
    /// evaluation of it to verifier.
    WithoutConstant,
    /// Current linearization strategy of GWC19, which has linearization
    /// polynomial that evaluate to 0 by subtracting product of vanishing and
    /// quotient polynomials.
    MinusVanishingTimesQuotient,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "derive_serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InstanceCommittingKey<C> {
    pub bases: Vec<C>,
    pub constant: Option<C>,
}
