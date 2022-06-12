use crate::util::{
    loader::{LoadedScalar, Loader},
    Curve, Domain, Field, Fraction, Rotation,
};
use std::{
    cmp::max,
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    iter::{self, Sum},
    ops::{Add, Mul, Neg, Sub},
};

#[derive(Clone, Copy, Debug)]
pub enum CommonPolynomial {
    Identity,
    Lagrange(i32),
}

#[derive(Clone, Debug)]
pub struct CommonPolynomialEvaluation<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    zn: L::LoadedScalar,
    zn_minus_one_inv: Fraction<L::LoadedScalar>,
    identity: L::LoadedScalar,
    lagrange: HashMap<i32, Fraction<L::LoadedScalar>>,
}

impl<C, L> CommonPolynomialEvaluation<C, L>
where
    C: Curve,
    L: Loader<C>,
{
    pub fn new(
        domain: &Domain<C::Scalar>,
        loader: &L,
        langranges: impl IntoIterator<Item = i32>,
        z: &L::LoadedScalar,
    ) -> Self {
        let zn = z.pow_const(domain.n as u64);
        let langranges = BTreeSet::<i32>::from_iter(langranges)
            .into_iter()
            .collect::<Vec<_>>();

        let one = loader.load_one();
        let zn_minus_one = zn.clone() - one;
        let n_inv = loader.load_const(&domain.n_inv);
        let numer = zn_minus_one.clone() * n_inv;

        let omegas = langranges
            .iter()
            .map(|&i| loader.load_const(&domain.rotate_scalar(C::Scalar::one(), Rotation(i))))
            .collect::<Vec<_>>();

        let lagrange_evals = omegas
            .iter()
            .map(|omega| Fraction::new(numer.clone() * omega, z.clone() - omega))
            .collect::<Vec<_>>();

        Self {
            zn,
            zn_minus_one_inv: Fraction::one_over(zn_minus_one),
            identity: z.clone(),
            lagrange: HashMap::from_iter(langranges.into_iter().zip(lagrange_evals)),
        }
    }

    pub fn zn(&self) -> L::LoadedScalar {
        self.zn.clone()
    }

    pub fn zn_minus_one_inv(&self) -> L::LoadedScalar {
        self.zn_minus_one_inv.evaluate()
    }

    pub fn get(&self, poly: CommonPolynomial) -> L::LoadedScalar {
        match poly {
            CommonPolynomial::Identity => self.identity.clone(),
            CommonPolynomial::Lagrange(i) => self.lagrange.get(&i).unwrap().evaluate(),
        }
    }

    pub fn denoms(&mut self) -> impl IntoIterator<Item = &'_ mut L::LoadedScalar> {
        self.lagrange
            .iter_mut()
            .map(|(_, value)| value.denom_mut())
            .chain(iter::once(self.zn_minus_one_inv.denom_mut()))
            .flatten()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Clone)]
pub enum Expression<F: Clone> {
    Constant(F),
    CommonPolynomial(CommonPolynomial),
    Polynomial(Query),
    Challenge(usize),
    Negated(Box<Expression<F>>),
    Sum(Box<Expression<F>>, Box<Expression<F>>),
    Product(Box<Expression<F>>, Box<Expression<F>>),
    Scaled(Box<Expression<F>>, F),
}

impl<F: Clone> Expression<F> {
    pub fn evaluate<T>(
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
        match self {
            Expression::Constant(scalar) => constant(scalar.clone()),
            Expression::CommonPolynomial(poly) => common_poly(*poly),
            Expression::Polynomial(query) => poly(*query),
            Expression::Challenge(index) => challenge(*index),
            Expression::Negated(a) => {
                let a = a.evaluate(
                    constant,
                    common_poly,
                    poly,
                    challenge,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                negated(a)
            }
            Expression::Sum(a, b) => {
                let a = a.evaluate(
                    constant,
                    common_poly,
                    poly,
                    challenge,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                let b = b.evaluate(
                    constant,
                    common_poly,
                    poly,
                    challenge,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                sum(a, b)
            }
            Expression::Product(a, b) => {
                let a = a.evaluate(
                    constant,
                    common_poly,
                    poly,
                    challenge,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                let b = b.evaluate(
                    constant,
                    common_poly,
                    poly,
                    challenge,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                product(a, b)
            }
            Expression::Scaled(a, scalar) => {
                let a = a.evaluate(
                    constant,
                    common_poly,
                    poly,
                    challenge,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                scaled(a, scalar.clone())
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
