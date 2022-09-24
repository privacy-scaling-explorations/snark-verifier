use crate::util::{arithmetic::Field, parallelize};
use rand::Rng;
use std::{
    iter::{self, Sum},
    ops::{
        Add, Index, IndexMut, Mul, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo,
        RangeToInclusive, Sub,
    },
};

#[derive(Clone, Debug)]
pub struct Polynomial<F>(Vec<F>);

impl<F> Polynomial<F> {
    pub fn new(inner: Vec<F>) -> Self {
        Self(inner)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &F> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut F> {
        self.0.iter_mut()
    }

    pub fn to_vec(self) -> Vec<F> {
        self.0
    }
}

impl<F: Field> Polynomial<F> {
    pub fn rand<R: Rng>(n: usize, mut rng: R) -> Self {
        Self::new(iter::repeat_with(|| F::random(&mut rng)).take(n).collect())
    }

    pub fn evaluate(&self, x: F) -> F {
        let evaluate_serial = |coeffs: &[F]| {
            coeffs
                .iter()
                .rev()
                .fold(F::zero(), |acc, coeff| acc * x + coeff)
        };

        #[cfg(feature = "parallel")]
        {
            use crate::util::{arithmetic::powers, current_num_threads, parallelize_iter};
            use num_integer::Integer;

            let num_threads = current_num_threads();
            if self.len() * 2 < num_threads {
                return evaluate_serial(&self.0);
            }

            let chunk_size = Integer::div_ceil(&self.len(), &num_threads);
            let mut results = vec![F::zero(); num_threads];
            parallelize_iter(
                results
                    .iter_mut()
                    .zip(self.0.chunks(chunk_size))
                    .zip(powers(x.pow_vartime(&[chunk_size as u64, 0, 0, 0]))),
                |((result, coeffs), scalar)| *result = evaluate_serial(coeffs) * scalar,
            );
            results.iter().fold(F::zero(), |acc, result| acc + result)
        }
        #[cfg(not(feature = "parallel"))]
        evaluate_serial(&self.0)
    }
}

impl<'a, F: Field> Add<&'a Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    fn add(mut self, rhs: &'a Polynomial<F>) -> Polynomial<F> {
        parallelize(&mut self.0, |(lhs, start)| {
            for (lhs, rhs) in lhs.iter_mut().zip(rhs.0[start..].iter()) {
                *lhs += *rhs;
            }
        });
        self
    }
}

impl<'a, F: Field> Sub<&'a Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    fn sub(mut self, rhs: &'a Polynomial<F>) -> Polynomial<F> {
        parallelize(&mut self.0, |(lhs, start)| {
            for (lhs, rhs) in lhs.iter_mut().zip(rhs.0[start..].iter()) {
                *lhs -= *rhs;
            }
        });
        self
    }
}

impl<F: Field> Sub<F> for Polynomial<F> {
    type Output = Polynomial<F>;

    fn sub(mut self, rhs: F) -> Polynomial<F> {
        self.0[0] -= rhs;
        self
    }
}

impl<F: Field> Add<F> for Polynomial<F> {
    type Output = Polynomial<F>;

    fn add(mut self, rhs: F) -> Polynomial<F> {
        self.0[0] += rhs;
        self
    }
}

impl<F: Field> Mul<F> for Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(mut self, rhs: F) -> Polynomial<F> {
        if rhs == F::zero() {
            return Polynomial::new(vec![F::zero(); self.len()]);
        }
        if rhs == F::one() {
            return self;
        }
        parallelize(&mut self.0, |(lhs, _)| {
            for lhs in lhs.iter_mut() {
                *lhs *= rhs;
            }
        });
        self
    }
}

impl<F: Field> Sum for Polynomial<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, item| acc + &item).unwrap()
    }
}

macro_rules! impl_index {
    ($($range:ty => $output:ty,)*) => {
        $(
            impl<F> Index<$range> for Polynomial<F> {
                type Output = $output;

                fn index(&self, index: $range) -> &$output {
                    self.0.index(index)
                }
            }
            impl<F> IndexMut<$range> for Polynomial<F> {
                fn index_mut(&mut self, index: $range) -> &mut $output {
                    self.0.index_mut(index)
                }
            }
        )*
    };
}

impl_index!(
    usize => F,
    Range<usize> => [F],
    RangeFrom<usize> => [F],
    RangeFull => [F],
    RangeInclusive<usize> => [F],
    RangeTo<usize> => [F],
    RangeToInclusive<usize> => [F],
);
