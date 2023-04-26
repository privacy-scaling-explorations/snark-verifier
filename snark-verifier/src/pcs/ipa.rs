//! Inner product argument polynomial commitment scheme and accumulation scheme.
//! The notations are following <https://eprint.iacr.org/2020/499.pdf>.

use crate::{
    loader::{native::NativeLoader, LoadedScalar, Loader, ScalarLoader},
    util::{
        arithmetic::{
            inner_product, powers, Curve, CurveAffine, Domain, Field, Fraction, PrimeField,
        },
        msm::{multi_scalar_multiplication, Msm},
        parallelize,
        poly::Polynomial,
        transcript::{TranscriptRead, TranscriptWrite},
        Itertools,
    },
    Error,
};
use rand::Rng;
use std::{fmt::Debug, iter, marker::PhantomData};

mod accumulation;
mod accumulator;
mod decider;
mod multiopen;

pub use accumulation::{IpaAs, IpaAsProof};
pub use accumulator::IpaAccumulator;
pub use decider::IpaDecidingKey;
pub use multiopen::{Bgh19, Bgh19Proof};

/// Inner product argument polynomial commitment scheme.
#[derive(Clone, Debug)]
pub struct Ipa<C>(PhantomData<C>);

impl<C> Ipa<C>
where
    C: CurveAffine,
{
    /// Create an inner product argument.
    pub fn create_proof<T, R>(
        pk: &IpaProvingKey<C>,
        p: &[C::Scalar],
        z: &C::Scalar,
        omega: Option<&C::Scalar>,
        transcript: &mut T,
        mut rng: R,
    ) -> Result<IpaAccumulator<C, NativeLoader>, Error>
    where
        T: TranscriptWrite<C>,
        R: Rng,
    {
        let mut p_prime = Polynomial::new(p.to_vec());
        if pk.zk() {
            let p_bar = {
                let mut p_bar = Polynomial::rand(p.len(), &mut rng);
                let p_bar_at_z = p_bar.evaluate(*z);
                p_bar[0] -= p_bar_at_z;
                p_bar
            };
            let omega_bar = C::Scalar::random(&mut rng);
            let c_bar = pk.commit(&p_bar, Some(omega_bar));
            transcript.write_ec_point(c_bar)?;

            let alpha = transcript.squeeze_challenge();
            let omega_prime = *omega.unwrap() + alpha * omega_bar;
            transcript.write_scalar(omega_prime)?;

            p_prime = p_prime + &(p_bar * alpha);
        };

        let xi_0 = transcript.squeeze_challenge();
        let h_prime = pk.h * xi_0;
        let mut bases = pk.g.clone();
        let mut coeffs = p_prime.to_vec();
        let mut zs = powers(*z).take(coeffs.len()).collect_vec();

        let k = pk.domain.k;
        let mut xi = Vec::with_capacity(k);
        for i in 0..k {
            let half = 1 << (k - i - 1);

            let l_i = multi_scalar_multiplication(&coeffs[half..], &bases[..half])
                + h_prime * inner_product(&coeffs[half..], &zs[..half]);
            let r_i = multi_scalar_multiplication(&coeffs[..half], &bases[half..])
                + h_prime * inner_product(&coeffs[..half], &zs[half..]);
            transcript.write_ec_point(l_i.to_affine())?;
            transcript.write_ec_point(r_i.to_affine())?;

            let xi_i = transcript.squeeze_challenge();
            let xi_i_inv = Field::invert(&xi_i).unwrap();

            let (bases_l, bases_r) = bases.split_at_mut(half);
            let (coeffs_l, coeffs_r) = coeffs.split_at_mut(half);
            let (zs_l, zs_r) = zs.split_at_mut(half);
            parallelize(bases_l, |(bases_l, start)| {
                let mut tmp = Vec::with_capacity(bases_l.len());
                for (lhs, rhs) in bases_l.iter().zip(bases_r[start..].iter()) {
                    tmp.push(lhs.to_curve() + *rhs * xi_i);
                }
                C::Curve::batch_normalize(&tmp, bases_l);
            });
            parallelize(coeffs_l, |(coeffs_l, start)| {
                for (lhs, rhs) in coeffs_l.iter_mut().zip(coeffs_r[start..].iter()) {
                    *lhs += xi_i_inv * rhs;
                }
            });
            parallelize(zs_l, |(zs_l, start)| {
                for (lhs, rhs) in zs_l.iter_mut().zip(zs_r[start..].iter()) {
                    *lhs += xi_i * rhs;
                }
            });
            bases = bases_l.to_vec();
            coeffs = coeffs_l.to_vec();
            zs = zs_l.to_vec();

            xi.push(xi_i);
        }

        transcript.write_ec_point(bases[0])?;
        transcript.write_scalar(coeffs[0])?;

        Ok(IpaAccumulator::new(xi, bases[0]))
    }

    /// Read [`IpaProof`] from transcript.
    pub fn read_proof<T, L: Loader<C>>(
        svk: &IpaSuccinctVerifyingKey<C>,
        transcript: &mut T,
    ) -> Result<IpaProof<C, L>, Error>
    where
        T: TranscriptRead<C, L>,
    {
        IpaProof::read(svk, transcript)
    }

    /// Perform the succinct check of the proof and returns [`IpaAccumulator`].
    pub fn succinct_verify<L: Loader<C>>(
        svk: &IpaSuccinctVerifyingKey<C>,
        commitment: &Msm<C, L>,
        z: &L::LoadedScalar,
        eval: &L::LoadedScalar,
        proof: &IpaProof<C, L>,
    ) -> Result<IpaAccumulator<C, L>, Error> {
        let loader = z.loader();
        let h = loader.ec_point_load_const(&svk.h);
        let s = svk.s.as_ref().map(|s| loader.ec_point_load_const(s));
        let h = Msm::<C, L>::base(&h);

        let h_prime = h * &proof.xi_0;
        let lhs = {
            let c_prime = match (
                s.as_ref(),
                proof.c_bar_alpha.as_ref(),
                proof.omega_prime.as_ref(),
            ) {
                (Some(s), Some((c_bar, alpha)), Some(omega_prime)) => {
                    let s = Msm::<C, L>::base(s);
                    commitment.clone() + Msm::base(c_bar) * alpha - s * omega_prime
                }
                (None, None, None) => commitment.clone(),
                _ => unreachable!(),
            };
            let c_0 = c_prime + h_prime.clone() * eval;
            let c_k = c_0
                + proof
                    .rounds
                    .iter()
                    .zip(proof.xi_inv().iter())
                    .flat_map(|(Round { l, r, xi }, xi_inv)| [(l, xi_inv), (r, xi)])
                    .map(|(base, scalar)| Msm::<C, L>::base(base) * scalar)
                    .sum::<Msm<_, _>>();
            c_k.evaluate(None)
        };
        let rhs = {
            let u = Msm::<C, L>::base(&proof.u);
            let v_prime = h_eval(&proof.xi(), z) * &proof.c;
            (u * &proof.c + h_prime * &v_prime).evaluate(None)
        };

        loader.ec_point_assert_eq("C_k == c[U] + v'[H']", &lhs, &rhs)?;

        Ok(IpaAccumulator::new(proof.xi(), proof.u.clone()))
    }
}

/// Inner product argument proving key.
#[derive(Clone, Debug)]
pub struct IpaProvingKey<C: CurveAffine> {
    /// Working domain.
    pub domain: Domain<C::Scalar>,
    /// $\mathbb{G}$
    pub g: Vec<C>,
    /// $H$
    pub h: C,
    /// $S$
    pub s: Option<C>,
}

impl<C: CurveAffine> IpaProvingKey<C> {
    /// Initialize an [`IpaProvingKey`].
    pub fn new(domain: Domain<C::Scalar>, g: Vec<C>, h: C, s: Option<C>) -> Self {
        Self { domain, g, h, s }
    }

    /// Returns if it supports zero-knowledge.
    pub fn zk(&self) -> bool {
        self.s.is_some()
    }

    /// Returns [`IpaSuccinctVerifyingKey`].
    pub fn svk(&self) -> IpaSuccinctVerifyingKey<C> {
        IpaSuccinctVerifyingKey::new(self.domain.clone(), self.g[0], self.h, self.s)
    }

    /// Returns [`IpaDecidingKey`].
    pub fn dk(&self) -> IpaDecidingKey<C> {
        IpaDecidingKey::new(self.svk(), self.g.clone())
    }

    /// Commit a polynomial into with a randomizer if any.
    pub fn commit(&self, poly: &Polynomial<C::Scalar>, omega: Option<C::Scalar>) -> C {
        let mut c = multi_scalar_multiplication(&poly[..], &self.g);
        match (self.s, omega) {
            (Some(s), Some(omega)) => c += s * omega,
            (None, None) => {}
            _ => unreachable!(),
        };
        c.to_affine()
    }
}

impl<C: CurveAffine> IpaProvingKey<C> {
    #[cfg(test)]
    pub(crate) fn rand<R: Rng>(k: usize, zk: bool, mut rng: R) -> Self {
        use crate::util::arithmetic::{root_of_unity, Group};

        let domain = Domain::new(k, root_of_unity(k));
        let mut g = vec![C::default(); 1 << k];
        C::Curve::batch_normalize(
            &iter::repeat_with(|| C::Curve::random(&mut rng))
                .take(1 << k)
                .collect_vec(),
            &mut g,
        );
        let h = C::Curve::random(&mut rng).to_affine();
        let s = zk.then(|| C::Curve::random(&mut rng).to_affine());
        Self { domain, g, h, s }
    }
}

/// Inner product argument succinct verifying key.
#[derive(Clone, Debug)]
pub struct IpaSuccinctVerifyingKey<C: CurveAffine> {
    /// Working domain.
    pub domain: Domain<C::Scalar>,
    /// $G_0$
    pub g: C,
    /// $H$
    pub h: C,
    /// $S$
    pub s: Option<C>,
}

impl<C: CurveAffine> IpaSuccinctVerifyingKey<C> {
    /// Initialize an [`IpaSuccinctVerifyingKey`].
    pub fn new(domain: Domain<C::Scalar>, g: C, h: C, s: Option<C>) -> Self {
        Self { domain, g, h, s }
    }

    /// Returns if it supports zero-knowledge.
    pub fn zk(&self) -> bool {
        self.s.is_some()
    }
}

/// Inner product argument
#[derive(Clone, Debug)]
pub struct IpaProof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    c_bar_alpha: Option<(L::LoadedEcPoint, L::LoadedScalar)>,
    omega_prime: Option<L::LoadedScalar>,
    xi_0: L::LoadedScalar,
    rounds: Vec<Round<C, L>>,
    u: L::LoadedEcPoint,
    c: L::LoadedScalar,
}

impl<C, L> IpaProof<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn new(
        c_bar_alpha: Option<(L::LoadedEcPoint, L::LoadedScalar)>,
        omega_prime: Option<L::LoadedScalar>,
        xi_0: L::LoadedScalar,
        rounds: Vec<Round<C, L>>,
        u: L::LoadedEcPoint,
        c: L::LoadedScalar,
    ) -> Self {
        Self {
            c_bar_alpha,
            omega_prime,
            xi_0,
            rounds,
            u,
            c,
        }
    }

    /// Read [`crate::pcs::AccumulationScheme::Proof`] from transcript.
    pub fn read<T>(svk: &IpaSuccinctVerifyingKey<C>, transcript: &mut T) -> Result<Self, Error>
    where
        T: TranscriptRead<C, L>,
    {
        let c_bar_alpha = svk
            .zk()
            .then(|| {
                let c_bar = transcript.read_ec_point()?;
                let alpha = transcript.squeeze_challenge();
                Ok((c_bar, alpha))
            })
            .transpose()?;
        let omega_prime = svk.zk().then(|| transcript.read_scalar()).transpose()?;
        let xi_0 = transcript.squeeze_challenge();
        let rounds = iter::repeat_with(|| {
            Ok(Round::new(
                transcript.read_ec_point()?,
                transcript.read_ec_point()?,
                transcript.squeeze_challenge(),
            ))
        })
        .take(svk.domain.k)
        .collect::<Result<Vec<_>, _>>()?;
        let u = transcript.read_ec_point()?;
        let c = transcript.read_scalar()?;
        Ok(Self {
            c_bar_alpha,
            omega_prime,
            xi_0,
            rounds,
            u,
            c,
        })
    }

    /// Returns $\{\xi_0, \xi_1, ...\}$.
    pub fn xi(&self) -> Vec<L::LoadedScalar> {
        self.rounds.iter().map(|round| round.xi.clone()).collect()
    }

    /// Returns $\{\xi_0^{-1}, \xi_1^{-1}, ...\}$.
    pub fn xi_inv(&self) -> Vec<L::LoadedScalar> {
        let mut xi_inv = self.xi().into_iter().map(Fraction::one_over).collect_vec();
        L::batch_invert(xi_inv.iter_mut().filter_map(Fraction::denom_mut));
        xi_inv.iter_mut().for_each(Fraction::evaluate);
        xi_inv
            .into_iter()
            .map(|xi_inv| xi_inv.evaluated().clone())
            .collect()
    }
}

#[derive(Clone, Debug)]
struct Round<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    l: L::LoadedEcPoint,
    r: L::LoadedEcPoint,
    xi: L::LoadedScalar,
}

impl<C, L> Round<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    fn new(l: L::LoadedEcPoint, r: L::LoadedEcPoint, xi: L::LoadedScalar) -> Self {
        Self { l, r, xi }
    }
}

fn h_eval<F: PrimeField, T: LoadedScalar<F>>(xi: &[T], z: &T) -> T {
    let loader = z.loader();
    let one = loader.load_one();
    loader.product(
        &iter::successors(Some(z.clone()), |z| Some(z.square()))
            .zip(xi.iter().rev())
            .map(|(z, xi)| z * xi + &one)
            .collect_vec()
            .iter()
            .collect_vec(),
    )
}

fn h_coeffs<F: Field>(xi: &[F], scalar: F) -> Vec<F> {
    assert!(!xi.is_empty());

    let mut coeffs = vec![F::ZERO; 1 << xi.len()];
    coeffs[0] = scalar;

    for (len, xi) in xi.iter().rev().enumerate().map(|(i, xi)| (1 << i, xi)) {
        let (left, right) = coeffs.split_at_mut(len);
        let right = &mut right[0..len];
        right.copy_from_slice(left);
        for coeffs in right {
            *coeffs *= xi;
        }
    }

    coeffs
}

#[cfg(all(test, feature = "system_halo2"))]
mod test {
    use crate::{
        pcs::{
            ipa::{self, IpaProvingKey},
            AccumulationDecider,
        },
        util::{arithmetic::Field, msm::Msm, poly::Polynomial},
    };
    use halo2_curves::pasta::pallas;
    use halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, TranscriptReadBuffer, TranscriptWriterBuffer,
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_ipa() {
        type Ipa = ipa::Ipa<pallas::Affine>;
        type IpaAs = ipa::IpaAs<pallas::Affine, ()>;

        let k = 10;
        let mut rng = OsRng;

        for zk in [false, true] {
            let pk = IpaProvingKey::<pallas::Affine>::rand(k, zk, &mut rng);
            let (c, z, v, proof) = {
                let p = Polynomial::<pallas::Scalar>::rand(pk.domain.n, &mut rng);
                let omega = pk.zk().then(|| pallas::Scalar::random(&mut rng));
                let c = pk.commit(&p, omega);
                let z = pallas::Scalar::random(&mut rng);
                let v = p.evaluate(z);
                let mut transcript = Blake2bWrite::init(Vec::new());
                Ipa::create_proof(&pk, &p[..], &z, omega.as_ref(), &mut transcript, &mut rng)
                    .unwrap();
                (c, z, v, transcript.finalize())
            };

            let svk = pk.svk();
            let accumulator = {
                let mut transcript = Blake2bRead::init(proof.as_slice());
                let proof = Ipa::read_proof(&svk, &mut transcript).unwrap();
                Ipa::succinct_verify(&svk, &Msm::base(&c), &z, &v, &proof).unwrap()
            };

            let dk = pk.dk();
            assert!(IpaAs::decide(&dk, accumulator).is_ok());
        }
    }
}
