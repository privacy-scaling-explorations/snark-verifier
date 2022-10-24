use crate::{
    loader::{LoadedScalar, ScalarLoader},
    util::{arithmetic::FieldExt, Itertools},
};
use poseidon::{self, SparseMDSMatrix, Spec};
use std::{iter, marker::PhantomData, mem};

struct State<F: FieldExt, L, const T: usize, const RATE: usize> {
    inner: [L; T],
    _marker: PhantomData<F>,
}

impl<F: FieldExt, L: LoadedScalar<F>, const T: usize, const RATE: usize> State<F, L, T, RATE> {
    fn new(inner: [L; T]) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    fn loader(&self) -> &L::Loader {
        self.inner[0].loader()
    }

    fn power5_with_constant(value: &L, constant: &F) -> L {
        value
            .loader()
            .sum_products_with_const(&[(value, &value.square().square())], *constant)
    }

    fn sbox_full(&mut self, constants: &[F; T]) {
        for (state, constant) in self.inner.iter_mut().zip(constants.iter()) {
            *state = Self::power5_with_constant(state, constant);
        }
    }

    fn sbox_part(&mut self, constant: &F) {
        self.inner[0] = Self::power5_with_constant(&self.inner[0], constant);
    }

    fn absorb_with_pre_constants(&mut self, inputs: &[L], pre_constants: &[F; T]) {
        assert!(inputs.len() < T);

        self.inner[0] = self
            .loader()
            .sum_with_const(&[&self.inner[0]], pre_constants[0]);
        self.inner
            .iter_mut()
            .zip(pre_constants.iter())
            .skip(1)
            .zip(inputs)
            .for_each(|((state, constant), input)| {
                *state = state.loader().sum_with_const(&[state, input], *constant);
            });
        self.inner
            .iter_mut()
            .zip(pre_constants.iter())
            .skip(1 + inputs.len())
            .enumerate()
            .for_each(|(idx, (state, constant))| {
                *state = state.loader().sum_with_const(
                    &[state],
                    if idx == 0 {
                        F::one() + constant
                    } else {
                        *constant
                    },
                );
            });
    }

    fn apply_mds(&mut self, mds: &[[F; T]; T]) {
        self.inner = mds
            .iter()
            .map(|row| {
                self.loader()
                    .sum_with_coeff(&row.iter().cloned().zip(self.inner.iter()).collect_vec())
            })
            .collect_vec()
            .try_into()
            .unwrap();
    }

    fn apply_sparse_mds(&mut self, mds: &SparseMDSMatrix<F, T, RATE>) {
        self.inner = iter::once(
            self.loader().sum_with_coeff(
                &mds.row()
                    .iter()
                    .cloned()
                    .zip(self.inner.iter())
                    .collect_vec(),
            ),
        )
        .chain(
            mds.col_hat()
                .iter()
                .zip(self.inner.iter().skip(1))
                .map(|(coeff, state)| {
                    self.loader()
                        .sum_with_coeff(&[(*coeff, &self.inner[0]), (F::one(), state)])
                }),
        )
        .collect_vec()
        .try_into()
        .unwrap();
    }
}

pub struct Poseidon<F: FieldExt, L, const T: usize, const RATE: usize> {
    spec: Spec<F, T, RATE>,
    state: State<F, L, T, RATE>,
    buf: Vec<L>,
}

impl<F: FieldExt, L: LoadedScalar<F>, const T: usize, const RATE: usize> Poseidon<F, L, T, RATE> {
    pub fn new(loader: L::Loader, r_f: usize, r_p: usize) -> Self {
        Self {
            spec: Spec::new(r_f, r_p),
            state: State::new(
                poseidon::State::default()
                    .words()
                    .map(|state| loader.load_const(&state)),
            ),
            buf: Vec::new(),
        }
    }

    pub fn update(&mut self, elements: &[L]) {
        self.buf.extend_from_slice(elements);
    }

    pub fn squeeze(&mut self) -> L {
        let buf = mem::take(&mut self.buf);
        let exact = buf.len() % RATE == 0;

        for chunk in buf.chunks(RATE) {
            self.permutation(chunk);
        }
        if exact {
            self.permutation(&[]);
        }

        self.state.inner[1].clone()
    }

    fn permutation(&mut self, inputs: &[L]) {
        let r_f = self.spec.r_f() / 2;
        let mds = self.spec.mds_matrices().mds().rows();
        let pre_sparse_mds = self.spec.mds_matrices().pre_sparse_mds().rows();
        let sparse_matrices = self.spec.mds_matrices().sparse_matrices();

        // First half of the full rounds
        let constants = self.spec.constants().start();
        self.state.absorb_with_pre_constants(inputs, &constants[0]);
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.state.sbox_full(constants);
            self.state.apply_mds(&mds);
        }
        self.state.sbox_full(constants.last().unwrap());
        self.state.apply_mds(&pre_sparse_mds);

        // Partial rounds
        let constants = self.spec.constants().partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.state.sbox_part(constant);
            self.state.apply_sparse_mds(sparse_mds);
        }

        // Second half of the full rounds
        let constants = self.spec.constants().end();
        for constants in constants.iter() {
            self.state.sbox_full(constants);
            self.state.apply_mds(&mds);
        }
        self.state.sbox_full(&[F::zero(); T]);
        self.state.apply_mds(&mds);
    }
}
