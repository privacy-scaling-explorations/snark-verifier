# Snark Verifier SDK

To make file storage go in the correct places,

```bash
cd snark-verifier-sdk
```

To run standard plonk example:

```bash
cargo run --example standard_plonk --release
```

If feature "loader_evm" is on, this will generate yul code for the verifier contract and simulate a transaction call to that contract with generated proof calldata using revm.

This example is essentially the same as [`evm-verifier-with-accumulator`](../snark-verifier/examples/evm-verifier-with-accumulator.rs) except that it uses this SDK and uses SHPLONK as the polynomial multi-open scheme instead of GWC (multi-open scheme from original PLONK paper).

To run standard Plonk benchmark:

```bash
cargo bench --bench standard_plonk
```

These examples/benches will generate unsafe trusted setups in `./params` folder. It will also cache proving keys and certain snarks.
