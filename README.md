# SNARK Verifier

Generic (S)NARK verifier.

## User Guide

This project is tailored for verifying [Halo2](https://github.com/privacy-scaling-explorations/halo2)-generated proofs on Ethereum.

Additionally, within this repository, there is an example provided for verifying an aggregated proof, which serves as proof for multiple other proofs. You can test it by executing `cargo run --example evm-verifier-with-accumulator`.

As this effort is continuously evolving, there are multiple repository variants to choose from. For optimal results:

- Use [Axiom’s fork](https://github.com/axiom-crypto/snark-verifier) of snark-verifier when
  - You require production-grade quality; Axiom's fork has been audited.
  - Proof aggregation is necessary.
- In the future, consider using [halo2-solidity-verifier](https://github.com/privacy-scaling-explorations/halo2-solidity-verifier) for solidity verifier generation. However, please note the following:
  - The plan is to phase out snark-verifier and shift focus to halo2-solidity-verifier
  - Keep in mind halo2-solidity-verifier is currently unaudited and has certain limitations, refer to the project README for details.
  - snark-verifier may encounter issues generating Solidity code due to hitting the contract size limit with large circuits, a problem addressed by halo2-solidity-verifier.
  - Proof aggregation is not supported in halo2-solidity-verifier at this time.
