# SNARK Verifier

Generic (S)NARK verifier.

## User Guide

If you write a circuit in Halo2 and want to verify the generated proof on Ethereum, this project is for you.

This repository also contains an example to verify an aggregated proof, which is a proof for multiple other proofs. Try it out with `cargo run --example evm-verifier-with-accumulator`.

The effort has been under active developement, so there are variants of repositories to chose.

- For production use, [axiom’s fork](https://github.com/axiom-crypto/snark-verifier) is audited and thus recommended.
- In the future, [halo2-solidity-verifier](https://github.com/privacy-scaling-explorations/halo2-solidity-verifier) is favored. Some notes:
  - We plan to sunset snark-verifier and shift focus to halo2-solidity-verifier
  - halo2-solidity-verifier is unaudited and has some limitations, see the project README for details.
  - snark-verifier fails to generate Solidity code by hitting the contract size limit when the circuit is too large. halo2-solidity-verifier is written to solve this issue.