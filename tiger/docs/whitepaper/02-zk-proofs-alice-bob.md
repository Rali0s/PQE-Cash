---
title: B) ZK Proofs in Alice and Bob Terms
---

## What Alice Proves

Alice wants to prove: “I am allowed to withdraw from this pool” without revealing which deposit is hers.

She creates a proof that verifies:

- commitment existed in the Merkle tree
- root is known
- nullifier is valid and unique for her note
- recipient/relayer/fee values are bound to proof inputs

## What Bob (Verifier Contract) Checks

The contract checks the proof and checks state rules:

- root is known
- nullifier not spent
- fee constraints
- relayer policy constraints

If valid, withdrawal executes while preserving deposit-withdraw unlinkability at protocol level.
