---
title: D) Why Relayer + Poseidon V2 Circuits
---

## Why Relayer-First

- User gas shielding and operational privacy improvement.
- Easier policy controls (quote binding, replay windows, abuse controls).
- Better UX for users who are not gas experts.

## Why Poseidon Tree in V2

- Circuit-friendly hashing vs Keccak-heavy proving circuits.
- Lower proving complexity and better operator UX for real prover integration.
- Cleaner path for production proof backends.

## Why Adapter Verifier

`PqVerifierAdapter` allows backend mode switching (`bytes` or `uint`) without changing pool interface.
This keeps verifier integration flexible while contracts stay stable.
