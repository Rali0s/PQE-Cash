# 6. Threat Model (V1)

## In Scope
- Nullifier replay prevention.
- Root freshness and known-root checks.
- Relayer privacy minimization.

## Out of Scope in This MVP
- Cryptographic soundness of mock verifier.
- Full PQ formal proofs.
- Network-layer deanonymization resistance against global adversary.

## Next Steps
- Integrate production STARK verifier.
- Harden relayer with PQ KEM and end-to-end encrypted payloads.
- Independent audits on circuits/contracts/infra.
