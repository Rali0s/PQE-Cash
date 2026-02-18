# 6. Threat Model

## In Scope
- Nullifier replay prevention.
- Root freshness and known-root checks.
- Relayer privacy minimization.

## Out of Scope
- Formal cryptographic assurance of the external verifier/circuit pair.
- Full PQ formal proofs.
- Network-layer deanonymization resistance against global adversary.

## Next Steps
- Integrate production STARK verifier.
- Harden relayer with authenticated ML-KEM key distribution, cert pinning, and key attestation.
- Independent audits on circuits/contracts/infra.
