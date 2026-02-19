---
title: C) How PQE and ZK Work Together
---

PQE and ZK solve different problems:

- PQE protects payload transport to relayers.
- ZK proves spend correctness on-chain without exposing secrets.

Combined model:

1. User opens hybrid ML-KEM + ECDH session with relayer.
2. User sends encrypted withdraw payload.
3. Relayer decrypts and submits transaction.
4. Contract verifies ZK proof + state checks.

Result:

- Better transport confidentiality to relayer.
- On-chain trust minimized to proof/system constraints.
