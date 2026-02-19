---
title: In-the-Wild PQE Math (ML-KEM)
---

This page adds practical ML-KEM deployment context and lightweight math framing for BlueARC.

## Real Deployments and Standards

1. **TLS standardization path**
   - The IETF TLS draft defines **hybrid key exchange groups** such as `X25519MLKEM768` and `SecP256r1MLKEM768`.
   - The hybrid model combines classical ECDHE and ML-KEM shared secrets before key schedule derivation.
   - Reference: [IETF draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)

2. **Cloud production support**
   - AWS announced ML-KEM support in TLS paths for KMS, ACM, and Secrets Manager, giving concrete production evidence that hybrid PQ TLS is operational at scale.
   - Reference: [AWS Security Blog](https://aws.amazon.com/blogs/security/ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager/)

3. **Operational ecosystem signals**
   - Community/industry summaries increasingly present ML-KEM as a practical default for post-quantum KEM migration tracks.
   - Reference: [EmergentMind ML-KEM topic page](https://www.emergentmind.com/topics/ml-kem)

## Practical Math Notes (Bob and Alice)

ML-KEM is lattice-based (module-LWE family). For protocol engineering, the useful mental model is:

- Alice and Bob derive a shared secret from structured polynomial/matrix relations over a finite ring.
- Security comes from the hardness of recovering hidden short vectors/noise in those relations.
- Encapsulation/decapsulation are efficient enough for real transport handshakes.

In hybrid TLS/transport usage:

- `S_classic = ECDHE(shared_secret)`
- `S_pq = ML-KEM(shared_secret)`
- `S_hybrid = KDF( transcript || S_classic || S_pq )`

So an attacker generally needs to break **both** components to recover transport keys (under hybrid assumptions).

## Size and Cost Intuition

For ML-KEM-768 deployments, practical tradeoffs include:

- Larger handshake material than pure ECDHE (public keys/ciphertexts are bigger).
- More CPU than classical-only handshake.
- Stronger long-term confidentiality posture against harvest-now/decrypt-later risk.

This is the exact tradeoff BlueARC makes in relayer session establishment.

## Why This Matters for BlueARC

BlueARC does not use PQE to replace ZK proofs. It uses PQE to protect **payload transport** to relayers:

- ZK handles spend correctness and privacy on-chain.
- ML-KEM hybrid handshake protects off-chain relay submit payload exchange.

This division keeps responsibilities clear and production migration practical.

## Sources

- [IETF draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [AWS Security Blog: ML-KEM TLS support](https://aws.amazon.com/blogs/security/ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager/)
- [EmergentMind: ML-KEM](https://www.emergentmind.com/topics/ml-kem)
