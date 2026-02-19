---
title: A) PQE in Alice and Bob Terms
---

## Why Post-Quantum Encryption (PQE)

Alice wants to send sensitive data to Bob. Today, strong classical encryption protects them.
The risk is “harvest now, decrypt later”: an attacker records encrypted traffic now, then decrypts it later once practical quantum attacks exist.

PQE (in this project, ML-KEM/Kyber) addresses that risk for session key establishment.

## Simple Story

1. Bob publishes a public key.
2. Alice uses Bob's public key to encapsulate a secret and sends ciphertext.
3. Bob decapsulates and gets the same shared secret.
4. Alice and Bob use that shared secret to encrypt payloads.

In BlueARC relayer flow, PQE is hybridized with ECDH. Both secrets are mixed into one session key.

## Security Goal

- Forward-looking confidentiality for relayer payloads.
- Reduced dependence on only classical key exchange.
- Stronger long-term privacy posture for sensitive withdraw metadata.
