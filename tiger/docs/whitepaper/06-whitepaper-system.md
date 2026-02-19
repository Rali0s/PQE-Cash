---
title: F) Whitepaper - How Relayer and Contracts Work
---

## Protocol Components

- `PrivacyPoolV2`: deposits, known roots, nullifier-spend checks, payout accounting.
- `PqVerifierAdapter`: verifier abstraction and backend mode control.
- `ProtocolTreasury`: protocol fee custody with timed withdrawals.
- `Relayer`: session handshake, quote signing, encrypted submit processing, on-chain execution.

## Relayer Flow

1. `/handshake/server-key` returns relay key material metadata.
2. `/handshake/open` establishes session key (hybrid ML-KEM + ECDH derivation).
3. `/quote` returns signed quote terms.
4. `/submit` accepts encrypted payload (AEAD), validates quote/nonce/version, submits withdraw.
5. `/status/:jobId` returns pending/confirmed/failed state.

## Why It Works

- Contracts enforce cryptographic/state correctness.
- Relayer enforces transport/session/anti-replay controls.
- Combined path reduces direct user exposure while preserving on-chain verifiability.
