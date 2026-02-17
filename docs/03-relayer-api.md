# 3. Relayer API with PQ-Hybrid Handshake

Base URL: `http://127.0.0.1:8080`

## `GET /health`
Returns relayer config readiness.

## `GET /handshake/server-key`
Returns server ECDH key metadata.

Response:
```json
{
  "keyId": "uuid",
  "curve": "prime256v1",
  "serverEcdhPublicKey": "base64"
}
```

## `POST /handshake/open`
Creates an authenticated session context.

Request:
```json
{
  "clientEcdhPublicKey": "base64",
  "pqSharedSecret": "base64 (optional)"
}
```

Session key schedule (V1):
`session_key = SHA256(classical_ecdh_secret || pq_shared_secret)`

Response:
```json
{
  "sessionId": "uuid",
  "expiresInSec": 600,
  "keySchedule": "sha256(classical_ecdh || pq_secret)",
  "submitMode": "encrypted-envelope-v1"
}
```

## `POST /quote`
Request withdrawal fee quote.

Request:
```json
{
  "pool": "0x...",
  "feeBps": 80
}
```

Response:
```json
{
  "quote": {
    "quoteId": "uuid",
    "pool": "0x...",
    "feeBps": 80,
    "fee": "1000000000000000",
    "chainId": 31337,
    "expiresAt": 1735689600000
  },
  "quoteSignature": "0x...",
  "ttlSec": 120,
  "signer": "0x..."
}
```

## `POST /submit`
Submit an encrypted withdrawal envelope to be broadcast by relayer.

Request:
```json
{
  "sessionId": "uuid",
  "envelope": {
    "iv": "base64",
    "ciphertext": "base64",
    "tag": "base64",
    "aad": "sessionId"
  }
}
```

Decrypted payload JSON (inside envelope):
```json
{
  "nonce": "uuid-v4",
  "expiresAt": 1735689600000,
  "quote": {
    "quoteId": "uuid",
    "pool": "0x...",
    "feeBps": 80,
    "fee": "1000000000000000",
    "chainId": 31337,
    "expiresAt": 1735689600000
  },
  "quoteSignature": "0x...",
  "pool": "0x...",
  "proof": "0x...",
  "root": "0x...",
  "nullifierHash": "0x...",
  "recipient": "0x...",
  "refund": "0"
}
```

AEAD mode:
- `AES-256-GCM`
- `key = SHA256(classical_ecdh_secret || pq_shared_secret)`
- `aad = sessionId` (or provided `aad`)

Replay protection:
- `nonce` must be unique per session.
- `expiresAt` must be in the future and within session expiry.
- Reused nonce returns `409 replay detected`.

Quote tamper protection:
- Quote payload is signed by relayer signer at `/quote`.
- `/submit` re-verifies `quoteSignature` and quote fields before tx broadcast.

Response:
```json
{
  "jobId": "uuid",
  "txHash": "0x...",
  "status": "pending"
}
```

## `GET /status/:jobId`
Returns one of: `queued | broadcasting | pending | confirmed | failed`

## Privacy/Anon Behavior in V1
- Minimal logging mode is default (`ANON_LOGGING=true`).
- No persistent DB; in-memory job/session state.
- No IP retention logic in app code.
- For stronger transport anonymity, deploy behind Tor hidden service or VPN fronting.

## Production Upgrade Path
- Replace `pqSharedSecret` placeholder with true ML-KEM encapsulation/decapsulation.
- Persist used nonces with bounded TTL in a hardened datastore.
- Add signed quote revocation list and strict rate-limits.
