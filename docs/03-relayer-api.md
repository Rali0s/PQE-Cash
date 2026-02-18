# 3. Relayer API with PQ-Hybrid Handshake

Base URL:
- Development: `http://127.0.0.1:8080`
- Production: `https://<relayer-host>` (TLS required, optional mTLS)

## Transport + Security
- `TLS_CERT_PATH` + `TLS_KEY_PATH` enable HTTPS listener.
- `TLS_REQUIRE_CLIENT_CERT=true` + `TLS_CA_PATH` enforce mTLS.
- If `NODE_ENV=production`, set TLS or explicitly allow insecure mode via `ALLOW_INSECURE_HTTP=true`.
- Sessions, nonce replay windows, and abuse/rate-limit counters are persisted in Redis.
- Quotes and jobs are persisted in Postgres.

## `GET /health`
Dependency readiness check.

Response:
```json
{
  "ok": true,
  "chainId": 31337,
  "signer": "0x...",
  "pqKemAlgorithm": "ML-KEM-768",
  "minFeeBps": 50,
  "maxFeeBps": 300
}
```

## `GET /metrics`
Prometheus metrics endpoint.

## `GET /handshake/server-key`
Returns active hybrid key material metadata (ECDH + ML-KEM-768 public key).

Response:
```json
{
  "keyId": "uuid",
  "curve": "prime256v1",
  "serverEcdhPublicKey": "base64",
  "pqKemAlgorithm": "ML-KEM-768",
  "pqKemPublicKey": "base64",
  "pqKemCiphertextBytes": 1088,
  "expiresAt": 1735689600000
}
```

## `POST /handshake/open`
Creates a short-lived encrypted session.

Request:
```json
{
  "keyId": "uuid (optional)",
  "clientEcdhPublicKey": "base64",
  "pqKemCiphertext": "base64"
}
```

Session key schedule (V2):
`session_key = SHA256("BLUEARC_HYBRID_MLKEM_V1" || len(keyId) || keyId || len(client_ecdh_pub) || client_ecdh_pub || len(server_ecdh_pub) || server_ecdh_pub || len(pq_kem_ciphertext) || pq_kem_ciphertext || len(classical_ecdh_secret) || classical_ecdh_secret || len(ml_kem_shared_secret) || ml_kem_shared_secret)`

Response:
```json
{
  "sessionId": "uuid",
  "expiresInSec": 600,
  "keySchedule": "sha256(bluearc_hybrid_mlkem_v1 transcript)",
  "submitMode": "encrypted-envelope-v1"
}
```

## `POST /quote`
Requests relayer quote.

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
    "expiresAt": 1735689600000,
    "issuedAt": 1735689480000
  },
  "quoteSignature": "0x...",
  "ttlSec": 120,
  "signer": "0x..."
}
```

## `POST /submit`
Submits an encrypted withdrawal payload.

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

Decrypted payload:
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

Response:
```json
{
  "jobId": "uuid",
  "txHash": "0x...",
  "status": "pending"
}
```

## `GET /status/:jobId`
Returns one of:
- `queued`
- `broadcasting`
- `pending`
- `confirmed`
- `failed`

## Anti-Tamper + Replay Controls
- Quote digest signed at `/quote`; verified again at `/submit`.
- Encrypted submit requires valid session key + AEAD tag.
- Per-session nonce keys persisted with TTL and replay rejection (`409`).
- Payload expiry bounded by session expiry and configurable max age.
- Optional session fingerprint binding (`ENFORCE_SESSION_BINDING=true`).

## Abuse Controls
- Redis-backed route limits by source.
- Abuse score buckets with temporary blocking threshold.
- Optional pool allowlist (`POOL_ALLOWLIST`).
- Proof size upper bound (`PROOF_MAX_BYTES`).

## Signer Modes
- `SIGNER_MODE=local`: local private key.
- `SIGNER_MODE=remote`: KMS/HSM service over HTTPS (`/v1/sign-message`, `/v1/sign-transaction`).
