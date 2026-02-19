# Railway Upstream Checklist (Sepolia)

## P0 - Required Before Public Testnet Use

1. Relayer `/health` returns:
   - `ok: true`
   - `chainId: 11155111`
   - `poolVersion: v2`
   - `requiredProofVersion: bluearc-v2`
2. `POOL_ALLOWLIST` includes current pool address.
3. `RELAYER_PRIVATE_KEY` funded with Sepolia ETH.
4. Postgres and Redis connectivity confirmed.
5. Web can reach relayer (`/api` proxy or direct URL).

## P1 - Functional Verification

1. Connect wallet on Sepolia in web UI.
2. Open session.
3. Get quote.
4. Submit encrypted withdrawal.
5. Confirm job status reaches `confirmed`.

## P2 - Safety Verification

1. Proof version mismatch is rejected if incorrect.
2. Quote tampering is rejected.
3. Replay attempts are rejected.
4. Rate limits and abuse thresholds produce expected HTTP responses.

## P3 - Operator Readiness

1. Alert webhook configured.
2. Relayer payout policy decided (`dry-run` or active sweep).
3. Rotation runbook for verifier adapter and relayer signer is documented.
4. Admin ownership accounts reviewed and backed by secure custody.

## Rollback Plan

1. Restrict `POOL_ALLOWLIST` to known-safe pool(s).
2. Revert `PROOF_VERSION_REQUIRED` to previous stable version.
3. Rotate relayer signer if compromise suspected.
4. Pause user-facing web by switching relayer URL to maintenance endpoint.
