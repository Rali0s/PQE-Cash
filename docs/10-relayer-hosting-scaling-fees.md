# BlueARC Relayer Hosting, Scaling, and Host Fees

## Goals
- Make relayer hosting straightforward for third-party operators.
- Support managed hosting (Railway) and edge/self-hosting (Raspberry Pi).
- Standardize fee collection for relay operators.

## A) Railway Deployment (managed)
1. Create a new service from the `relayer/` directory.
2. Add managed Postgres + Redis in Railway.
3. Copy `/Users/proteu5/Documents/Github/PQE-Cash/relayer/.env.railway.example` values into Railway variables.
4. Set required secrets:
   - `RELAYER_PRIVATE_KEY`
   - `RPC_URL`
   - `POSTGRES_URL`
   - `REDIS_URL`
   - `POOL_ALLOWLIST`
5. Keep healthcheck on `GET /health`.
6. Point UI relayer mesh at the Railway URL.

Note: `relayer/railway.json` is included for Dockerfile-based Railway deploy.

## B) Raspberry Pi Deployment (self-hosted)
1. Use 64-bit Raspberry Pi OS and Docker.
2. In `/Users/proteu5/Documents/Github/PQE-Cash/relayer`:
   - `cp .env.host.example .env.host`
   - set `RELAYER_PRIVATE_KEY`, `RPC_URL`, and `POOL_ALLOWLIST`
3. Start stack:
   - `docker compose -f docker-compose.host.yml up -d --build`
4. Confirm:
   - `curl http://127.0.0.1:8080/health`

Alternative bare-metal env file is provided at:
- `/Users/proteu5/Documents/Github/PQE-Cash/relayer/.env.rpi.example`

## C) Relay Mesh Scaling Pattern
- Run multiple independent relayers (different hosts/regions/keys).
- Each relayer uses its own:
  - signer key
  - Postgres + Redis
  - `POOL_ALLOWLIST`
- Frontend already supports mesh health/failover routing.

Recommended controls per host:
- `RATE_LIMIT_*` tuned to capacity
- abuse thresholds (`ABUSE_*`)
- metrics scrape via `/metrics`
- alerting webhook via `ALERT_WEBHOOK_URL`

## D) Relay Host Fee Collection
Relayer fee is paid on successful withdraw to the relayer signer address.

Use the sweep script to move earned ETH to host treasury:
- Script: `/Users/proteu5/Documents/Github/PQE-Cash/relayer/scripts/sweep-fees.js`
- Command:
  - `npm run sweep:fees`

Required env:
- `RELAYER_PAYOUT_ADDRESS`
- `RELAYER_PRIVATE_KEY`
- `RPC_URL`

Safety env:
- `RELAYER_SWEEP_DRY_RUN=true` (test first)
- `RELAYER_SWEEP_RESERVE_WEI` (keep gas buffer)
- `RELAYER_MIN_SWEEP_WEI` (skip tiny transfers)

## E) Production Guidance
- Use distinct keys per relay host.
- Use remote signer mode (`SIGNER_MODE=remote`) for KMS/HSM in production.
- Restrict pools with `POOL_ALLOWLIST`.
- Set strict CORS and run behind TLS.
- Keep relayer process non-custodial: no user note storage.
