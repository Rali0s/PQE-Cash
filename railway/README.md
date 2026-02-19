# BlueARC Railway Upstream (Sepolia/Testnet)

This folder is the canonical Railway deployment upstream for the current BlueARC stack.

## Scope

- Service 1: `relayer` (Node API + ML-KEM/ECDH handshake + quote/submit/status)
- Service 2: `web` (React app served via Vite preview)
- Managed data: Postgres + Redis (Railway add-ons)

## Current Testnet Baseline (Sepolia)

- Pool version: `v2`
- Proof version: `bluearc-v2`
- Default pool: `0xBeBE31Bf60f55CfE7caC13162e88a628eB637667`
- Chain ID: `11155111`

## Files in this folder

- `relayer.railway.json` - Railway service manifest for relayer
- `web.railway.json` - Railway service manifest for web
- `relayer.env.template` - relayer environment template
- `web.env.template` - web environment template
- `UPSTREAM-CHECKLIST.md` - preflight + release checks

## Recommended Railway Project Layout

Create one Railway project with:

1. `relayer` service
2. `web` service
3. Postgres plugin
4. Redis plugin

Set service root directories:

- relayer root: `relayer/`
- web root: `web/`

## Deploy Steps

### 0) One-command bootstrap (recommended)

From repo root:

```bash
./railway/master-up.sh
```

What it does:

- links/initializes a Railway project
- creates missing services: `relayer`, `web`
- adds missing databases: `postgres`, `redis`
- applies env vars from:
  - `railway/relayer.env.template`
  - `railway/web.env.template`
- deploys both services with `railway up`

Optional overrides:

```bash
PROJECT_NAME=bluearc-sepolia \
WORKSPACE=your-workspace \
ENVIRONMENT=production \
RELAYER_ENV_FILE=railway/relayer.env.template \
WEB_ENV_FILE=railway/web.env.template \
./railway/master-up.sh
```

### 1) Relayer Service

- Import this repo into Railway
- Set root directory to `relayer/`
- Use `relayer/railway.json` or this folder's `relayer.railway.json`
- Apply vars from `railway/relayer.env.template`

### 2) Web Service

- Add second service from same repo
- Set root directory to `web/`
- Use this folder's `web.railway.json`
- Apply vars from `railway/web.env.template`

### 3) Wire web -> relayer

- Set `VITE_API_PROXY_TARGET` to relayer internal URL, or
- Set `VITE_RELAYER_URL` to the relayer public URL if you do not proxy

### 4) Smoke test

- Relayer: `GET /health` returns `ok: true`, `poolVersion: v2`, `requiredProofVersion: bluearc-v2`
- Web loads and can open session, fetch quote, and submit

## Secrets Handling

Do not commit any private key or credential in plain text:

- `RELAYER_PRIVATE_KEY`
- DB/Redis credentials (Railway injects these)
- Webhook tokens

Use Railway environment variables only.

## Production Live-Testnet Command (strict)

Use this when your Sepolia deployment is operated like production.

```bash
SIGNER_SERVICE_URL=https://your-signer.example \
SIGNER_ADDRESS=0xYourRemoteSignerAddress \
CORS_ORIGIN=https://your-web-domain.example \
RELAYER_PUBLIC_URL=https://your-relayer.up.railway.app \
./railway/master-up-prod.sh
```

What is enforced by `master-up-prod.sh`:

- remote signer mode only (`SIGNER_MODE=remote`)
- `ALLOW_INSECURE_HTTP=false`
- `RUNTIME_POOL_VERSION=v2`
- `PROOF_VERSION_REQUIRED=bluearc-v2`
- direct web -> relayer public URL wiring

Production templates:

- `railway/relayer.env.production.template`
- `railway/web.env.production.template`
