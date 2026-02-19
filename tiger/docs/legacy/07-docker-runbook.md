# 7. Docker Runbook

## Start all services
```bash
docker compose up --build
```

## Services
- `postgres`: durable quote/job DB
- `redis`: durable sessions/nonces/rate-limit counters
- `hardhat`: JSON-RPC on `localhost:8545`
- `deployer`: deploys contracts once and writes `/shared/deploy.json`
- `relayer`: API on `localhost:8080`
- `web`: UI on `localhost:5173`

## Pool auto-discovery
`relayer` mounts deploy volume read-only and reads `/shared/deploy.json`.
UI calls relayer `/health` and auto-fills `defaultPool` when available.

## Relayer health and metrics
```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/metrics
```

## Stop services
```bash
docker compose down
```
