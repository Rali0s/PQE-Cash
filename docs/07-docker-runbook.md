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

## Get deployed addresses
```bash
docker logs bluearc-deployer
```
Copy `privacyPool` address into the web UI.

## Relayer health and metrics
```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/metrics
```

## Stop services
```bash
docker compose down
```
