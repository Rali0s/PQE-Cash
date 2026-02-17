# 7. Docker Runbook

## Start all services
```bash
docker compose up --build
```

## Services
- `hardhat`: JSON-RPC on `localhost:8545`
- `deployer`: deploys contracts once and writes `/shared/deploy.json` in compose volume
- `relayer`: API on `localhost:8080`
- `web`: UI on `localhost:5173`

## Get deployed addresses
```bash
docker logs pqe-deployer
```
Copy `privacyPool` address into the web UI.

## Stop services
```bash
docker compose down
```
