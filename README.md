# BlueARC

Post-quantum-oriented privacy pool with:
- On-chain privacy pool contracts (`contracts/`)
- Relayer service with encrypted session handshake + durable storage (`relayer/`)
- React frontend with 8-bit green/blue UI (`web/`)
- Design and API docs (`docs/`)
- One-command containers (`docker-compose.yml`)

Branding:
- Product: `BlueARC`
- Protocol: `BlueARC Privacy Protocol`
- Relayer network: `BlueARC Relay Mesh`
- UI tag: `BLUEARC // 8BIT`

## Quick Start

### 1) Contracts
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/contracts
npm install
npm run build
npm run node
```
In a second terminal:
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/contracts
EXTERNAL_VERIFIER_ADDRESS=0x... EXTERNAL_VERIFIER_BACKEND=bytes npm run deploy:local
```

Rotate verifier safely with event/state checks:
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/contracts
ADAPTER_ADDRESS=0x... NEW_VERIFIER_ADDRESS=0x... EXPECTED_OLD_VERIFIER=0x... npm run rotate:verifier
```

For local-only dev verifier deployments:
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/contracts
ALLOW_DEV_VERIFIER=true npm run deploy:local
```

### 2) Relayer
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/relayer
cp .env.example .env
# set POSTGRES_URL, REDIS_URL, and signer config
npm install
npm run dev
```
If Postgres/Redis are not running locally, start them with:
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash
docker-compose up -d postgres redis
```

### 3) Frontend
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/web
npm install
npm run dev
```
Open `http://127.0.0.1:5173`.

### 4) One-command Docker
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash
docker compose up --build
```
This starts:
- Postgres + Redis
- Hardhat JSON-RPC on `8545`
- Deployer job (writes `/shared/deploy.json` in the deployer container volume)
- Relayer on `8080`
- Web on `5173`

## Notes
- `PqVerifierAdapter` supports explicit backend modes (`bytes` or `uint`) for real verifier integration.
- Production deploys require `EXTERNAL_VERIFIER_ADDRESS`; dev verifier deploy is opt-in only.
- Relayer persists quotes/jobs in Postgres and sessions/nonces/rate limits in Redis.
- Relayer handshake uses true `ML-KEM-768 (Kyber)` encapsulation + server decapsulation.
- Remote signer mode supports KMS/HSM-style signing services (`SIGNER_MODE=remote`).
- TLS/mTLS is configurable on relayer listener via `TLS_*` variables.
- Pool includes owner-controlled `baseRelayerFee`, `protocolFeeBps`, and treasury routing for protocol profit.
- Protocol fees are custodied in `ProtocolTreasury` with queued timed owner withdrawals.
- Contracts use OpenZeppelin `Ownable` and `ReentrancyGuard`.
- Relayer anonymity is privacy-hardened but not absolute; see docs.
