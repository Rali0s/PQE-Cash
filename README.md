# BlueARC

Post-quantum-oriented privacy pool with:
- On-chain privacy pool contracts (`contracts/`)
- Relayer service with encrypted session handshake + durable storage (`relayer/`)
- React frontend with 8-bit green/blue UI (`web/`)
- Design and API docs (`docs/`)
- One-command containers (`docker-compose.yml`)
  
## Front-End:
![Alt text](connect.jpg)
![Alt text](deposit.jpg)

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

Sepolia deploy:
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/contracts
cp env.sample .env
# fill DEPLOYER_PRIVATE_KEY and EXTERNAL_VERIFIER_ADDRESS
npm install
npm run deploy:sepolia
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
Default project ports are isolated to avoid conflicts with other stacks:
- Postgres: `127.0.0.1:55432`
- Redis: `127.0.0.1:56379`

Relay operator fee sweep:
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/relayer
# set RELAYER_PAYOUT_ADDRESS + RELAYER_PRIVATE_KEY + RPC_URL
npm run sweep:fees
```

### 3) Frontend
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/web
cp env.sample .env.local
npm install
npm run dev
```
Open `http://127.0.0.1:5173`.
By default the UI uses `/api` and auto-loads relayer health/config (including `defaultPool` when relayer can read deploy JSON).

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
- Relayer publishes runtime config (`/health`, `/config`) including auto-detected `defaultPool` from deploy JSON path when configured.
- Remote signer mode supports KMS/HSM-style signing services (`SIGNER_MODE=remote`).
- TLS/mTLS is configurable on relayer listener via `TLS_*` variables.
- Pool includes owner-controlled `baseRelayerFee`, `protocolFeeBps`, and treasury routing for protocol profit.
- Protocol fees are custodied in `ProtocolTreasury` with queued timed owner withdrawals.
- Contracts use OpenZeppelin `Ownable` and `ReentrancyGuard`.
- Relayer anonymity is privacy-hardened but not absolute; see docs.

## Relay Host Packaging
- Railway service config: `/Users/proteu5/Documents/Github/PQE-Cash/relayer/railway.json`
- Host compose stack (good for Raspberry Pi/VPS): `/Users/proteu5/Documents/Github/PQE-Cash/relayer/docker-compose.host.yml`

- ## SepoliaETH
- Deployer: 0x5F1667Ee0aAAF2bF9750125598FA3f7657882C12
- ExternalVerifier: 0x5d9aB94bB4B0d4b7660Ce5F44dE46894DF0D2466 (backend=bytes, deployed=true)
- PqVerifierAdapter: 0x5245355b3e43837B3D519DFff3Da272Ab151Ff92
- PrivacyPool: 0x0999D3Aa4e8CF3F4A2d1D855d3D4874984df0083

- Host env templates:
  - `/Users/proteu5/Documents/Github/PQE-Cash/relayer/.env.host.example`
  - `/Users/proteu5/Documents/Github/PQE-Cash/relayer/.env.railway.example`
  - `/Users/proteu5/Documents/Github/PQE-Cash/relayer/.env.rpi.example`
- Full runbook: `/Users/proteu5/Documents/Github/PQE-Cash/docs/10-relayer-hosting-scaling-fees.md`

