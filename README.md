# BlueARC V1

Post-quantum-oriented privacy pool MVP with:
- On-chain privacy pool contracts (`contracts/`)
- Relayer service with hybrid session handshake (`relayer/`)
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
npm run deploy:local
```

Rotate verifier safely with event/state checks:
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/contracts
ADAPTER_ADDRESS=0x... NEW_VERIFIER_ADDRESS=0x... EXPECTED_OLD_VERIFIER=0x... npm run rotate:verifier
```

### 2) Relayer
```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/relayer
cp .env.example .env
# set RELAYER_PRIVATE_KEY from hardhat local account
npm install
npm run dev
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
- Hardhat JSON-RPC on `8545`
- Deployer job (writes `/shared/deploy.json` in the deployer container volume)
- Relayer on `8080`
- Web on `5173`

## Notes
- This V1 uses a verifier integration adapter (`PqVerifierAdapter`) over an external verifier interface.
- The bundled external verifier is a dev stub (`DevExternalPqVerifier`) for local integration.
- Replace the dev external verifier address via adapter before production.
- Pool includes owner-controlled `baseRelayerFee`, `protocolFeeBps`, and treasury routing for protocol profit.
- Protocol fees are custodied in `ProtocolTreasury` with queued timed owner withdrawals.
- Contracts use OpenZeppelin `Ownable` and `ReentrancyGuard`.
- Relayer anonymity is privacy-hardened but not absolute; see docs.
