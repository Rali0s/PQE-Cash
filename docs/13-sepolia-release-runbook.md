# Sepolia Release Runbook (PrivacyPoolV2)

## 1) Required Env (contracts/.env)
- `SEPOLIA_RPC_URL`
- `DEPLOYER_PRIVATE_KEY`
- `EXPECTED_DEPLOYER_ADDRESS`
- `POOL_VERSION=v2`
- `EXTERNAL_VERIFIER_BACKEND=bytes` (or `uint` if your verifier requires it)
- `EXTERNAL_VERIFIER_ADDRESS=<deployed verifier>`
- `POSEIDON_HASHER_ADDRESS=<deployed poseidon hasher>`

Must be false/unset for release:
- `ALLOW_DEV_VERIFIER`
- `ALLOW_DEV_POSEIDON_HASHER`
- `ALLOW_EOA_EXTERNAL_VERIFIER`

## 2) Preflight
```bash
cd <repo-root>/contracts
npm run preflight:sepolia
```

Preflight checks:
- deployer account matches expected owner
- chain is Sepolia (`11155111`)
- external verifier has bytecode
- Poseidon hasher has bytecode (V2)
- deployer has minimum ETH balance
- dev bypass flags are disabled

## 3) Release Deploy
```bash
cd <repo-root>/contracts
npm run release:v2:sepolia
```

Output manifest:
- `contracts/deployments/sepolia-v2.latest.json`

## 4) Post-Deploy Actions
1. Set relayer runtime pool to new address.
2. Confirm relayer `/health` and `/quote` on Sepolia.
3. Run one deposit + one real/fixture withdrawal smoke test.
4. Publish addresses in docs/release notes.
