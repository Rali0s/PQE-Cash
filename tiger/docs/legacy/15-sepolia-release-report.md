# BlueARC Privacy Protocol - Sepolia Release Report

Date: 2026-02-19  
Network: Sepolia (`chainId=11155111`)  
Product: BlueARC  
Protocol: BlueARC Privacy Protocol

## 1) Release Objective

Validate that BlueARC V2 contracts (Poseidon tree variant) and relay-integrated withdrawal flow are operational on Sepolia with production-grade guardrails enabled for testnet operations.

## 2) Deployed Contract Set (Current)

Source: `contracts/deployments/sepolia-v2.latest.json`

- Deployer: `0x5F1667Ee0aAAF2bF9750125598FA3f7657882C12`
- ExternalVerifier: `0x5d9aB94bB4B0d4b7660Ce5F44dE46894DF0D2466`
- Verifier Adapter: `0xf09a2593da7a1aC97C4225580A890FB8401B42F9`
- Treasury: `0x4B46662aA215982D7ca8dFB241FfDD5F1c757398`
- PrivacyPoolV2: `0xBeBE31Bf60f55CfE7caC13162e88a628eB637667`
- Poseidon Hasher: `0x0C6a0f38a95D00096aD3aCbaB30Cc4D2aE5196c4`

Config:

- Denomination: `0.1 ETH`
- Base relayer fee: `0.001 ETH`
- Protocol fee: `50 bps`
- Pool version marker: `v2`

## 3) Functional Status

Based on your latest runtime logs and verified test paths:

- Relayer startup healthy on Sepolia signer
- Session open/quote/submit/status flow works
- Base fee floor enforcement works (`fee below base` surfaced correctly)
- Withdraws confirmed on-chain via relayer
- GUI now presents human-readable fee and proof-size feedback
- GUI/relayer proof-version compatibility path wired (`requiredProofVersion`)

## 4) Security Validation in This Release

### Unit tests

- Total passing: `23`
- Failing: `0`
- Coverage focus expanded from happy path to security controls:
  - access control
  - reentrancy prevention
  - replay defense
  - relayer policy gates
  - treasury timelock behavior
  - verifier adapter fail-closed behavior

### Files added for this release cycle

- `contracts/test/pool.security.test.js`
- `contracts/test/adapter.security.test.js`
- `contracts/test/treasury.security.test.js`
- `contracts/contracts/test/DevExternalPqVerifierUint.sol`
- `contracts/contracts/test/ReenterWithdrawRecipient.sol`

## 5) Release Checklist

Completed:

- [x] V2 pool deployment path prepared and executed
- [x] Poseidon hasher address injected
- [x] Relayer/web wiring for pool version + proof version checks
- [x] Security unit tests added and passing
- [x] Fee floor and quote mismatch behavior validated

Required before mainnet-style production:

- [ ] Replace non-production verifier target with audited proving verifier
- [ ] Move relayer signer to managed KMS/HSM
- [ ] Enforce TLS/mTLS between web clients and relayers
- [ ] Durable relayer persistence and replay-window controls (Postgres/Redis)
- [ ] Alerting/SLO dashboards for relayer health and job failure rates
- [ ] Ownership migration to multisig + timelock governance policy

## 6) Operational Guidance for Current Testnet

1. Keep `PROOF_VERSION_REQUIRED` pinned to your intended proof artifact version.
2. Keep `RUNTIME_POOL_VERSION=v2` so web/admin tooling can assert compatibility.
3. Use relayer-first withdrawals for better operational privacy and gas shielding.
4. Keep treasury withdrawals timelocked and owner-key restricted.
5. Run preflight + tests before each redeploy.

## 7) Known Risks (Open)

1. ML-KEM integration is live in app flow, but cryptographic implementation should still undergo external review.
2. Wallet fingerprinting risks remain at user behavior and network metadata layers.
3. Dev/test verifier confusion risk remains if environment discipline is weak.
4. Node runtime warning: Hardhat currently reports unsupported Node v25; pin CI and operator runtime to supported LTS.

## 8) Go/No-Go

For Sepolia staging and partner testing: **GO**.  
For permissionless mainnet production: **NO-GO until P0 hardening items are complete**.

## 9) Reproduce Release Validation

From `contracts/`:

```bash
npm test
npm run preflight:sepolia
npm run deploy:v2:sepolia
```

From `relayer/`:

```bash
npm run dev
```

From `web/`:

```bash
npm run build
npm run dev
```
