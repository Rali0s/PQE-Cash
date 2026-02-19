# BlueARC Privacy Protocol - Smart Contract Security Validation Report

Date: 2026-02-19  
Scope: `contracts/contracts/*.sol` and `contracts/test/*.js`

## 1) Executive Summary

This report documents security-focused unit testing and review for:

- `PrivacyPool` (v1)
- `PrivacyPoolV2` (Poseidon-hasher variant)
- `PqVerifierAdapter`
- `ProtocolTreasury`

Result:

- Test status: **23 passing / 0 failing**
- New security tests added: **21 assertions across 3 new suites**
- Critical regressions found during this run: **none**
- Residual risks remain in areas that require external controls (real proof system integration, key management, and production relayer hardening).

## 2) Added Test Artifacts

### New Solidity test helpers

- `contracts/contracts/test/DevExternalPqVerifierUint.sol`
- `contracts/contracts/test/ReenterWithdrawRecipient.sol`

### New security test suites

- `contracts/test/pool.security.test.js`
- `contracts/test/adapter.security.test.js`
- `contracts/test/treasury.security.test.js`

## 3) Security Controls Validated

### A. Pool contracts (`PrivacyPool`, `PrivacyPoolV2`)

Validated:

- Owner-only access for admin mutators:
  - `setBaseRelayerFee`
  - `setProtocolFeeBps`
  - `setTreasury`
  - `setRelayerOnly`
  - `setApprovedRelayersOnly`
  - `setRelayerApproval`
- Deposit validation:
  - exact denomination required
  - no commitment reuse
- Withdraw precondition enforcement:
  - `relayerOnly` sender checks
  - known root checks
  - non-zero recipient and relayer
  - base fee floor enforcement
  - total fee upper bound (`fee + protocolFee <= denomination`)
  - invalid proof rejection
- Policy controls:
  - approved-relayer allowlist can be enforced
- Double-spend defense:
  - nullifier replay blocked
- Reentrancy defense:
  - receive-hook reentry attempt blocked by `ReentrancyGuard`
- Ether handling safety:
  - direct `receive/fallback` disabled on pools (expected custom error)

### B. Verifier adapter (`PqVerifierAdapter`)

Validated:

- Owner-only verifier rotation (`setExternalVerifier`)
- Owner-only backend mode switching (`setBackendType`)
- Zero-address verifier rejection
- Bytes backend call path works with `DevExternalPqVerifier`
- Uint backend call path works with `DevExternalPqVerifierUint`
- Interface mismatch fails closed (returns `false`, does not revert-open)

### C. Treasury (`ProtocolTreasury`)

Validated:

- Owner-only protections:
  - `setWithdrawDelay`
  - `queueWithdrawal`
  - `executeWithdrawal`
- Queue constraints:
  - destination non-zero
  - amount non-zero
- Timelock enforcement (`withdrawDelay`)
- Single execution semantics (`already executed` blocked)
- Balance sufficiency checks before payout
- Ether ingress/egress behavior:
  - `receive()` accepts funds
  - `fallback()` rejects unknown calldata

## 4) Threat-Aligned Notes (from prior references)

The following classes are materially addressed by current architecture and tests:

- Fee tampering (bounded by on-chain checks and quote binding path in relayer flow)
- Replay/double-spend via nullifier checks
- Unauthorized config mutation via `Ownable`
- Reentrancy on ETH payout via OZ `ReentrancyGuard`

Wallet-fingerprint privacy risk (as discussed in the 2025 SAC paper "Attacking Anonymity Set in Tornado Cash via Wallet Fingerprints") remains an **operational/UX OPSEC risk**, not solvable solely by contract logic. Mitigations should remain in relayer/UI policy:

- relayer-first withdrawals
- timing and amount hygiene prompts
- anti-fingerprinting warnings
- optional randomized relayer fee/route strategies

## 5) Residual Risks and Gaps

1. Dev verifier still permissive in non-production mode.
2. No formal verification/SMT checks yet.
3. No fuzz/property test suite yet (e.g., Echidna/Foundry invariants).
4. Contract-level slashing/reputation model for relayer mesh not yet implemented.
5. Governance hardening (multisig + timelock ownership) should be mandatory before mainnet.

## 6) Recommended Next Security Steps

P0:

1. Enforce production verifier adapter target (no dev verifier in prod env).
2. Add multisig ownership for pool, adapter, treasury.
3. Add CI gate requiring security test suites to pass on PR.

P1:

1. Add invariant fuzzing for:
   - conservation of value on withdraw
   - nullifier uniqueness
   - root history consistency
2. Add Slither static analysis and baseline triage report.
3. Add event-indexing checks for ops monitoring.

P2:

1. External audit for contracts + relayer crypto flow.
2. Formalize emergency runbooks for relayer compromise, signer rotation, and treasury incidents.

## 7) Reproduction Commands

From `contracts/`:

```bash
npm test
```

Specific suites:

```bash
npx hardhat test test/pool.security.test.js
npx hardhat test test/adapter.security.test.js
npx hardhat test test/treasury.security.test.js
```

## 8) Final Assessment

Current contract set is significantly stronger than baseline happy-path coverage and is in good shape for controlled testnet operations. Mainnet production readiness still depends on hardening items outside pure unit tests: real verifier integration discipline, governance controls, signer/KMS policy, and external audit.
