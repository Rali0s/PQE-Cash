# Audit Checklist Coverage (Knownsec 404) vs BlueARC Tests

Date: 2026-02-19

Reference checklist:
- `<external-local-file>`

Current test result:
- `33 passing`

## Strong Coverage

- Permission control (`onlyOwner`) across pool/adapter/treasury
- Reentrancy defenses on withdrawal payout path
- Replay/double-spend protections (`nullifierSpent`)
- Address initialization checks (`recipient`, `relayer`, treasury destination)
- Balance and timing checks (`withdrawDelay`, insufficient treasury balance)
- Fallback/receive behavior hardening
- Event logging coverage for key admin mutations
- ZK input-aliasing guard behavior through field-bounded verifier adapter tests

## Partially Covered

- Loop/DoS concerns: fixed-depth tree loops are bounded, but no explicit gas budget thresholds in CI.
- Overflow: protected by Solidity `^0.8.24` checked arithmetic, but no dedicated arithmetic fuzz suite.
- External call hardening: fail-closed behavior tested, but additional malicious verifier fuzzing can be expanded.
- Owner-permission risk: access tested, but governance policy (multisig/timelock ownership transfer) is operationally enforced, not unit-enforced.

## Not Applicable / Out of Scope for This Protocol

- ERC20 approve race-condition details
- ERC20 return-standard and event-standard items
- ERC20 fake recharge patterns
- Weak random-number concerns (protocol does not use RNG for security decisions)

## Test Files Mapping

- `contracts/test/pool.security.test.js`
- `contracts/test/adapter.security.test.js`
- `contracts/test/treasury.security.test.js`
- `contracts/test/checklist.expanded.test.js`

Supporting helper contracts:

- `contracts/contracts/test/ReenterWithdrawRecipient.sol`
- `contracts/contracts/test/DevExternalPqVerifierUint.sol`
- `contracts/contracts/test/FieldBoundedExternalVerifier.sol`

## Recommended Next Additions

1. Add property/fuzz tests for random withdraw sequences and root-history invariants over longer runs.
2. Add gas snapshot thresholds to prevent accidental gas regressions.
3. Add static-analysis stage (Slither) and external-audit checklist sign-off gate in CI.
