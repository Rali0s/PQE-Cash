# 8. Admin Ops

## Deploy with real verifier (production default)

`scripts/deploy.js` now requires `EXTERNAL_VERIFIER_ADDRESS` unless `ALLOW_DEV_VERIFIER=true` is explicitly set.

```bash
cd <repo-root>/contracts
EXTERNAL_VERIFIER_ADDRESS=0x... \
EXTERNAL_VERIFIER_BACKEND=bytes \
npm run deploy:local
```

For local sandbox only:
```bash
ALLOW_DEV_VERIFIER=true npm run deploy:local
```

## Rotate external verifier safely

```bash
cd <repo-root>/contracts
ADAPTER_ADDRESS=0x... \
NEW_VERIFIER_ADDRESS=0x... \
EXPECTED_OLD_VERIFIER=0x... \
npm run rotate:verifier
```

Checks performed by script:
- Reads current `externalVerifier` from adapter.
- Verifies expected old verifier (if provided).
- Sends `setExternalVerifier(newVerifier)`.
- Verifies `ExternalVerifierUpdated(previous,new)` event exists exactly once.
- Re-reads adapter state and confirms `externalVerifier == newVerifier`.

Optional backend switch (bytes/uint) is owner-controlled in `PqVerifierAdapter`:
```solidity
setBackendType(BackendType.Bytes)
setBackendType(BackendType.Uint)
```

Script path:
- `<repo-root>/contracts/scripts/rotate-verifier.js`

## Protocol profit payout

`PrivacyPool` routes protocol fees to `ProtocolTreasury`.
Owner withdrawal is timed in two steps:

```solidity
queueWithdrawal(address payable to, uint256 amount)
executeWithdrawal(uint256 requestId)
```

Guards:
- `onlyOwner`
- `nonReentrant`
- queue requires `amount > 0`
- execute requires `block.timestamp >= unlockTime`
