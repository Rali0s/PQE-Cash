# 8. Admin Ops

## Rotate external verifier safely

```bash
cd /Users/proteu5/Documents/Github/PQE-Cash/contracts
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

Script path:
- `/Users/proteu5/Documents/Github/PQE-Cash/contracts/scripts/rotate-verifier.js`

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
