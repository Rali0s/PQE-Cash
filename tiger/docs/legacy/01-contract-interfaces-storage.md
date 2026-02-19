# 1. Contract Interfaces and Storage Layout

## `IVerifier`
```solidity
function verifyProof(bytes calldata proof, uint256[] calldata input) external view returns (bool);
```

## `PqVerifierAdapter`
Adapter that connects pool verifier calls to an external circuit verifier contract.

```solidity
enum BackendType { Bytes, Uint }

constructor(address externalVerifier_, BackendType backendType_)
function setExternalVerifier(address externalVerifier_) external
function setBackendType(BackendType backendType_) external
function verifyProof(bytes calldata proof, uint256[] calldata input) external view returns (bool)
```

Storage:
- `address public externalVerifier`
- `BackendType public backendType`

Behavior:
- `BackendType.Bytes` calls `verify(bytes proof, bytes encodedPublicInputs)`.
- `BackendType.Uint` calls `verifyProof(bytes proof, uint256[] publicInputs)`.
- No fallback mode: backend semantics are explicit and owner-controlled.

## `ProtocolTreasury`
```solidity
constructor(uint256 withdrawDelay_)
function setWithdrawDelay(uint256 newWithdrawDelay) external
function queueWithdrawal(address payable to, uint256 amount) external returns (uint256 requestId)
function executeWithdrawal(uint256 requestId) external
```

Storage:
- `uint256 public withdrawDelay`
- `uint256 public nextRequestId`
- `mapping(uint256 => WithdrawalRequest) public requests`

Guards:
- OpenZeppelin `Ownable`
- OpenZeppelin `ReentrancyGuard`

## `PrivacyPool`

### Constructor
```solidity
constructor(
  address verifier_,
  uint256 denomination_,
  uint256 baseRelayerFee_,
  uint256 protocolFeeBps_,
  address payable treasury_
)
```

### Public/External Functions
```solidity
function isKnownRoot(bytes32 root) public view returns (bool)
function computeRootFromPath(bytes32 leaf, bytes32[20] calldata siblings, uint32 leafIndex) external pure returns (bytes32)
function verifyMerklePath(bytes32 leaf, bytes32[20] calldata siblings, uint32 leafIndex, bytes32 expectedRoot) external pure returns (bool)
function deposit(bytes32 commitment) external payable
function withdraw(bytes calldata proof, bytes32 root, bytes32 nullifierHash, address payable recipient, address payable relayer, uint256 fee, uint256 refund) external
function setBaseRelayerFee(uint256 newBaseRelayerFee) external
function setProtocolFeeBps(uint256 newProtocolFeeBps) external
function setTreasury(address payable newTreasury) external
function setRelayerOnly(bool enabled) external
function setApprovedRelayersOnly(bool enabled) external
function setRelayerApproval(address relayer, bool approved) external
```

### Storage Layout
- `IVerifier public immutable verifier`
- `uint256 public immutable denomination`
- `uint32 public nextLeafIndex`
- `bytes32 public currentRoot`
- `uint256 public depositCount`
- `uint256 public baseRelayerFee`
- `uint256 public protocolFeeBps`
- `address payable public treasury`
- `bool public relayerOnly`
- `bool public approvedRelayersOnly`
- `mapping(address => bool) public approvedRelayers`
- `mapping(bytes32 => bool) public commitmentUsed`
- `mapping(bytes32 => bool) public nullifierSpent`
- `mapping(bytes32 => bool) public rootKnown`
- `bytes32[100] public rootHistory`
- `uint256 public rootHistoryIndex`
- `bytes32[21] public zeros`
- `bytes32[20] public filledSubtrees`

### Merkle Semantics
- Incremental insert with `nextLeafIndex`, `zeros`, `filledSubtrees`.
- Root history ring-buffer with `rootKnown` membership checks.
- Path recomputation helper functions available for off-chain proof tooling/tests.

### Security Controls
- OpenZeppelin `Ownable` + `ReentrancyGuard`.
- `receive()` and `fallback()` revert (deposits must use `deposit`).
- Nullifier one-time spend.
- Relayer policy switches:
  - `relayerOnly=true` enforces relayer-submitted withdrawals.
  - `approvedRelayersOnly=true` enforces relayer allowlist.

## `PoolFactory`
```solidity
constructor(address verifier_, address payable treasury_)
function createPool(uint256 denomination, uint256 baseRelayerFee, uint256 protocolFeeBps) external returns (address)
function allPools() external view returns (address[] memory)
```

Storage:
- `address public immutable verifier`
- `address payable public immutable treasury`
- `address[] public pools`
