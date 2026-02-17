# 1. Contract Interfaces and Storage Layout

## `IVerifier`
```solidity
function verifyProof(bytes calldata proof, uint256[] calldata input) external view returns (bool);
```

## `PqVerifierAdapter`
```solidity
function verifyProof(bytes calldata proof, uint256[] calldata input) external view returns (bool);
function setExternalVerifier(address externalVerifier_) external;
```

Adapter behavior:
- Tries external verifier `verify(bytes proof, bytes publicInputsEncoded)`.
- Fallback tries `verifyProof(bytes proof, uint256[] publicInputs)`.
- Returns false if neither call path succeeds.

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

Security:
- `Ownable`, `ReentrancyGuard`
- `receive()` accepts funds
- `fallback()` reverts

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

### Public Functions
```solidity
function isKnownRoot(bytes32 root) public view returns (bool)
function deposit(bytes32 commitment) external payable
function withdraw(
  bytes calldata proof,
  bytes32 root,
  bytes32 nullifierHash,
  address payable recipient,
  address payable relayer,
  uint256 fee,
  uint256 refund
) external
function setBaseRelayerFee(uint256 newBaseRelayerFee) external
function setProtocolFeeBps(uint256 newProtocolFeeBps) external
function setTreasury(address payable newTreasury) external
```

### Storage Layout
- `IVerifier public immutable verifier`
- `uint256 public immutable denomination`
- `uint256 public depositCount`
- `bytes32 public currentRoot`
- `uint256 public baseRelayerFee`
- `uint256 public protocolFeeBps`
- `address payable public treasury`
- `mapping(bytes32 => bool) public commitmentUsed`
- `mapping(bytes32 => bool) public nullifierSpent`
- `mapping(bytes32 => bool) public rootKnown`
- `bytes32[100] public rootHistory`
- `uint256 public rootHistoryIndex`

### Events
```solidity
event Deposit(bytes32 indexed commitment, uint256 leafIndex, bytes32 root, uint256 timestamp);
event Withdrawal(bytes32 indexed nullifierHash, address indexed recipient, address indexed relayer, uint256 fee);
event BaseRelayerFeeUpdated(uint256 previousValue, uint256 newValue);
event ProtocolFeeBpsUpdated(uint256 previousValue, uint256 newValue);
event TreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);
```

### Security Controls
- Uses OpenZeppelin `Ownable` and `ReentrancyGuard`.
- `receive()` and `fallback()` both revert to prevent accidental ETH sends outside `deposit`.

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
