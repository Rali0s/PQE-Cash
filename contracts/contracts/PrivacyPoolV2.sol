// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from './IVerifier.sol';
import {IPoseidonHasher} from './IPoseidonHasher.sol';
import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';

contract PrivacyPoolV2 is Ownable, ReentrancyGuard {
  uint32 public constant TREE_LEVELS = 20;
  uint256 public constant ROOT_HISTORY_SIZE = 100;
  uint256 public constant FEE_BPS_DENOMINATOR = 10_000;

  IVerifier public immutable verifier;
  IPoseidonHasher public immutable hasher;
  uint256 public immutable denomination;

  uint256 public depositCount;
  uint32 public nextLeafIndex;
  bytes32 public currentRoot;
  uint256 public baseRelayerFee;
  uint256 public protocolFeeBps;
  address payable public treasury;
  bool public relayerOnly;
  bool public approvedRelayersOnly;

  mapping(bytes32 => bool) public commitmentUsed;
  mapping(bytes32 => bool) public nullifierSpent;
  mapping(bytes32 => bool) public rootKnown;
  mapping(address => bool) public approvedRelayers;
  bytes32[ROOT_HISTORY_SIZE] public rootHistory;
  uint256 public rootHistoryIndex;
  bytes32[TREE_LEVELS + 1] public zeros;
  bytes32[TREE_LEVELS] public filledSubtrees;

  event Deposit(bytes32 indexed commitment, uint256 leafIndex, bytes32 root, uint256 timestamp);
  event Withdrawal(bytes32 indexed nullifierHash, address indexed recipient, address indexed relayer, uint256 fee);
  event BaseRelayerFeeUpdated(uint256 previousValue, uint256 newValue);
  event ProtocolFeeBpsUpdated(uint256 previousValue, uint256 newValue);
  event TreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);
  event RelayerOnlyUpdated(bool previousValue, bool newValue);
  event ApprovedRelayersOnlyUpdated(bool previousValue, bool newValue);
  event RelayerApprovalUpdated(address indexed relayer, bool approved);

  error DirectEthDisabled();

  constructor(
    address verifier_,
    address hasher_,
    uint256 denomination_,
    uint256 baseRelayerFee_,
    uint256 protocolFeeBps_,
    address payable treasury_
  ) Ownable(msg.sender) {
    require(verifier_ != address(0), 'verifier=0');
    require(hasher_ != address(0), 'hasher=0');
    require(denomination_ > 0, 'denomination=0');
    require(protocolFeeBps_ <= FEE_BPS_DENOMINATOR, 'protocol fee too high');
    require(treasury_ != address(0), 'treasury=0');
    verifier = IVerifier(verifier_);
    hasher = IPoseidonHasher(hasher_);
    denomination = denomination_;
    baseRelayerFee = baseRelayerFee_;
    protocolFeeBps = protocolFeeBps_;
    treasury = treasury_;
    relayerOnly = true;
    approvedRelayersOnly = false;

    _initializeTree();
    _rememberRoot(currentRoot);
  }

  function isKnownRoot(bytes32 root) public view returns (bool) {
    return rootKnown[root];
  }

  function computeRootFromPath(
    bytes32 leaf,
    bytes32[TREE_LEVELS] calldata siblings,
    uint32 leafIndex
  ) external view returns (bytes32) {
    return _computeRootFromPath(leaf, siblings, leafIndex);
  }

  function verifyMerklePath(
    bytes32 leaf,
    bytes32[TREE_LEVELS] calldata siblings,
    uint32 leafIndex,
    bytes32 expectedRoot
  ) external view returns (bool) {
    return _computeRootFromPath(leaf, siblings, leafIndex) == expectedRoot;
  }

  function deposit(bytes32 commitment) external payable nonReentrant {
    require(msg.value == denomination, 'bad amount');
    require(!commitmentUsed[commitment], 'commitment used');
    require(nextLeafIndex < uint32(1) << TREE_LEVELS, 'tree is full');

    commitmentUsed[commitment] = true;
    currentRoot = _insert(commitment);
    _rememberRoot(currentRoot);

    emit Deposit(commitment, nextLeafIndex, currentRoot, block.timestamp);
    unchecked {
      nextLeafIndex += 1;
      depositCount += 1;
    }
  }

  function withdraw(
    bytes calldata proof,
    bytes32 root,
    bytes32 nullifierHash,
    address payable recipient,
    address payable relayer,
    uint256 fee,
    uint256 refund
  ) external nonReentrant {
    require(recipient != address(0), 'recipient=0');
    require(relayer != address(0), 'relayer=0');
    if (relayerOnly) {
      require(msg.sender == relayer, 'sender must be relayer');
    }
    if (approvedRelayersOnly) {
      require(approvedRelayers[relayer], 'relayer not approved');
    }
    require(!nullifierSpent[nullifierHash], 'nullifier spent');
    require(isKnownRoot(root), 'unknown root');
    require(fee >= baseRelayerFee, 'fee below base');

    uint256 protocolFee = (denomination * protocolFeeBps) / FEE_BPS_DENOMINATOR;
    require(fee + protocolFee <= denomination, 'fees too high');

    uint256[] memory input = new uint256[](7);
    input[0] = uint256(root);
    input[1] = uint256(nullifierHash);
    input[2] = uint256(uint160(address(recipient)));
    input[3] = uint256(uint160(address(relayer)));
    input[4] = fee;
    input[5] = refund;
    input[6] = block.chainid;

    require(verifier.verifyProof(proof, input), 'invalid proof');

    nullifierSpent[nullifierHash] = true;

    uint256 toRecipient = denomination - fee - protocolFee;

    _safeTransferETH(recipient, toRecipient);

    if (fee > 0) {
      _safeTransferETH(relayer, fee);
    }
    if (protocolFee > 0) {
      _safeTransferETH(treasury, protocolFee);
    }

    emit Withdrawal(nullifierHash, recipient, relayer, fee);
  }

  function setBaseRelayerFee(uint256 newBaseRelayerFee) external onlyOwner {
    uint256 previous = baseRelayerFee;
    baseRelayerFee = newBaseRelayerFee;
    emit BaseRelayerFeeUpdated(previous, newBaseRelayerFee);
  }

  function setProtocolFeeBps(uint256 newProtocolFeeBps) external onlyOwner {
    require(newProtocolFeeBps <= FEE_BPS_DENOMINATOR, 'protocol fee too high');
    uint256 previous = protocolFeeBps;
    protocolFeeBps = newProtocolFeeBps;
    emit ProtocolFeeBpsUpdated(previous, newProtocolFeeBps);
  }

  function setTreasury(address payable newTreasury) external onlyOwner {
    require(newTreasury != address(0), 'treasury=0');
    address previous = treasury;
    treasury = newTreasury;
    emit TreasuryUpdated(previous, newTreasury);
  }

  function setRelayerOnly(bool enabled) external onlyOwner {
    bool previous = relayerOnly;
    relayerOnly = enabled;
    emit RelayerOnlyUpdated(previous, enabled);
  }

  function setApprovedRelayersOnly(bool enabled) external onlyOwner {
    bool previous = approvedRelayersOnly;
    approvedRelayersOnly = enabled;
    emit ApprovedRelayersOnlyUpdated(previous, enabled);
  }

  function setRelayerApproval(address relayer, bool approved) external onlyOwner {
    require(relayer != address(0), 'relayer=0');
    approvedRelayers[relayer] = approved;
    emit RelayerApprovalUpdated(relayer, approved);
  }

  receive() external payable {
    revert DirectEthDisabled();
  }

  fallback() external payable {
    revert DirectEthDisabled();
  }

  function _rememberRoot(bytes32 root) internal {
    bytes32 evicted = rootHistory[rootHistoryIndex];
    if (evicted != bytes32(0)) {
      rootKnown[evicted] = false;
    }

    rootHistory[rootHistoryIndex] = root;
    rootKnown[root] = true;
    rootHistoryIndex = (rootHistoryIndex + 1) % ROOT_HISTORY_SIZE;
  }

  function _initializeTree() internal {
    bytes32 zeroValue = bytes32(block.chainid);
    zeros[0] = zeroValue;

    for (uint32 i = 0; i < TREE_LEVELS; i++) {
      filledSubtrees[i] = zeros[i];
      zeros[i + 1] = _hashLeftRight(zeros[i], zeros[i]);
    }

    currentRoot = zeros[TREE_LEVELS];
  }

  function _insert(bytes32 leaf) internal returns (bytes32) {
    uint32 currentIndex = nextLeafIndex;
    bytes32 currentLevelHash = leaf;
    bytes32 left;
    bytes32 right;

    for (uint32 i = 0; i < TREE_LEVELS; i++) {
      if (currentIndex % 2 == 0) {
        left = currentLevelHash;
        right = zeros[i];
        filledSubtrees[i] = currentLevelHash;
      } else {
        left = filledSubtrees[i];
        right = currentLevelHash;
      }

      currentLevelHash = _hashLeftRight(left, right);
      currentIndex /= 2;
    }

    return currentLevelHash;
  }

  function _hashLeftRight(bytes32 left, bytes32 right) internal view returns (bytes32) {
    return hasher.hash(left, right);
  }

  function _computeRootFromPath(
    bytes32 leaf,
    bytes32[TREE_LEVELS] calldata siblings,
    uint32 leafIndex
  ) internal view returns (bytes32) {
    require(leafIndex < uint32(1) << TREE_LEVELS, 'leafIndex out of range');

    bytes32 current = leaf;
    uint32 idx = leafIndex;
    for (uint32 i = 0; i < TREE_LEVELS; i++) {
      bytes32 sibling = siblings[i];
      if (idx % 2 == 0) {
        current = _hashLeftRight(current, sibling);
      } else {
        current = _hashLeftRight(sibling, current);
      }
      idx /= 2;
    }
    return current;
  }

  function _safeTransferETH(address payable to, uint256 amount) internal {
    (bool ok, ) = to.call{value: amount}('');
    require(ok, 'eth transfer failed');
  }
}
