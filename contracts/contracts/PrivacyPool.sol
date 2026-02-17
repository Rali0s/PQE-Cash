// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from './IVerifier.sol';
import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';

contract PrivacyPool is Ownable, ReentrancyGuard {
  uint256 public constant ROOT_HISTORY_SIZE = 100;
  uint256 public constant FEE_BPS_DENOMINATOR = 10_000;

  IVerifier public immutable verifier;
  uint256 public immutable denomination;

  uint256 public depositCount;
  bytes32 public currentRoot;
  uint256 public baseRelayerFee;
  uint256 public protocolFeeBps;
  address payable public treasury;

  mapping(bytes32 => bool) public commitmentUsed;
  mapping(bytes32 => bool) public nullifierSpent;
  mapping(bytes32 => bool) public rootKnown;
  bytes32[ROOT_HISTORY_SIZE] public rootHistory;
  uint256 public rootHistoryIndex;

  event Deposit(bytes32 indexed commitment, uint256 leafIndex, bytes32 root, uint256 timestamp);
  event Withdrawal(bytes32 indexed nullifierHash, address indexed recipient, address indexed relayer, uint256 fee);
  event BaseRelayerFeeUpdated(uint256 previousValue, uint256 newValue);
  event ProtocolFeeBpsUpdated(uint256 previousValue, uint256 newValue);
  event TreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);

  error DirectEthDisabled();

  constructor(
    address verifier_,
    uint256 denomination_,
    uint256 baseRelayerFee_,
    uint256 protocolFeeBps_,
    address payable treasury_
  ) Ownable(msg.sender) {
    require(verifier_ != address(0), 'verifier=0');
    require(denomination_ > 0, 'denomination=0');
    require(protocolFeeBps_ <= FEE_BPS_DENOMINATOR, 'protocol fee too high');
    require(treasury_ != address(0), 'treasury=0');
    verifier = IVerifier(verifier_);
    denomination = denomination_;
    baseRelayerFee = baseRelayerFee_;
    protocolFeeBps = protocolFeeBps_;
    treasury = treasury_;

    currentRoot = keccak256(abi.encodePacked(uint256(0), block.chainid));
    _rememberRoot(currentRoot);
  }

  function isKnownRoot(bytes32 root) public view returns (bool) {
    return rootKnown[root];
  }

  function deposit(bytes32 commitment) external payable nonReentrant {
    require(msg.value == denomination, 'bad amount');
    require(!commitmentUsed[commitment], 'commitment used');

    commitmentUsed[commitment] = true;

    currentRoot = keccak256(abi.encodePacked(currentRoot, commitment, depositCount));
    _rememberRoot(currentRoot);

    emit Deposit(commitment, depositCount, currentRoot, block.timestamp);
    unchecked {
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

  function _safeTransferETH(address payable to, uint256 amount) internal {
    (bool ok, ) = to.call{value: amount}('');
    require(ok, 'eth transfer failed');
  }
}
