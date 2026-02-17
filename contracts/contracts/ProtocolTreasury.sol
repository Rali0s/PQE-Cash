// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';

contract ProtocolTreasury is Ownable, ReentrancyGuard {
  struct WithdrawalRequest {
    address payable to;
    uint256 amount;
    uint256 unlockTime;
    bool executed;
  }

  uint256 public withdrawDelay;
  uint256 public nextRequestId;
  mapping(uint256 => WithdrawalRequest) public requests;

  event WithdrawalQueued(uint256 indexed requestId, address indexed to, uint256 amount, uint256 unlockTime);
  event WithdrawalExecuted(uint256 indexed requestId, address indexed to, uint256 amount);
  event WithdrawDelayUpdated(uint256 previousValue, uint256 newValue);

  error DirectFallbackDisabled();

  constructor(uint256 withdrawDelay_) Ownable(msg.sender) {
    withdrawDelay = withdrawDelay_;
  }

  function setWithdrawDelay(uint256 newWithdrawDelay) external onlyOwner {
    uint256 previous = withdrawDelay;
    withdrawDelay = newWithdrawDelay;
    emit WithdrawDelayUpdated(previous, newWithdrawDelay);
  }

  function queueWithdrawal(address payable to, uint256 amount) external onlyOwner returns (uint256 requestId) {
    require(to != address(0), 'to=0');
    require(amount > 0, 'amount=0');

    requestId = nextRequestId;
    unchecked {
      nextRequestId += 1;
    }

    uint256 unlockTime = block.timestamp + withdrawDelay;
    requests[requestId] = WithdrawalRequest({
      to: to,
      amount: amount,
      unlockTime: unlockTime,
      executed: false
    });

    emit WithdrawalQueued(requestId, to, amount, unlockTime);
  }

  function executeWithdrawal(uint256 requestId) external onlyOwner nonReentrant {
    WithdrawalRequest storage request = requests[requestId];
    require(!request.executed, 'already executed');
    require(request.to != address(0), 'request missing');
    require(block.timestamp >= request.unlockTime, 'withdrawal locked');
    require(address(this).balance >= request.amount, 'insufficient balance');

    request.executed = true;
    _safeTransferETH(request.to, request.amount);

    emit WithdrawalExecuted(requestId, request.to, request.amount);
  }

  receive() external payable {}

  fallback() external payable {
    revert DirectFallbackDisabled();
  }

  function _safeTransferETH(address payable to, uint256 amount) internal {
    (bool ok, ) = to.call{value: amount}('');
    require(ok, 'eth transfer failed');
  }
}
