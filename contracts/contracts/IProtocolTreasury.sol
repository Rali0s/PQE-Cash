// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IProtocolTreasury {
  function queueWithdrawal(address payable to, uint256 amount) external returns (uint256 requestId);
}
