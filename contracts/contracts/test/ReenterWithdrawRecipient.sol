// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IWithdrawPool {
  function withdraw(
    bytes calldata proof,
    bytes32 root,
    bytes32 nullifierHash,
    address payable recipient,
    address payable relayer,
    uint256 fee,
    uint256 refund
  ) external;
}

contract ReenterWithdrawRecipient {
  address public targetPool;
  bytes public payload;
  bool public attempted;
  bool public reenterSucceeded;

  function arm(
    address targetPool_,
    bytes calldata proof,
    bytes32 root,
    bytes32 nullifierHash,
    address payable relayer,
    uint256 fee,
    uint256 refund
  ) external {
    targetPool = targetPool_;
    payload = abi.encodeWithSelector(
      IWithdrawPool.withdraw.selector,
      proof,
      root,
      nullifierHash,
      payable(address(this)),
      relayer,
      fee,
      refund
    );
    attempted = false;
    reenterSucceeded = false;
  }

  receive() external payable {
    if (attempted || payload.length == 0) {
      return;
    }

    attempted = true;
    (bool ok, ) = targetPool.call(payload);
    reenterSucceeded = ok;
  }
}
