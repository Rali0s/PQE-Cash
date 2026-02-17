// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVerifier {
  function verifyProof(bytes calldata proof, uint256[] calldata input) external view returns (bool);
}
