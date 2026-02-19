// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPoseidonHasher {
  function hash(bytes32 left, bytes32 right) external view returns (bytes32);
}
