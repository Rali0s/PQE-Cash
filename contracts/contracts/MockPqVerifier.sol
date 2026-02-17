// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from './IVerifier.sol';

contract MockPqVerifier is IVerifier {
  function verifyProof(bytes calldata proof, uint256[] calldata input) external pure override returns (bool) {
    return proof.length > 0 && input.length == 7;
  }
}
