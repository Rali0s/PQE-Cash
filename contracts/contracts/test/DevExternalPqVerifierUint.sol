// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DevExternalPqVerifierUint {
  function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) external pure returns (bool) {
    return proof.length > 0 && publicInputs.length == 7;
  }
}
