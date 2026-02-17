// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IExternalPqVerifierBytes {
  function verify(bytes calldata proof, bytes calldata publicInputs) external view returns (bool);
}

interface IExternalPqVerifierUint {
  function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool);
}
