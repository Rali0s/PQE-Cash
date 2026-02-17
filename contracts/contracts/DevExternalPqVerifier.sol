// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DevExternalPqVerifier {
  function verify(bytes calldata proof, bytes calldata publicInputs) external pure returns (bool) {
    if (proof.length == 0) {
      return false;
    }

    uint256[] memory decoded = abi.decode(publicInputs, (uint256[]));
    return decoded.length == 7;
  }
}
