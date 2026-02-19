// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract FieldBoundedExternalVerifier {
  uint256 internal constant SNARK_SCALAR_FIELD =
    21888242871839275222246405745257275088548364400416034343698204186575808495617;

  function verify(bytes calldata proof, bytes calldata publicInputs) external pure returns (bool) {
    if (proof.length == 0) {
      return false;
    }

    uint256[] memory decoded = abi.decode(publicInputs, (uint256[]));
    return _allInField(decoded);
  }

  function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) external pure returns (bool) {
    if (proof.length == 0) {
      return false;
    }
    return _allInField(publicInputs);
  }

  function _allInField(uint256[] memory values) internal pure returns (bool) {
    if (values.length != 7) {
      return false;
    }

    for (uint256 i = 0; i < values.length; i++) {
      if (values[i] >= SNARK_SCALAR_FIELD) {
        return false;
      }
    }

    return true;
  }
}
