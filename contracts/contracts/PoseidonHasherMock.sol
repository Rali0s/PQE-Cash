// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoseidonHasher} from './IPoseidonHasher.sol';

// Dev-only fallback hasher so PrivacyPoolV2 can be wired end-to-end before real Poseidon integration.
contract PoseidonHasherMock is IPoseidonHasher {
  function hash(bytes32 left, bytes32 right) external pure override returns (bytes32) {
    return keccak256(abi.encodePacked('POSEIDON_MOCK_V1', left, right));
  }
}
