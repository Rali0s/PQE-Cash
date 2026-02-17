// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from './IVerifier.sol';
import {IExternalPqVerifierBytes, IExternalPqVerifierUint} from './IExternalPqVerifier.sol';

contract PqVerifierAdapter is IVerifier {
  address public owner;
  address public externalVerifier;

  event ExternalVerifierUpdated(address indexed previousVerifier, address indexed newVerifier);

  modifier onlyOwner() {
    require(msg.sender == owner, 'not owner');
    _;
  }

  constructor(address externalVerifier_) {
    require(externalVerifier_ != address(0), 'externalVerifier=0');
    owner = msg.sender;
    externalVerifier = externalVerifier_;
  }

  function setExternalVerifier(address externalVerifier_) external onlyOwner {
    require(externalVerifier_ != address(0), 'externalVerifier=0');
    address previous = externalVerifier;
    externalVerifier = externalVerifier_;
    emit ExternalVerifierUpdated(previous, externalVerifier_);
  }

  function verifyProof(bytes calldata proof, uint256[] calldata input) external view override returns (bool) {
    bytes memory encodedPublicInputs = abi.encode(input);

    (bool okBytes, bytes memory retBytes) = externalVerifier.staticcall(
      abi.encodeWithSelector(IExternalPqVerifierBytes.verify.selector, proof, encodedPublicInputs)
    );

    if (okBytes && retBytes.length >= 32) {
      return abi.decode(retBytes, (bool));
    }

    (bool okUint, bytes memory retUint) = externalVerifier.staticcall(
      abi.encodeWithSelector(IExternalPqVerifierUint.verifyProof.selector, proof, input)
    );

    if (okUint && retUint.length >= 32) {
      return abi.decode(retUint, (bool));
    }

    return false;
  }
}
