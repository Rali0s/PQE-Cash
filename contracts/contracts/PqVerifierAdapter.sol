// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from './IVerifier.sol';
import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';
import {IExternalPqVerifierBytes, IExternalPqVerifierUint} from './IExternalPqVerifier.sol';

contract PqVerifierAdapter is IVerifier, Ownable {
  enum BackendType {
    Bytes,
    Uint
  }

  address public externalVerifier;
  BackendType public backendType;

  event ExternalVerifierUpdated(address indexed previousVerifier, address indexed newVerifier);
  event BackendTypeUpdated(BackendType previousType, BackendType newType);

  constructor(address externalVerifier_, BackendType backendType_) Ownable(msg.sender) {
    require(externalVerifier_ != address(0), 'externalVerifier=0');
    externalVerifier = externalVerifier_;
    backendType = backendType_;
  }

  function setExternalVerifier(address externalVerifier_) external onlyOwner {
    require(externalVerifier_ != address(0), 'externalVerifier=0');
    address previous = externalVerifier;
    externalVerifier = externalVerifier_;
    emit ExternalVerifierUpdated(previous, externalVerifier_);
  }

  function setBackendType(BackendType backendType_) external onlyOwner {
    BackendType previous = backendType;
    backendType = backendType_;
    emit BackendTypeUpdated(previous, backendType_);
  }

  function verifyProof(bytes calldata proof, uint256[] calldata input) external view override returns (bool) {
    if (backendType == BackendType.Bytes) {
      return _verifyBytes(proof, input);
    }
    if (backendType == BackendType.Uint) {
      return _verifyUint(proof, input);
    }
    return false;
  }

  function _verifyBytes(bytes calldata proof, uint256[] calldata input) internal view returns (bool) {
    bytes memory encodedPublicInputs = abi.encode(input);

    (bool okBytes, bytes memory retBytes) = externalVerifier.staticcall(
      abi.encodeWithSelector(IExternalPqVerifierBytes.verify.selector, proof, encodedPublicInputs)
    );

    if (okBytes && retBytes.length == 32) {
      return abi.decode(retBytes, (bool));
    }
    return false;
  }

  function _verifyUint(bytes calldata proof, uint256[] calldata input) internal view returns (bool) {
    (bool okUint, bytes memory retUint) = externalVerifier.staticcall(
      abi.encodeWithSelector(IExternalPqVerifierUint.verifyProof.selector, proof, input)
    );

    if (okUint && retUint.length == 32) {
      return abi.decode(retUint, (bool));
    }
    return false;
  }
}
