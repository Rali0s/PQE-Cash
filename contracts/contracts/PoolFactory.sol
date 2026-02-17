// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PrivacyPool} from './PrivacyPool.sol';

contract PoolFactory {
  address public immutable verifier;
  address payable public immutable treasury;
  address[] public pools;

  event PoolCreated(address indexed pool, uint256 denomination);

  constructor(address verifier_, address payable treasury_) {
    verifier = verifier_;
    treasury = treasury_;
  }

  function createPool(uint256 denomination, uint256 baseRelayerFee, uint256 protocolFeeBps) external returns (address) {
    PrivacyPool pool = new PrivacyPool(verifier, denomination, baseRelayerFee, protocolFeeBps, treasury);
    pools.push(address(pool));
    emit PoolCreated(address(pool), denomination);
    return address(pool);
  }

  function allPools() external view returns (address[] memory) {
    return pools;
  }
}
