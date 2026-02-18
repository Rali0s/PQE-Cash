require('@nomicfoundation/hardhat-toolbox');
require('dotenv').config();

const sepoliaRpcUrl = process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';
const deployerPrivateKey = process.env.DEPLOYER_PRIVATE_KEY || '';

module.exports = {
  solidity: {
    version: '0.8.24',
    settings: {
      optimizer: { enabled: true, runs: 200 }
    }
  },
  networks: {
    localhost: {
      url: 'http://127.0.0.1:8545'
    },
    docker: {
      url: 'http://hardhat:8545'
    },
    sepolia: {
      url: sepoliaRpcUrl,
      accounts: deployerPrivateKey ? [deployerPrivateKey] : []
    }
  }
};
