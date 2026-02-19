const hre = require('hardhat');

function required(name) {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`Missing required env: ${name}`);
  }
  return value.trim();
}

function optional(name, fallback = '') {
  const value = process.env[name];
  return value === undefined ? fallback : String(value).trim();
}

function parseBool(name, fallback = false) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

async function assertContractCode(provider, address, label) {
  if (!hre.ethers.isAddress(address)) {
    throw new Error(`${label} is not a valid address: ${address}`);
  }
  const code = await provider.getCode(address);
  if (!code || code === '0x') {
    throw new Error(`${label} has no bytecode at ${address}`);
  }
}

async function main() {
  const network = hre.network.name;
  if (network !== 'sepolia') {
    throw new Error(`Preflight must run on sepolia network, got: ${network}`);
  }

  const provider = hre.ethers.provider;
  const signers = await hre.ethers.getSigners();
  if (!signers || signers.length === 0) {
    throw new Error('No deployer signer available from DEPLOYER_PRIVATE_KEY');
  }
  const deployer = signers[0];

  const poolVersion = optional('POOL_VERSION', 'v1').toLowerCase();
  if (!['v1', 'v2'].includes(poolVersion)) {
    throw new Error('POOL_VERSION must be v1 or v2');
  }

  const externalVerifierBackend = optional('EXTERNAL_VERIFIER_BACKEND', 'bytes').toLowerCase();
  if (!['bytes', 'uint'].includes(externalVerifierBackend)) {
    throw new Error('EXTERNAL_VERIFIER_BACKEND must be bytes or uint');
  }

  const allowDevVerifier = parseBool('ALLOW_DEV_VERIFIER', false);
  const allowEoaExternalVerifier = parseBool('ALLOW_EOA_EXTERNAL_VERIFIER', false);
  const allowDevPoseidonHasher = parseBool('ALLOW_DEV_POSEIDON_HASHER', false);

  if (allowDevVerifier) {
    throw new Error('ALLOW_DEV_VERIFIER must be false for Sepolia release');
  }
  if (allowEoaExternalVerifier) {
    throw new Error('ALLOW_EOA_EXTERNAL_VERIFIER must be false for Sepolia release');
  }
  if (allowDevPoseidonHasher) {
    throw new Error('ALLOW_DEV_POSEIDON_HASHER must be false for Sepolia release');
  }

  const expectedDeployer = required('EXPECTED_DEPLOYER_ADDRESS');
  if (!hre.ethers.isAddress(expectedDeployer)) {
    throw new Error(`EXPECTED_DEPLOYER_ADDRESS invalid: ${expectedDeployer}`);
  }
  if (deployer.address.toLowerCase() !== expectedDeployer.toLowerCase()) {
    throw new Error(`Deployer mismatch expected=${expectedDeployer} actual=${deployer.address}`);
  }

  const externalVerifierAddress = required('EXTERNAL_VERIFIER_ADDRESS');
  await assertContractCode(provider, externalVerifierAddress, 'EXTERNAL_VERIFIER_ADDRESS');

  let poseidonHasherAddress = '';
  if (poolVersion === 'v2') {
    poseidonHasherAddress = required('POSEIDON_HASHER_ADDRESS');
    await assertContractCode(provider, poseidonHasherAddress, 'POSEIDON_HASHER_ADDRESS');
  }

  const chain = await provider.getNetwork();
  if (Number(chain.chainId) !== 11155111) {
    throw new Error(`Wrong chain: expected 11155111 got ${Number(chain.chainId)}`);
  }

  const balance = await provider.getBalance(deployer.address);
  const recommendedMin = hre.ethers.parseEther('0.02');
  if (balance < recommendedMin) {
    throw new Error(
      `Deployer balance too low: ${hre.ethers.formatEther(balance)} ETH (recommend >= ${hre.ethers.formatEther(recommendedMin)} ETH)`
    );
  }

  console.log('Sepolia release preflight passed');
  console.log(`chainId=${Number(chain.chainId)}`);
  console.log(`deployer=${deployer.address}`);
  console.log(`poolVersion=${poolVersion}`);
  console.log(`externalVerifierBackend=${externalVerifierBackend}`);
  console.log(`externalVerifier=${externalVerifierAddress}`);
  if (poolVersion === 'v2') {
    console.log(`poseidonHasher=${poseidonHasherAddress}`);
  }
  console.log(`deployerBalanceEth=${hre.ethers.formatEther(balance)}`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
