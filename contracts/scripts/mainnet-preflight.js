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

async function estimateDeployGas(contractName, args, signer) {
  const factory = await hre.ethers.getContractFactory(contractName, signer);
  const tx = await factory.getDeployTransaction(...args);
  return signer.estimateGas(tx);
}

async function main() {
  const networkName = hre.network.name;
  if (networkName !== 'mainnet') {
    throw new Error(`Preflight must run on mainnet network, got: ${networkName}`);
  }

  const provider = hre.ethers.provider;
  const chain = await provider.getNetwork();
  if (Number(chain.chainId) !== 1) {
    throw new Error(`Wrong chain: expected 1 got ${Number(chain.chainId)}`);
  }

  if (!parseBool('ALLOW_MAINNET_DEPLOY', false)) {
    throw new Error('ALLOW_MAINNET_DEPLOY must be true for mainnet deployment');
  }

  const signers = await hre.ethers.getSigners();
  if (!signers || signers.length === 0) {
    throw new Error(
      'No deployer signer available from MAINNET_DEPLOYER_PRIVATE_KEY (or DEPLOYER_MAINNET_PRIVATE_KEY)'
    );
  }
  const deployer = signers[0];

  const expectedDeployer = required('EXPECTED_DEPLOYER_ADDRESS');
  if (!hre.ethers.isAddress(expectedDeployer)) {
    throw new Error(`EXPECTED_DEPLOYER_ADDRESS invalid: ${expectedDeployer}`);
  }
  if (deployer.address.toLowerCase() !== expectedDeployer.toLowerCase()) {
    throw new Error(`Deployer mismatch expected=${expectedDeployer} actual=${deployer.address}`);
  }

  const poolVersion = optional('POOL_VERSION', 'v2').toLowerCase();
  if (!['v1', 'v2'].includes(poolVersion)) {
    throw new Error('POOL_VERSION must be v1 or v2');
  }
  const backend = optional('EXTERNAL_VERIFIER_BACKEND', 'bytes').toLowerCase();
  if (!['bytes', 'uint'].includes(backend)) {
    throw new Error('EXTERNAL_VERIFIER_BACKEND must be bytes or uint');
  }

  if (parseBool('ALLOW_DEV_VERIFIER', false)) {
    throw new Error('ALLOW_DEV_VERIFIER must be false on mainnet');
  }
  if (parseBool('ALLOW_EOA_EXTERNAL_VERIFIER', false)) {
    throw new Error('ALLOW_EOA_EXTERNAL_VERIFIER must be false on mainnet');
  }
  if (parseBool('ALLOW_DEV_POSEIDON_HASHER', false)) {
    throw new Error('ALLOW_DEV_POSEIDON_HASHER must be false on mainnet');
  }

  const externalVerifier = required('EXTERNAL_VERIFIER_ADDRESS');
  await assertContractCode(provider, externalVerifier, 'EXTERNAL_VERIFIER_ADDRESS');

  let poseidonHasher = '';
  if (poolVersion === 'v2') {
    poseidonHasher = required('POSEIDON_HASHER_ADDRESS');
    await assertContractCode(provider, poseidonHasher, 'POSEIDON_HASHER_ADDRESS');
  }

  const denominationEth = optional('DENOMINATION_ETH', '0.1');
  const baseRelayerFeeEth = optional('BASE_RELAYER_FEE_ETH', '0.001');
  const protocolFeeBps = Number(optional('PROTOCOL_FEE_BPS', '50'));
  const treasuryDelaySec = optional('TREASURY_WITHDRAW_DELAY_SEC', '3600');
  if (Number.isNaN(protocolFeeBps) || protocolFeeBps < 0 || protocolFeeBps > 10_000) {
    throw new Error('PROTOCOL_FEE_BPS must be between 0 and 10000');
  }

  const denomination = hre.ethers.parseEther(denominationEth);
  const baseRelayerFee = hre.ethers.parseEther(baseRelayerFeeEth);
  if (baseRelayerFee > denomination) {
    throw new Error('BASE_RELAYER_FEE_ETH cannot exceed DENOMINATION_ETH');
  }
  const backendType = backend === 'bytes' ? 0 : 1;

  const gasAdapter = await estimateDeployGas('PqVerifierAdapter', [externalVerifier, backendType], deployer);
  const gasTreasury = await estimateDeployGas('ProtocolTreasury', [BigInt(treasuryDelaySec)], deployer);
  const gasPool =
    poolVersion === 'v2'
      ? await estimateDeployGas(
          'PrivacyPoolV2',
          [externalVerifier, poseidonHasher, denomination, baseRelayerFee, protocolFeeBps, deployer.address],
          deployer
        )
      : await estimateDeployGas(
          'PrivacyPool',
          [externalVerifier, denomination, baseRelayerFee, protocolFeeBps, deployer.address],
          deployer
        );

  const totalGas = gasAdapter + gasTreasury + gasPool;
  const gasPrice = await provider.getFeeData();
  const maxFeePerGas = gasPrice.maxFeePerGas || gasPrice.gasPrice;
  if (!maxFeePerGas) {
    throw new Error('Failed to fetch fee data');
  }
  const estimatedWei = totalGas * maxFeePerGas;

  const deployerBalance = await provider.getBalance(deployer.address);
  const recommendedMin = estimatedWei + hre.ethers.parseEther('0.05');
  const allowLowBalanceBypass = parseBool('ALLOW_LOW_BALANCE_BYPASS', false);
  if (deployerBalance < recommendedMin) {
    if (!allowLowBalanceBypass) {
      throw new Error(
        `Deployer balance too low: ${hre.ethers.formatEther(deployerBalance)} ETH (recommend >= ${hre.ethers.formatEther(recommendedMin)} ETH)`
      );
    }
    console.warn(
      `WARNING: ALLOW_LOW_BALANCE_BYPASS=true set. Deployer balance is low: ${hre.ethers.formatEther(deployerBalance)} ETH (recommend >= ${hre.ethers.formatEther(recommendedMin)} ETH)`
    );
  }

  console.log('Mainnet preflight passed');
  console.log(`chainId=${Number(chain.chainId)}`);
  console.log(`deployer=${deployer.address}`);
  console.log(`poolVersion=${poolVersion}`);
  console.log(`externalVerifierBackend=${backend}`);
  console.log(`externalVerifier=${externalVerifier}`);
  if (poolVersion === 'v2') {
    console.log(`poseidonHasher=${poseidonHasher}`);
  }
  console.log(`denominationEth=${denominationEth}`);
  console.log(`baseRelayerFeeEth=${baseRelayerFeeEth}`);
  console.log(`protocolFeeBps=${protocolFeeBps}`);
  console.log(`treasuryWithdrawDelaySec=${treasuryDelaySec}`);
  console.log(`estimatedDeployGas=${totalGas.toString()}`);
  console.log(`networkMaxFeePerGasWei=${maxFeePerGas.toString()}`);
  console.log(`estimatedDeployCostEth=${hre.ethers.formatEther(estimatedWei)}`);
  console.log(`deployerBalanceEth=${hre.ethers.formatEther(deployerBalance)}`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
