const hre = require('hardhat');
const fs = require('fs');
const path = require('path');

function parseEnvBool(name, defaultValue = false) {
  const value = process.env[name];
  if (value == null || value === '') return defaultValue;
  const normalized = String(value).trim().toLowerCase();
  return ['1', 'true', 'yes', 'y', 'on'].includes(normalized);
}

async function main() {
  const networkName = hre.network.name;
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  const isMainnet = chainId === 1 || networkName === 'mainnet';

  const signers = await hre.ethers.getSigners();
  if (!signers || signers.length === 0) {
    throw new Error(
      isMainnet
        ? 'No deployer signer found. Set MAINNET_DEPLOYER_PRIVATE_KEY (or DEPLOYER_MAINNET_PRIVATE_KEY) in .env.'
        : 'No deployer signer found. Set DEPLOYER_PRIVATE_KEY in .env.'
    );
  }
  const [deployer] = signers;
  console.log('Network:', networkName, `(chainId=${chainId})`);
  console.log('Deployer:', deployer.address);

  if (isMainnet) {
    const allowMainnet = parseEnvBool('ALLOW_MAINNET_DEPLOY', false);
    if (!allowMainnet) {
      throw new Error(
        'Mainnet deploy blocked. Set ALLOW_MAINNET_DEPLOY=true after final verification.'
      );
    }
  }

  const expectedDeployer = process.env.EXPECTED_DEPLOYER_ADDRESS || '';
  if (expectedDeployer) {
    if (!hre.ethers.isAddress(expectedDeployer)) {
      throw new Error('EXPECTED_DEPLOYER_ADDRESS is not a valid address');
    }
    if (deployer.address.toLowerCase() !== expectedDeployer.toLowerCase()) {
      throw new Error(`Deployer mismatch. expected=${expectedDeployer} got=${deployer.address}`);
    }
  }

  const backendName = (process.env.EXTERNAL_VERIFIER_BACKEND || 'bytes').toLowerCase();
  const backendMap = { bytes: 0, uint: 1 };
  if (!(backendName in backendMap)) {
    throw new Error('EXTERNAL_VERIFIER_BACKEND must be "bytes" or "uint"');
  }
  const backendType = backendMap[backendName];

  const providedExternalVerifier = process.env.EXTERNAL_VERIFIER_ADDRESS || '';
  const allowDevVerifier = process.env.ALLOW_DEV_VERIFIER === 'true';
  const poolVersion = (process.env.POOL_VERSION || 'v1').toLowerCase();
  if (!['v1', 'v2'].includes(poolVersion)) {
    throw new Error('POOL_VERSION must be "v1" or "v2"');
  }
  if (isMainnet) {
    if (allowDevVerifier) {
      throw new Error('ALLOW_DEV_VERIFIER must be false on mainnet');
    }
    if (!providedExternalVerifier) {
      throw new Error('EXTERNAL_VERIFIER_ADDRESS is required on mainnet');
    }
  }

  let externalVerifierAddress;
  let externalVerifierDeployed = false;
  let poseidonHasherAddress = '';
  let poseidonHasherDeployed = false;

  if (providedExternalVerifier) {
    if (!hre.ethers.isAddress(providedExternalVerifier)) {
      throw new Error('EXTERNAL_VERIFIER_ADDRESS is not a valid address');
    }
    const code = await hre.ethers.provider.getCode(providedExternalVerifier);
    const hasCode = code && code !== '0x';
    if (!hasCode && process.env.ALLOW_EOA_EXTERNAL_VERIFIER !== 'true') {
      throw new Error(
        `EXTERNAL_VERIFIER_ADDRESS has no code on this network (${providedExternalVerifier}). Set ALLOW_EOA_EXTERNAL_VERIFIER=true to bypass.`
      );
    }
    if (!hasCode && isMainnet) {
      throw new Error('EXTERNAL_VERIFIER_ADDRESS has no code on mainnet');
    }
    externalVerifierAddress = providedExternalVerifier;
  } else if (allowDevVerifier) {
    const externalVerifier = await hre.ethers.deployContract('DevExternalPqVerifier');
    await externalVerifier.waitForDeployment();
    externalVerifierAddress = await externalVerifier.getAddress();
    externalVerifierDeployed = true;
  } else {
    throw new Error(
      'Production deployment requires EXTERNAL_VERIFIER_ADDRESS. For local/dev only, set ALLOW_DEV_VERIFIER=true.'
    );
  }

  const verifierAdapter = await hre.ethers.deployContract('PqVerifierAdapter', [externalVerifierAddress, backendType]);
  await verifierAdapter.waitForDeployment();
  const withdrawDelaySec = BigInt(process.env.TREASURY_WITHDRAW_DELAY_SEC || '3600');
  const treasury = await hre.ethers.deployContract('ProtocolTreasury', [withdrawDelaySec]);
  await treasury.waitForDeployment();

  if (poolVersion === 'v2') {
    const providedPoseidonHasher = process.env.POSEIDON_HASHER_ADDRESS || '';
    const allowDevPoseidonHasher = process.env.ALLOW_DEV_POSEIDON_HASHER === 'true';
    if (isMainnet) {
      if (allowDevPoseidonHasher) {
        throw new Error('ALLOW_DEV_POSEIDON_HASHER must be false on mainnet');
      }
      if (!providedPoseidonHasher) {
        throw new Error('POSEIDON_HASHER_ADDRESS is required for POOL_VERSION=v2 on mainnet');
      }
    }
    if (providedPoseidonHasher) {
      if (!hre.ethers.isAddress(providedPoseidonHasher)) {
        throw new Error('POSEIDON_HASHER_ADDRESS is not a valid address');
      }
      const code = await hre.ethers.provider.getCode(providedPoseidonHasher);
      if (!code || code === '0x') {
        throw new Error(`POSEIDON_HASHER_ADDRESS has no code on this network (${providedPoseidonHasher})`);
      }
      poseidonHasherAddress = providedPoseidonHasher;
    } else if (allowDevPoseidonHasher) {
      const poseidonHasher = await hre.ethers.deployContract('PoseidonHasherMock');
      await poseidonHasher.waitForDeployment();
      poseidonHasherAddress = await poseidonHasher.getAddress();
      poseidonHasherDeployed = true;
    } else {
      throw new Error(
        'POOL_VERSION=v2 requires POSEIDON_HASHER_ADDRESS. For local/dev only, set ALLOW_DEV_POSEIDON_HASHER=true.'
      );
    }
  }

  const denomination = hre.ethers.parseEther(process.env.DENOMINATION_ETH || '0.1');
  const baseRelayerFee = hre.ethers.parseEther(process.env.BASE_RELAYER_FEE_ETH || '0.001');
  const protocolFeeBps = Number(process.env.PROTOCOL_FEE_BPS || '50');
  if (Number.isNaN(protocolFeeBps) || protocolFeeBps < 0 || protocolFeeBps > 10_000) {
    throw new Error('PROTOCOL_FEE_BPS must be between 0 and 10000');
  }
  if (baseRelayerFee > denomination) {
    throw new Error('BASE_RELAYER_FEE_ETH cannot exceed DENOMINATION_ETH');
  }
  const pool =
    poolVersion === 'v2'
      ? await hre.ethers.deployContract('PrivacyPoolV2', [
          await verifierAdapter.getAddress(),
          poseidonHasherAddress,
          denomination,
          baseRelayerFee,
          protocolFeeBps,
          await treasury.getAddress()
        ])
      : await hre.ethers.deployContract('PrivacyPool', [
          await verifierAdapter.getAddress(),
          denomination,
          baseRelayerFee,
          protocolFeeBps,
          await treasury.getAddress()
        ]);
  await pool.waitForDeployment();

  const out = {
    network: networkName,
    chainId,
    deployer: deployer.address,
    externalVerifier: externalVerifierAddress,
    externalVerifierBackend: backendName,
    externalVerifierDeployed,
    poolVersion,
    poseidonHasher: poseidonHasherAddress || undefined,
    poseidonHasherDeployed,
    verifierAdapter: await verifierAdapter.getAddress(),
    treasury: await treasury.getAddress(),
    privacyPool: await pool.getAddress(),
    denomination: denomination.toString(),
    baseRelayerFee: baseRelayerFee.toString(),
    protocolFeeBps,
    treasuryWithdrawDelaySec: withdrawDelaySec.toString()
  };

  console.log('ExternalVerifier:', out.externalVerifier, `(backend=${backendName}, deployed=${externalVerifierDeployed})`);
  if (poolVersion === 'v2') {
    console.log('PoseidonHasher:', out.poseidonHasher, `(deployed=${poseidonHasherDeployed})`);
  }
  console.log('PqVerifierAdapter:', out.verifierAdapter);
  console.log(`PrivacyPool(${poolVersion}):`, out.privacyPool);
  console.log('Denomination (wei):', out.denomination);

  const outputPath = process.env.DEPLOY_OUTPUT;
  if (outputPath) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(out, null, 2));
    console.log('Deployment JSON:', outputPath);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
