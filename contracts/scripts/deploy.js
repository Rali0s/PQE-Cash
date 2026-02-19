const hre = require('hardhat');
const fs = require('fs');
const path = require('path');

async function main() {
  const signers = await hre.ethers.getSigners();
  if (!signers || signers.length === 0) {
    throw new Error('No deployer signer found. Set DEPLOYER_PRIVATE_KEY in .env for testnet networks.');
  }
  const [deployer] = signers;
  console.log('Deployer:', deployer.address);

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
  const treasury = await hre.ethers.deployContract('ProtocolTreasury', [3600]);
  await treasury.waitForDeployment();

  if (poolVersion === 'v2') {
    const providedPoseidonHasher = process.env.POSEIDON_HASHER_ADDRESS || '';
    const allowDevPoseidonHasher = process.env.ALLOW_DEV_POSEIDON_HASHER === 'true';
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

  const denomination = hre.ethers.parseEther('0.1');
  const baseRelayerFee = hre.ethers.parseEther('0.001');
  const protocolFeeBps = 50;
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
    chainId: Number((await hre.ethers.provider.getNetwork()).chainId),
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
    protocolFeeBps
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
