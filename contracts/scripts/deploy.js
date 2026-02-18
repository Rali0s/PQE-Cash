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

  let externalVerifierAddress;
  let externalVerifierDeployed = false;

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

  const denomination = hre.ethers.parseEther('0.1');
  const baseRelayerFee = hre.ethers.parseEther('0.001');
  const protocolFeeBps = 50;
  const pool = await hre.ethers.deployContract('PrivacyPool', [
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
    verifierAdapter: await verifierAdapter.getAddress(),
    treasury: await treasury.getAddress(),
    privacyPool: await pool.getAddress(),
    denomination: denomination.toString(),
    baseRelayerFee: baseRelayerFee.toString(),
    protocolFeeBps
  };

  console.log('ExternalVerifier:', out.externalVerifier, `(backend=${backendName}, deployed=${externalVerifierDeployed})`);
  console.log('PqVerifierAdapter:', out.verifierAdapter);
  console.log('PrivacyPool:', out.privacyPool);
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
