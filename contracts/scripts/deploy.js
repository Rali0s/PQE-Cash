const hre = require('hardhat');
const fs = require('fs');
const path = require('path');

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log('Deployer:', deployer.address);

  const externalVerifier = await hre.ethers.deployContract('DevExternalPqVerifier');
  await externalVerifier.waitForDeployment();

  const verifierAdapter = await hre.ethers.deployContract('PqVerifierAdapter', [await externalVerifier.getAddress()]);
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
    externalVerifier: await externalVerifier.getAddress(),
    verifierAdapter: await verifierAdapter.getAddress(),
    treasury: await treasury.getAddress(),
    privacyPool: await pool.getAddress(),
    denomination: denomination.toString(),
    baseRelayerFee: baseRelayerFee.toString(),
    protocolFeeBps
  };

  console.log('DevExternalPqVerifier:', out.externalVerifier);
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
