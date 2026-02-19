const hre = require('hardhat');

function parseBool(name, fallback) {
  const value = process.env[name];
  if (value == null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on', 'y'].includes(String(value).toLowerCase());
}

async function main() {
  const network = hre.network.name;
  const chain = await hre.ethers.provider.getNetwork();
  const chainId = Number(chain.chainId);
  const signers = await hre.ethers.getSigners();
  if (!signers || signers.length === 0) {
    throw new Error('No deployer signer found');
  }
  const deployer = signers[0];

  const deployExternalVerifier = parseBool('DEPLOY_EXTERNAL_VERIFIER', true);
  const deployPoseidonHasher = parseBool('DEPLOY_POSEIDON_HASHER', true);

  if (!deployExternalVerifier && !deployPoseidonHasher) {
    throw new Error('Nothing to deploy. Set DEPLOY_EXTERNAL_VERIFIER and/or DEPLOY_POSEIDON_HASHER to true');
  }

  console.log(`Network: ${network} (chainId=${chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  const out = { network, chainId, deployer: deployer.address };

  if (deployExternalVerifier) {
    // NOTE: DevExternalPqVerifier is a placeholder verifier for integration testing.
    const verifier = await hre.ethers.deployContract('DevExternalPqVerifier');
    await verifier.waitForDeployment();
    out.externalVerifier = await verifier.getAddress();
    console.log(`DevExternalPqVerifier: ${out.externalVerifier}`);
  }

  if (deployPoseidonHasher) {
    // NOTE: PoseidonHasherMock is a placeholder hasher and not production-cryptographic Poseidon.
    const hasher = await hre.ethers.deployContract('PoseidonHasherMock');
    await hasher.waitForDeployment();
    out.poseidonHasher = await hasher.getAddress();
    console.log(`PoseidonHasherMock: ${out.poseidonHasher}`);
  }

  console.log('\nCopy into .env:');
  if (out.externalVerifier) {
    console.log(`EXTERNAL_VERIFIER_ADDRESS=${out.externalVerifier}`);
    console.log('EXTERNAL_VERIFIER_BACKEND=bytes');
  }
  if (out.poseidonHasher) {
    console.log(`POSEIDON_HASHER_ADDRESS=${out.poseidonHasher}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
