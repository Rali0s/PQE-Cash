const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('PqVerifierAdapter security', function () {
  it('enforces onlyOwner for verifier rotation and backend mode changes', async function () {
    const [owner, outsider] = await ethers.getSigners();
    const bytesVerifier = await ethers.deployContract('DevExternalPqVerifier');
    await bytesVerifier.waitForDeployment();
    const uintVerifier = await ethers.deployContract('DevExternalPqVerifierUint');
    await uintVerifier.waitForDeployment();

    const adapter = await ethers.deployContract('PqVerifierAdapter', [await bytesVerifier.getAddress(), 0]);
    await adapter.waitForDeployment();

    await expect(adapter.connect(outsider).setExternalVerifier(await uintVerifier.getAddress())).to.be.revertedWithCustomError(
      adapter,
      'OwnableUnauthorizedAccount'
    );
    await expect(adapter.connect(outsider).setBackendType(1)).to.be.revertedWithCustomError(
      adapter,
      'OwnableUnauthorizedAccount'
    );

    await expect(adapter.connect(owner).setExternalVerifier(ethers.ZeroAddress)).to.be.revertedWith('externalVerifier=0');
  });

  it('verifies correctly in bytes backend mode', async function () {
    const bytesVerifier = await ethers.deployContract('DevExternalPqVerifier');
    await bytesVerifier.waitForDeployment();
    const adapter = await ethers.deployContract('PqVerifierAdapter', [await bytesVerifier.getAddress(), 0]);
    await adapter.waitForDeployment();

    const goodInput = [1n, 2n, 3n, 4n, 5n, 6n, 7n];
    expect(await adapter.verifyProof('0x1234', goodInput)).to.equal(true);
    expect(await adapter.verifyProof('0x', goodInput)).to.equal(false);
  });

  it('supports uint backend mode and fails closed on interface mismatch', async function () {
    const bytesVerifier = await ethers.deployContract('DevExternalPqVerifier');
    await bytesVerifier.waitForDeployment();
    const uintVerifier = await ethers.deployContract('DevExternalPqVerifierUint');
    await uintVerifier.waitForDeployment();

    const adapter = await ethers.deployContract('PqVerifierAdapter', [await bytesVerifier.getAddress(), 0]);
    await adapter.waitForDeployment();

    const goodInput = [11n, 12n, 13n, 14n, 15n, 16n, 17n];

    await adapter.setExternalVerifier(await uintVerifier.getAddress());
    await adapter.setBackendType(1);
    expect(await adapter.verifyProof('0x1234', goodInput)).to.equal(true);

    await adapter.setExternalVerifier(await bytesVerifier.getAddress());
    expect(await adapter.verifyProof('0x1234', goodInput)).to.equal(false);
  });
});
