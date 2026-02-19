const { expect } = require('chai');
const { ethers } = require('hardhat');
const { anyValue } = require('@nomicfoundation/hardhat-chai-matchers/withArgs');

const POOL_VARIANTS = ['PrivacyPool', 'PrivacyPoolV2'];
const SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function deployFixture(variant) {
  const [owner, user, recipient, relayer, newOwner] = await ethers.getSigners();

  const externalVerifier = await ethers.deployContract('DevExternalPqVerifier');
  await externalVerifier.waitForDeployment();
  const adapter = await ethers.deployContract('PqVerifierAdapter', [await externalVerifier.getAddress(), 0]);
  await adapter.waitForDeployment();

  const treasury = await ethers.deployContract('ProtocolTreasury', [3600n]);
  await treasury.waitForDeployment();

  const denom = ethers.parseEther('0.1');
  const baseRelayerFee = ethers.parseEther('0.001');
  const protocolFeeBps = 50n;

  let pool;
  if (variant === 'PrivacyPoolV2') {
    const hasher = await ethers.deployContract('PoseidonHasherMock');
    await hasher.waitForDeployment();
    pool = await ethers.deployContract('PrivacyPoolV2', [
      await adapter.getAddress(),
      await hasher.getAddress(),
      denom,
      baseRelayerFee,
      protocolFeeBps,
      await treasury.getAddress()
    ]);
  } else {
    pool = await ethers.deployContract('PrivacyPool', [
      await adapter.getAddress(),
      denom,
      baseRelayerFee,
      protocolFeeBps,
      await treasury.getAddress()
    ]);
  }
  await pool.waitForDeployment();

  return {
    owner,
    user,
    recipient,
    relayer,
    newOwner,
    pool,
    adapter,
    treasury,
    denom,
    baseRelayerFee,
    protocolFeeBps
  };
}

describe('Checklist expanded coverage', function () {
  describe('Input aliasing guard (field bounds)', function () {
    it('rejects out-of-field public inputs in bytes backend mode', async function () {
      const boundedVerifier = await ethers.deployContract('FieldBoundedExternalVerifier');
      await boundedVerifier.waitForDeployment();
      const adapter = await ethers.deployContract('PqVerifierAdapter', [await boundedVerifier.getAddress(), 0]);
      await adapter.waitForDeployment();

      const good = [1n, 2n, 3n, 4n, 5n, 6n, 7n];
      const bad = [1n, 2n, SNARK_SCALAR_FIELD, 4n, 5n, 6n, 7n];

      expect(await adapter.verifyProof('0x1234', good)).to.equal(true);
      expect(await adapter.verifyProof('0x1234', bad)).to.equal(false);
    });

    it('rejects out-of-field public inputs in uint backend mode', async function () {
      const boundedVerifier = await ethers.deployContract('FieldBoundedExternalVerifier');
      await boundedVerifier.waitForDeployment();
      const adapter = await ethers.deployContract('PqVerifierAdapter', [await boundedVerifier.getAddress(), 1]);
      await adapter.waitForDeployment();

      const good = [11n, 12n, 13n, 14n, 15n, 16n, 17n];
      const bad = [11n, 12n, 13n, 14n, 15n, SNARK_SCALAR_FIELD + 1n, 17n];

      expect(await adapter.verifyProof('0x1234', good)).to.equal(true);
      expect(await adapter.verifyProof('0x1234', bad)).to.equal(false);
    });
  });

  for (const variant of POOL_VARIANTS) {
    describe(`${variant} governance + events + invariants`, function () {
      it('supports safe owner rotation for pool/adapter/treasury', async function () {
        const { owner, newOwner, pool, adapter, treasury } = await deployFixture(variant);

        await expect(pool.connect(owner).transferOwnership(newOwner.address))
          .to.emit(pool, 'OwnershipTransferred')
          .withArgs(owner.address, newOwner.address);
        await expect(adapter.connect(owner).transferOwnership(newOwner.address))
          .to.emit(adapter, 'OwnershipTransferred')
          .withArgs(owner.address, newOwner.address);
        await expect(treasury.connect(owner).transferOwnership(newOwner.address))
          .to.emit(treasury, 'OwnershipTransferred')
          .withArgs(owner.address, newOwner.address);

        await expect(pool.connect(owner).setRelayerOnly(false)).to.be.revertedWithCustomError(
          pool,
          'OwnableUnauthorizedAccount'
        );
        await expect(adapter.connect(owner).setBackendType(1)).to.be.revertedWithCustomError(
          adapter,
          'OwnableUnauthorizedAccount'
        );
        await expect(treasury.connect(owner).setWithdrawDelay(1n)).to.be.revertedWithCustomError(
          treasury,
          'OwnableUnauthorizedAccount'
        );

        await expect(pool.connect(newOwner).setRelayerOnly(false)).to.emit(pool, 'RelayerOnlyUpdated');
        await expect(adapter.connect(newOwner).setBackendType(1)).to.emit(adapter, 'BackendTypeUpdated');
        await expect(treasury.connect(newOwner).setWithdrawDelay(120n)).to.emit(treasury, 'WithdrawDelayUpdated');
      });

      it('emits admin events for mutating controls', async function () {
        const { owner, relayer, newOwner, pool, adapter, treasury } = await deployFixture(variant);
        const oldBaseFee = await pool.baseRelayerFee();
        const oldBps = await pool.protocolFeeBps();
        const oldTreasury = await pool.treasury();
        const oldDelay = await treasury.withdrawDelay();

        await expect(pool.connect(owner).setBaseRelayerFee(oldBaseFee + 1n))
          .to.emit(pool, 'BaseRelayerFeeUpdated')
          .withArgs(oldBaseFee, oldBaseFee + 1n);
        await expect(pool.connect(owner).setProtocolFeeBps(oldBps + 1n))
          .to.emit(pool, 'ProtocolFeeBpsUpdated')
          .withArgs(oldBps, oldBps + 1n);
        await expect(pool.connect(owner).setTreasury(newOwner.address))
          .to.emit(pool, 'TreasuryUpdated')
          .withArgs(oldTreasury, newOwner.address);
        await expect(pool.connect(owner).setRelayerOnly(false))
          .to.emit(pool, 'RelayerOnlyUpdated')
          .withArgs(true, false);
        await expect(pool.connect(owner).setApprovedRelayersOnly(true))
          .to.emit(pool, 'ApprovedRelayersOnlyUpdated')
          .withArgs(false, true);
        await expect(pool.connect(owner).setRelayerApproval(relayer.address, true))
          .to.emit(pool, 'RelayerApprovalUpdated')
          .withArgs(relayer.address, true);

        const boundedVerifier = await ethers.deployContract('FieldBoundedExternalVerifier');
        await boundedVerifier.waitForDeployment();

        await expect(adapter.connect(owner).setExternalVerifier(await boundedVerifier.getAddress()))
          .to.emit(adapter, 'ExternalVerifierUpdated')
          .withArgs(await adapter.externalVerifier(), await boundedVerifier.getAddress());
        await expect(adapter.connect(owner).setBackendType(1))
          .to.emit(adapter, 'BackendTypeUpdated')
          .withArgs(0, 1);

        await expect(treasury.connect(owner).setWithdrawDelay(oldDelay + 1n))
          .to.emit(treasury, 'WithdrawDelayUpdated')
          .withArgs(oldDelay, oldDelay + 1n);
        await expect(treasury.connect(owner).queueWithdrawal(owner.address, 1n))
          .to.emit(treasury, 'WithdrawalQueued')
          .withArgs(0n, owner.address, 1n, anyValue);
      });

      it('maintains value conservation for successful withdraws (invariant-style)', async function () {
        const { user, recipient, relayer, pool, denom, baseRelayerFee, protocolFeeBps } = await deployFixture(variant);
        const protocolFee = (denom * protocolFeeBps) / 10_000n;
        const maxFee = denom - protocolFee;
        const poolAddress = await pool.getAddress();

        for (let i = 0; i < 8; i++) {
          const commitment = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-inv-commitment-${i}`));
          const nullifier = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-inv-nullifier-${i}`));

          await pool.connect(user).deposit(commitment, { value: denom });
          const root = await pool.currentRoot();

          const range = maxFee - baseRelayerFee + 1n;
          const fee = baseRelayerFee + (BigInt((i + 1) * 7919) % range);

          const before = await ethers.provider.getBalance(poolAddress);
          await expect(
            pool
              .connect(relayer)
              .withdraw('0x1234', root, nullifier, recipient.address, relayer.address, fee, 0)
          ).to.emit(pool, 'Withdrawal');
          const after = await ethers.provider.getBalance(poolAddress);

          expect(before - after).to.equal(denom);
          expect(await pool.nullifierSpent(nullifier)).to.equal(true);
        }
      });

      it('rotates root history and evicts stale roots', async function () {
        const { user, pool, denom } = await deployFixture(variant);
        const initialRoot = await pool.currentRoot();
        expect(await pool.isKnownRoot(initialRoot)).to.equal(true);

        for (let i = 0; i < 101; i++) {
          const commitment = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-root-rotate-${i}`));
          await pool.connect(user).deposit(commitment, { value: denom });
        }

        expect(await pool.isKnownRoot(await pool.currentRoot())).to.equal(true);
        expect(await pool.isKnownRoot(initialRoot)).to.equal(false);
      });
    });
  }
});
