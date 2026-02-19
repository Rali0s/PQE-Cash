const { expect } = require('chai');
const { ethers } = require('hardhat');

const POOL_VARIANTS = ['PrivacyPool', 'PrivacyPoolV2'];

async function deployPoolFixture(variant) {
  const [owner, user, recipient, relayer, outsider] = await ethers.getSigners();

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
    outsider,
    pool,
    adapter,
    treasury,
    denom,
    baseRelayerFee
  };
}

for (const variant of POOL_VARIANTS) {
  describe(`${variant} security`, function () {
    it('enforces owner-only admin controls', async function () {
      const { pool, outsider, relayer } = await deployPoolFixture(variant);

      await expect(pool.connect(outsider).setBaseRelayerFee(1n)).to.be.revertedWithCustomError(
        pool,
        'OwnableUnauthorizedAccount'
      );
      await expect(pool.connect(outsider).setProtocolFeeBps(10n)).to.be.revertedWithCustomError(
        pool,
        'OwnableUnauthorizedAccount'
      );
      await expect(pool.connect(outsider).setTreasury(relayer.address)).to.be.revertedWithCustomError(
        pool,
        'OwnableUnauthorizedAccount'
      );
      await expect(pool.connect(outsider).setRelayerOnly(false)).to.be.revertedWithCustomError(
        pool,
        'OwnableUnauthorizedAccount'
      );
      await expect(pool.connect(outsider).setApprovedRelayersOnly(true)).to.be.revertedWithCustomError(
        pool,
        'OwnableUnauthorizedAccount'
      );
      await expect(pool.connect(outsider).setRelayerApproval(relayer.address, true)).to.be.revertedWithCustomError(
        pool,
        'OwnableUnauthorizedAccount'
      );
    });

    it('rejects malformed deposits and duplicate commitments', async function () {
      const { pool, user, denom } = await deployPoolFixture(variant);
      const commitment = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-commitment-dup`));

      await expect(pool.connect(user).deposit(commitment, { value: 0n })).to.be.revertedWith('bad amount');
      await expect(pool.connect(user).deposit(commitment, { value: denom })).to.emit(pool, 'Deposit');
      await expect(pool.connect(user).deposit(commitment, { value: denom })).to.be.revertedWith('commitment used');
    });

    it('rejects invalid withdraw preconditions', async function () {
      const { pool, user, recipient, relayer, outsider, denom, baseRelayerFee } = await deployPoolFixture(variant);
      const commitment = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-commitment-preconditions`));
      await pool.connect(user).deposit(commitment, { value: denom });
      const root = await pool.currentRoot();

      const nullifier = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-nullifier-preconditions`));
      const fee = baseRelayerFee;

      await expect(
        pool
          .connect(outsider)
          .withdraw('0x1234', root, nullifier, recipient.address, relayer.address, fee, 0)
      ).to.be.revertedWith('sender must be relayer');

      await expect(
        pool
          .connect(relayer)
          .withdraw('0x', root, nullifier, recipient.address, relayer.address, fee, 0)
      ).to.be.revertedWith('invalid proof');

      await expect(
        pool
          .connect(relayer)
          .withdraw('0x1234', ethers.ZeroHash, nullifier, recipient.address, relayer.address, fee, 0)
      ).to.be.revertedWith('unknown root');

      await expect(
        pool
          .connect(relayer)
          .withdraw('0x1234', root, nullifier, recipient.address, relayer.address, baseRelayerFee - 1n, 0)
      ).to.be.revertedWith('fee below base');

      await expect(
        pool
          .connect(relayer)
          .withdraw(
            '0x1234',
            root,
            nullifier,
            recipient.address,
            relayer.address,
            denom,
            0
          )
      ).to.be.revertedWith('fees too high');

      await expect(
        pool
          .connect(relayer)
          .withdraw('0x1234', root, nullifier, ethers.ZeroAddress, relayer.address, fee, 0)
      ).to.be.revertedWith('recipient=0');

      await expect(
        pool
          .connect(relayer)
          .withdraw('0x1234', root, nullifier, recipient.address, ethers.ZeroAddress, fee, 0)
      ).to.be.revertedWith('relayer=0');
    });

    it('enforces approved relayer policy when enabled', async function () {
      const { pool, owner, user, recipient, relayer, denom, baseRelayerFee } = await deployPoolFixture(variant);
      const commitment = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-commitment-approved-relayer`));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-nullifier-approved-relayer`));

      await pool.connect(owner).setApprovedRelayersOnly(true);
      await pool.connect(user).deposit(commitment, { value: denom });

      const root = await pool.currentRoot();
      await expect(
        pool
          .connect(relayer)
          .withdraw('0x1234', root, nullifier, recipient.address, relayer.address, baseRelayerFee, 0)
      ).to.be.revertedWith('relayer not approved');

      await pool.connect(owner).setRelayerApproval(relayer.address, true);
      await expect(
        pool
          .connect(relayer)
          .withdraw('0x1234', root, nullifier, recipient.address, relayer.address, baseRelayerFee, 0)
      ).to.emit(pool, 'Withdrawal');
    });

    it('prevents nullifier replay (double spend)', async function () {
      const { pool, user, recipient, relayer, denom, baseRelayerFee } = await deployPoolFixture(variant);

      const commitmentOne = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-commitment-replay-1`));
      const commitmentTwo = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-commitment-replay-2`));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-nullifier-replay`));

      await pool.connect(user).deposit(commitmentOne, { value: denom });
      await pool.connect(user).deposit(commitmentTwo, { value: denom });

      const root = await pool.currentRoot();
      await expect(
        pool
          .connect(relayer)
          .withdraw('0x1234', root, nullifier, recipient.address, relayer.address, baseRelayerFee, 0)
      ).to.emit(pool, 'Withdrawal');

      await expect(
        pool
          .connect(relayer)
          .withdraw('0x1234', root, nullifier, recipient.address, relayer.address, baseRelayerFee, 0)
      ).to.be.revertedWith('nullifier spent');
    });

    it('blocks reentrancy attempts during recipient payout', async function () {
      const { pool, user, relayer, denom, baseRelayerFee } = await deployPoolFixture(variant);
      const attacker = await ethers.deployContract('ReenterWithdrawRecipient');
      await attacker.waitForDeployment();

      const commitment = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-commitment-reentrancy`));
      await pool.connect(user).deposit(commitment, { value: denom });
      const root = await pool.currentRoot();

      const firstNullifier = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-nullifier-reentrancy-1`));
      const reentryNullifier = ethers.keccak256(ethers.toUtf8Bytes(`${variant}-nullifier-reentrancy-2`));

      await attacker.arm(
        await pool.getAddress(),
        '0x1234',
        root,
        reentryNullifier,
        relayer.address,
        baseRelayerFee,
        0
      );

      await expect(
        pool
          .connect(relayer)
          .withdraw(
            '0x1234',
            root,
            firstNullifier,
            await attacker.getAddress(),
            relayer.address,
            baseRelayerFee,
            0
          )
      ).to.emit(pool, 'Withdrawal');

      expect(await attacker.attempted()).to.equal(true);
      expect(await attacker.reenterSucceeded()).to.equal(false);
      expect(await pool.nullifierSpent(firstNullifier)).to.equal(true);
      expect(await pool.nullifierSpent(reentryNullifier)).to.equal(false);
    });

    it('rejects unexpected direct eth via receive/fallback', async function () {
      const { pool, outsider } = await deployPoolFixture(variant);
      const poolAddress = await pool.getAddress();

      await expect(
        outsider.sendTransaction({
          to: poolAddress,
          value: 1n
        })
      ).to.be.revertedWithCustomError(pool, 'DirectEthDisabled');

      await expect(
        outsider.sendTransaction({
          to: poolAddress,
          value: 1n,
          data: '0x12345678'
        })
      ).to.be.revertedWithCustomError(pool, 'DirectEthDisabled');
    });
  });
}
