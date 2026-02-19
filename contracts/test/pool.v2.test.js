const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('PrivacyPoolV2', function () {
  it('deposits and withdraws with relayer fee using pluggable hasher', async function () {
    const [owner, user, recipient, relayer] = await ethers.getSigners();

    const externalVerifier = await ethers.deployContract('DevExternalPqVerifier');
    await externalVerifier.waitForDeployment();
    const adapter = await ethers.deployContract('PqVerifierAdapter', [await externalVerifier.getAddress(), 0]);
    await adapter.waitForDeployment();
    const hasher = await ethers.deployContract('PoseidonHasherMock');
    await hasher.waitForDeployment();

    const denom = ethers.parseEther('0.1');
    const baseRelayerFee = ethers.parseEther('0.001');
    const protocolFeeBps = 50n;
    const treasury = await ethers.deployContract('ProtocolTreasury', [3600n]);
    await treasury.waitForDeployment();

    const pool = await ethers.deployContract('PrivacyPoolV2', [
      await adapter.getAddress(),
      await hasher.getAddress(),
      denom,
      baseRelayerFee,
      protocolFeeBps,
      await treasury.getAddress()
    ]);
    await pool.waitForDeployment();

    const commitment = ethers.keccak256(ethers.toUtf8Bytes('v2-commitment-1'));
    await expect(pool.connect(user).deposit(commitment, { value: denom })).to.emit(pool, 'Deposit');

    const root = await pool.currentRoot();
    const siblings = [];
    for (let i = 0; i < 20; i += 1) {
      siblings.push(await pool.zeros(i));
    }
    expect(await pool.computeRootFromPath(commitment, siblings, 0)).to.equal(root);
    expect(await pool.verifyMerklePath(commitment, siblings, 0, root)).to.equal(true);

    const nullifier = ethers.keccak256(ethers.toUtf8Bytes('v2-nullifier-1'));
    const fee = ethers.parseEther('0.01');
    const protocolFee = (denom * protocolFeeBps) / 10000n;

    const balBefore = await ethers.provider.getBalance(recipient.address);

    await expect(
      pool
        .connect(relayer)
        .withdraw('0x1234', root, nullifier, recipient.address, relayer.address, fee, 0)
    ).to.emit(pool, 'Withdrawal');

    const balAfter = await ethers.provider.getBalance(recipient.address);
    expect(balAfter - balBefore).to.equal(denom - fee - protocolFee);
    expect(await ethers.provider.getBalance(await treasury.getAddress())).to.equal(protocolFee);

    const queueTx = await treasury.connect(owner).queueWithdrawal(owner.address, protocolFee);
    const queueRcpt = await queueTx.wait();
    const queued = queueRcpt.logs
      .map((log) => {
        try {
          return treasury.interface.parseLog(log);
        } catch (_e) {
          return null;
        }
      })
      .filter(Boolean)
      .find((ev) => ev.name === 'WithdrawalQueued');
    const requestId = queued.args.requestId;

    await ethers.provider.send('evm_increaseTime', [3601]);
    await ethers.provider.send('evm_mine', []);

    const ownerBalBefore = await ethers.provider.getBalance(owner.address);
    const execTx = await treasury.connect(owner).executeWithdrawal(requestId);
    const execRcpt = await execTx.wait();
    const gas = execRcpt.gasUsed * execRcpt.gasPrice;
    const ownerBalAfter = await ethers.provider.getBalance(owner.address);
    expect(ownerBalAfter).to.equal(ownerBalBefore + protocolFee - gas);
    expect(await ethers.provider.getBalance(await treasury.getAddress())).to.equal(0n);
  });
});
