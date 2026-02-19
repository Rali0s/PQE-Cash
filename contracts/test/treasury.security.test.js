const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('ProtocolTreasury security', function () {
  it('enforces onlyOwner on admin and withdrawal operations', async function () {
    const [owner, outsider] = await ethers.getSigners();
    const treasury = await ethers.deployContract('ProtocolTreasury', [3600n]);
    await treasury.waitForDeployment();

    await expect(treasury.connect(outsider).setWithdrawDelay(1n)).to.be.revertedWithCustomError(
      treasury,
      'OwnableUnauthorizedAccount'
    );
    await expect(
      treasury.connect(outsider).queueWithdrawal(outsider.address, ethers.parseEther('0.1'))
    ).to.be.revertedWithCustomError(treasury, 'OwnableUnauthorizedAccount');
    await expect(treasury.connect(outsider).executeWithdrawal(0n)).to.be.revertedWithCustomError(
      treasury,
      'OwnableUnauthorizedAccount'
    );

    await expect(treasury.connect(owner).queueWithdrawal(ethers.ZeroAddress, 1n)).to.be.revertedWith('to=0');
    await expect(treasury.connect(owner).queueWithdrawal(owner.address, 0n)).to.be.revertedWith('amount=0');
  });

  it('enforces timelock and prevents double execution', async function () {
    const [owner] = await ethers.getSigners();
    const treasury = await ethers.deployContract('ProtocolTreasury', [60n]);
    await treasury.waitForDeployment();
    const treasuryAddress = await treasury.getAddress();

    await owner.sendTransaction({
      to: treasuryAddress,
      value: ethers.parseEther('0.05')
    });

    const queueTx = await treasury.queueWithdrawal(owner.address, ethers.parseEther('0.01'));
    await queueTx.wait();

    await expect(treasury.executeWithdrawal(0n)).to.be.revertedWith('withdrawal locked');

    await ethers.provider.send('evm_increaseTime', [61]);
    await ethers.provider.send('evm_mine', []);

    await expect(treasury.executeWithdrawal(0n)).to.emit(treasury, 'WithdrawalExecuted');
    await expect(treasury.executeWithdrawal(0n)).to.be.revertedWith('already executed');
  });

  it('checks treasury balance before execution', async function () {
    const [owner] = await ethers.getSigners();
    const treasury = await ethers.deployContract('ProtocolTreasury', [0n]);
    await treasury.waitForDeployment();

    await treasury.queueWithdrawal(owner.address, ethers.parseEther('1'));
    await expect(treasury.executeWithdrawal(0n)).to.be.revertedWith('insufficient balance');
  });

  it('accepts receive() transfers and rejects fallback() calls', async function () {
    const [owner] = await ethers.getSigners();
    const treasury = await ethers.deployContract('ProtocolTreasury', [0n]);
    await treasury.waitForDeployment();
    const treasuryAddress = await treasury.getAddress();

    await expect(
      owner.sendTransaction({
        to: treasuryAddress,
        value: 1n
      })
    ).to.not.be.reverted;

    await expect(
      owner.sendTransaction({
        to: treasuryAddress,
        value: 1n,
        data: '0x12345678'
      })
    ).to.be.revertedWithCustomError(treasury, 'DirectFallbackDisabled');
  });
});
