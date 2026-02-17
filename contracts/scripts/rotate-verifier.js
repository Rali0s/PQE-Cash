const hre = require('hardhat');

async function main() {
  const adapterAddress = process.env.ADAPTER_ADDRESS;
  const newVerifier = process.env.NEW_VERIFIER_ADDRESS;
  const expectedOld = process.env.EXPECTED_OLD_VERIFIER || '';

  if (!adapterAddress || !newVerifier) {
    throw new Error('Set ADAPTER_ADDRESS and NEW_VERIFIER_ADDRESS');
  }

  const [signer] = await hre.ethers.getSigners();
  const adapter = await hre.ethers.getContractAt('PqVerifierAdapter', adapterAddress, signer);

  const oldVerifier = await adapter.externalVerifier();
  if (expectedOld && oldVerifier.toLowerCase() !== expectedOld.toLowerCase()) {
    throw new Error(`Old verifier mismatch. onchain=${oldVerifier} expected=${expectedOld}`);
  }

  if (oldVerifier.toLowerCase() === newVerifier.toLowerCase()) {
    throw new Error('New verifier equals current verifier');
  }

  console.log('Rotating verifier', { adapterAddress, oldVerifier, newVerifier, signer: signer.address });

  const tx = await adapter.setExternalVerifier(newVerifier);
  const receipt = await tx.wait();

  const eventSig = adapter.interface.getEvent('ExternalVerifierUpdated').topicHash;
  const matched = receipt.logs
    .filter((log) => log.address.toLowerCase() === adapterAddress.toLowerCase() && log.topics[0] === eventSig)
    .map((log) => adapter.interface.parseLog(log));

  if (matched.length !== 1) {
    throw new Error(`Expected exactly 1 ExternalVerifierUpdated event, found ${matched.length}`);
  }

  const ev = matched[0].args;
  if (ev.previousVerifier.toLowerCase() !== oldVerifier.toLowerCase()) {
    throw new Error(`Event previousVerifier mismatch: ${ev.previousVerifier} != ${oldVerifier}`);
  }
  if (ev.newVerifier.toLowerCase() !== newVerifier.toLowerCase()) {
    throw new Error(`Event newVerifier mismatch: ${ev.newVerifier} != ${newVerifier}`);
  }

  const onchain = await adapter.externalVerifier();
  if (onchain.toLowerCase() !== newVerifier.toLowerCase()) {
    throw new Error(`Post-check failed. externalVerifier=${onchain}`);
  }

  console.log('Rotation successful', {
    txHash: tx.hash,
    blockNumber: receipt.blockNumber,
    externalVerifier: onchain
  });
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
