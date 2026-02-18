import 'dotenv/config';
import { ethers } from 'ethers';

function env(name, fallback = '') {
  return process.env[name] ?? fallback;
}

function envBool(name, fallback = false) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

async function main() {
  const rpcUrl = env('RPC_URL');
  const privateKey = env('RELAYER_PRIVATE_KEY');
  const payoutAddress = env('RELAYER_PAYOUT_ADDRESS');
  const reserveWei = BigInt(env('RELAYER_SWEEP_RESERVE_WEI', '10000000000000000')); // 0.01 ETH
  const minSweepWei = BigInt(env('RELAYER_MIN_SWEEP_WEI', '5000000000000000')); // 0.005 ETH
  const dryRun = envBool('RELAYER_SWEEP_DRY_RUN', false);

  if (!rpcUrl) throw new Error('RPC_URL is required');
  if (!privateKey) throw new Error('RELAYER_PRIVATE_KEY is required');
  if (!ethers.isAddress(payoutAddress)) throw new Error('RELAYER_PAYOUT_ADDRESS must be a valid address');

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);
  const chain = await provider.getNetwork();
  const balance = await provider.getBalance(wallet.address);

  let amount = 0n;
  if (balance > reserveWei) {
    amount = balance - reserveWei;
  }

  console.log(`chainId=${Number(chain.chainId)}`);
  console.log(`relayer=${wallet.address}`);
  console.log(`payout=${payoutAddress}`);
  console.log(`balanceWei=${balance}`);
  console.log(`reserveWei=${reserveWei}`);
  console.log(`candidateSweepWei=${amount}`);

  if (amount < minSweepWei) {
    console.log(`skip: candidate amount below RELAYER_MIN_SWEEP_WEI (${minSweepWei})`);
    return;
  }

  if (dryRun) {
    console.log('dry-run: not broadcasting transaction');
    return;
  }

  const tx = await wallet.sendTransaction({
    to: payoutAddress,
    value: amount
  });
  console.log(`broadcast tx=${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`confirmed block=${receipt.blockNumber}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
