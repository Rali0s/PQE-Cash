import axios from 'axios';
import https from 'node:https';
import fs from 'node:fs';
import { ethers } from 'ethers';

export function createHttpsAgentFromEnv(prefix) {
  const certPath = process.env[`${prefix}_TLS_CERT_PATH`];
  const keyPath = process.env[`${prefix}_TLS_KEY_PATH`];
  const caPath = process.env[`${prefix}_TLS_CA_PATH`];

  if (!certPath && !keyPath && !caPath) {
    return null;
  }

  return new https.Agent({
    cert: certPath ? fs.readFileSync(certPath) : undefined,
    key: keyPath ? fs.readFileSync(keyPath) : undefined,
    ca: caPath ? fs.readFileSync(caPath) : undefined,
    rejectUnauthorized: true
  });
}

class LocalSigner {
  constructor(privateKey, provider) {
    this.wallet = new ethers.Wallet(privateKey, provider);
  }

  async getAddress() {
    return this.wallet.address;
  }

  async signDigest(digestHex) {
    return this.wallet.signMessage(ethers.getBytes(digestHex));
  }

  async sendWithdrawTx({ poolContract, args }) {
    const tx = await poolContract.connect(this.wallet).withdraw(...args);
    return tx;
  }
}

class RemoteSigner {
  constructor({ url, address, apiKey, httpsAgent, provider, poolAbi }) {
    this.address = address;
    this.provider = provider;
    this.poolInterface = new ethers.Interface(poolAbi);
    this.client = axios.create({
      baseURL: url,
      timeout: 12_000,
      httpsAgent,
      headers: apiKey ? { 'x-api-key': apiKey } : undefined
    });
  }

  async getAddress() {
    return this.address;
  }

  async signDigest(digestHex) {
    const { data } = await this.client.post('/v1/sign-message', { digestHex });
    return data.signature;
  }

  async sendWithdrawTx({ args, poolAddress }) {
    const from = this.address;
    const data = this.poolInterface.encodeFunctionData('withdraw', args);
    const network = await this.provider.getNetwork();
    const nonce = await this.provider.getTransactionCount(from, 'pending');
    const feeData = await this.provider.getFeeData();
    const gasLimit = await this.provider.estimateGas({ from, to: poolAddress, data });

    const txRequest = {
      chainId: Number(network.chainId),
      nonce,
      to: poolAddress,
      value: '0x0',
      data,
      gasLimit: gasLimit.toString()
    };

    if (feeData.maxFeePerGas != null && feeData.maxPriorityFeePerGas != null) {
      txRequest.type = 2;
      txRequest.maxFeePerGas = feeData.maxFeePerGas.toString();
      txRequest.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas.toString();
    } else if (feeData.gasPrice != null) {
      txRequest.gasPrice = feeData.gasPrice.toString();
    }

    const { data: signed } = await this.client.post('/v1/sign-transaction', { transaction: txRequest });
    if (!signed?.signedTransaction) {
      throw new Error('remote signer did not return signedTransaction');
    }

    return this.provider.broadcastTransaction(signed.signedTransaction);
  }
}

export function createSigner({ provider, poolAbi }) {
  const mode = (process.env.SIGNER_MODE || 'local').toLowerCase();

  if (mode === 'remote') {
    const url = process.env.SIGNER_SERVICE_URL;
    const address = process.env.SIGNER_ADDRESS;
    if (!url || !address) {
      throw new Error('SIGNER_MODE=remote requires SIGNER_SERVICE_URL and SIGNER_ADDRESS');
    }
    return new RemoteSigner({
      url,
      address,
      apiKey: process.env.SIGNER_SERVICE_API_KEY,
      httpsAgent: createHttpsAgentFromEnv('SIGNER'),
      provider,
      poolAbi
    });
  }

  const privateKey = process.env.RELAYER_PRIVATE_KEY;
  if (!privateKey) {
    throw new Error('SIGNER_MODE=local requires RELAYER_PRIVATE_KEY');
  }
  return new LocalSigner(privateKey, provider);
}
