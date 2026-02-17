import 'dotenv/config';
import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import { ethers } from 'ethers';
import { z } from 'zod';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.PORT || 8080);
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8545';
const MIN_FEE_BPS = Number(process.env.MIN_FEE_BPS || 50);
const MAX_FEE_BPS = Number(process.env.MAX_FEE_BPS || 300);
const ANON_LOGGING = (process.env.ANON_LOGGING || 'true') === 'true';

const provider = new ethers.JsonRpcProvider(RPC_URL);
const wallet = process.env.RELAYER_PRIVATE_KEY ? new ethers.Wallet(process.env.RELAYER_PRIVATE_KEY, provider) : null;

const poolAbi = [
  'function denomination() view returns (uint256)',
  'function withdraw(bytes proof, bytes32 root, bytes32 nullifierHash, address recipient, address relayer, uint256 fee, uint256 refund)'
];

const jobs = new Map();
const quotes = new Map();
const sessions = new Map();

const serverECDH = crypto.createECDH('prime256v1');
serverECDH.generateKeys();
const serverKeyId = crypto.randomUUID();

const b64 = z.string().min(1).regex(/^[A-Za-z0-9+/=]+$/);

const quoteSchema = z.object({
  pool: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  feeBps: z.number().int().min(MIN_FEE_BPS).max(MAX_FEE_BPS).optional()
});

const quotePayloadSchema = z.object({
  quoteId: z.string().uuid(),
  pool: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  feeBps: z.number().int().min(0),
  fee: z.string().regex(/^[0-9]+$/),
  chainId: z.number().int().positive(),
  expiresAt: z.number().int().positive()
});

const handshakeOpenSchema = z.object({
  clientEcdhPublicKey: b64,
  pqSharedSecret: b64.optional()
});

const submitEnvelopeSchema = z.object({
  sessionId: z.string(),
  envelope: z.object({
    iv: b64,
    ciphertext: b64,
    tag: b64,
    aad: z.string().optional()
  })
});

const submitPayloadSchema = z.object({
  nonce: z.string().uuid(),
  expiresAt: z.number().int().positive(),
  quote: quotePayloadSchema,
  quoteSignature: z.string().regex(/^0x[a-fA-F0-9]+$/),
  pool: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  proof: z.string().startsWith('0x'),
  root: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
  nullifierHash: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
  recipient: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  refund: z.string().regex(/^[0-9]+$/).default('0')
});

function anonLog(message, data = {}) {
  if (!ANON_LOGGING) {
    console.log(message, data);
    return;
  }
  const redacted = Object.fromEntries(Object.entries(data).map(([k]) => [k, '<redacted>']));
  console.log(message, redacted);
}

function quoteDigest(quote) {
  return ethers.solidityPackedKeccak256(
    ['string', 'string', 'address', 'uint256', 'uint256', 'uint256', 'uint256'],
    ['BLUEARC_QUOTE_V1', quote.quoteId, quote.pool, BigInt(quote.feeBps), BigInt(quote.fee), BigInt(quote.chainId), BigInt(quote.expiresAt)]
  );
}

function decryptEnvelope(sessionKeyHex, envelope, sessionId) {
  const key = Buffer.from(sessionKeyHex, 'hex');
  if (key.length !== 32) {
    throw new Error('session key length invalid');
  }

  const iv = Buffer.from(envelope.iv, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const aad = Buffer.from(envelope.aad || sessionId, 'utf8');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, hasSigner: !!wallet, minFeeBps: MIN_FEE_BPS, maxFeeBps: MAX_FEE_BPS });
});

app.get('/handshake/server-key', (_req, res) => {
  res.json({
    keyId: serverKeyId,
    curve: 'prime256v1',
    serverEcdhPublicKey: serverECDH.getPublicKey('base64')
  });
});

app.post('/handshake/open', (req, res) => {
  const parsed = handshakeOpenSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid handshake payload' });
  }

  try {
    const { clientEcdhPublicKey, pqSharedSecret } = parsed.data;
    const clientPub = Buffer.from(clientEcdhPublicKey, 'base64');
    const classicalSecret = serverECDH.computeSecret(clientPub);
    const pqPart = pqSharedSecret ? Buffer.from(pqSharedSecret, 'base64') : Buffer.alloc(0);

    const sessionKey = crypto
      .createHash('sha256')
      .update(Buffer.concat([classicalSecret, pqPart]))
      .digest('hex');

    const sessionId = crypto.randomUUID();
    const createdAt = Date.now();
    const expiresAt = createdAt + 600_000;
    sessions.set(sessionId, { sessionKey, createdAt, expiresAt, usedNonces: new Set() });

    return res.json({
      sessionId,
      expiresInSec: 600,
      keySchedule: 'sha256(classical_ecdh || pq_secret)',
      submitMode: 'encrypted-envelope-v1'
    });
  } catch (_e) {
    return res.status(400).json({ error: 'handshake failed' });
  }
});

app.post('/quote', async (req, res) => {
  if (!wallet) {
    return res.status(500).json({ error: 'relayer signer not configured' });
  }

  const parsed = quoteSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  try {
    const { pool } = parsed.data;
    const feeBps = parsed.data.feeBps ?? MIN_FEE_BPS;

    const poolContract = new ethers.Contract(pool, poolAbi, provider);
    const denomination = await poolContract.denomination();
    const fee = (denomination * BigInt(feeBps)) / 10000n;

    const quoteId = crypto.randomUUID();
    const now = Date.now();
    const ttlMs = 120_000;
    const chainId = Number((await provider.getNetwork()).chainId);
    const quote = {
      quoteId,
      pool,
      feeBps,
      fee: fee.toString(),
      chainId,
      expiresAt: now + ttlMs
    };

    const digest = quoteDigest(quote);
    const signature = await wallet.signMessage(ethers.getBytes(digest));

    quotes.set(quoteId, { ...quote, signature, createdAt: now });

    return res.json({ quote, quoteSignature: signature, ttlSec: ttlMs / 1000, signer: wallet.address });
  } catch (e) {
    return res.status(500).json({ error: `quote failed: ${e.message}` });
  }
});

app.post('/submit', async (req, res) => {
  if (!wallet) {
    return res.status(500).json({ error: 'relayer signer not configured' });
  }

  const parsedEnvelope = submitEnvelopeSchema.safeParse(req.body);
  if (!parsedEnvelope.success) {
    return res.status(400).json({ error: parsedEnvelope.error.flatten() });
  }

  const { sessionId, envelope } = parsedEnvelope.data;
  const session = sessions.get(sessionId);
  if (!session) {
    return res.status(401).json({ error: 'invalid session' });
  }
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return res.status(401).json({ error: 'session expired' });
  }

  let data;
  try {
    const decryptedPayload = decryptEnvelope(session.sessionKey, envelope, sessionId);
    const parsedPayload = submitPayloadSchema.safeParse(decryptedPayload);
    if (!parsedPayload.success) {
      return res.status(400).json({ error: parsedPayload.error.flatten() });
    }
    data = parsedPayload.data;
  } catch (_e) {
    return res.status(400).json({ error: 'decrypt/parse failed' });
  }

  if (Date.now() > data.expiresAt || data.expiresAt > session.expiresAt) {
    return res.status(400).json({ error: 'payload expired' });
  }
  if (session.usedNonces.has(data.nonce)) {
    return res.status(409).json({ error: 'replay detected' });
  }
  session.usedNonces.add(data.nonce);

  if (data.pool.toLowerCase() !== data.quote.pool.toLowerCase()) {
    return res.status(400).json({ error: 'quote/pool mismatch' });
  }

  const quote = quotes.get(data.quote.quoteId);
  if (!quote || quote.pool.toLowerCase() !== data.pool.toLowerCase()) {
    return res.status(400).json({ error: 'invalid quote' });
  }
  if (Date.now() > quote.expiresAt) {
    return res.status(400).json({ error: 'quote expired' });
  }
  if (data.quote.expiresAt !== quote.expiresAt || data.quote.fee !== quote.fee || data.quote.feeBps !== quote.feeBps) {
    return res.status(400).json({ error: 'quote tamper detected' });
  }

  const digest = quoteDigest(data.quote);
  const recovered = ethers.verifyMessage(ethers.getBytes(digest), data.quoteSignature);
  if (recovered.toLowerCase() !== wallet.address.toLowerCase()) {
    return res.status(400).json({ error: 'invalid quote signature' });
  }
  if (quote.signature.toLowerCase() !== data.quoteSignature.toLowerCase()) {
    return res.status(400).json({ error: 'signature mismatch' });
  }
  const liveChainId = Number((await provider.getNetwork()).chainId);
  if (data.quote.chainId !== liveChainId) {
    return res.status(400).json({ error: 'quote chain mismatch' });
  }

  const jobId = crypto.randomUUID();
  jobs.set(jobId, { status: 'queued', createdAt: Date.now() });

  anonLog('submit_received', { jobId, pool: data.pool, recipient: data.recipient });

  try {
    jobs.set(jobId, { status: 'broadcasting' });

    const poolContract = new ethers.Contract(data.pool, poolAbi, wallet);
    const tx = await poolContract.withdraw(
      data.proof,
      data.root,
      data.nullifierHash,
      data.recipient,
      wallet.address,
      BigInt(data.quote.fee),
      BigInt(data.refund)
    );

    jobs.set(jobId, { status: 'pending', txHash: tx.hash });
    const receipt = await tx.wait();

    jobs.set(jobId, {
      status: 'confirmed',
      txHash: tx.hash,
      blockNumber: receipt.blockNumber
    });

    return res.json({ jobId, txHash: tx.hash, status: 'pending' });
  } catch (e) {
    jobs.set(jobId, { status: 'failed', error: e.message });
    return res.status(500).json({ error: e.message, jobId });
  }
});

app.get('/status/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'job not found' });
  }
  return res.json(job);
});

app.listen(PORT, () => {
  console.log(`relayer listening on http://0.0.0.0:${PORT}`);
});
