import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import pino from 'pino';
import pinoHttp from 'pino-http';
import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';
import { ethers } from 'ethers';
import { z } from 'zod';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { DurableStorage } from './storage.js';
import { createSigner } from './signer.js';

const poolAbi = [
  'function denomination() view returns (uint256)',
  'function baseRelayerFee() view returns (uint256)',
  'function withdraw(bytes proof, bytes32 root, bytes32 nullifierHash, address recipient, address relayer, uint256 fee, uint256 refund)'
];

const b64 = z.string().min(1).regex(/^[A-Za-z0-9+/=]+$/);

const quoteSchema = z.object({
  pool: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  feeBps: z.number().int().optional()
});

const quotePayloadSchema = z.object({
  quoteId: z.string().uuid(),
  pool: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  feeBps: z.number().int().min(0),
  fee: z.string().regex(/^[0-9]+$/),
  chainId: z.number().int().positive(),
  expiresAt: z.number().int().positive(),
  issuedAt: z.number().int().positive().optional()
});

const handshakeOpenSchema = z.object({
  keyId: z.string().uuid().optional(),
  clientEcdhPublicKey: b64,
  pqKemCiphertext: b64
});

const submitEnvelopeSchema = z.object({
  sessionId: z.string().uuid(),
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

function envBool(name, fallback = false) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

function envNum(name, fallback) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Invalid number for ${name}`);
  }
  return parsed;
}

const PORT = envNum('PORT', 8080);
const HOST = process.env.HOST || '0.0.0.0';
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8545';
const POSTGRES_URL = process.env.POSTGRES_URL || 'postgres://postgres:postgres@127.0.0.1:5432/bluearc';
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const MIN_FEE_BPS = envNum('MIN_FEE_BPS', 50);
const MAX_FEE_BPS = envNum('MAX_FEE_BPS', 300);
const SESSION_TTL_MS = envNum('SESSION_TTL_MS', 600_000);
const QUOTE_TTL_MS = envNum('QUOTE_TTL_MS', 120_000);
const NONCE_TTL_MS = envNum('NONCE_TTL_MS', 900_000);
const PAYLOAD_MAX_AGE_MS = envNum('PAYLOAD_MAX_AGE_MS', 90_000);
const QUOTE_REPLAY_WINDOW_MS = envNum('QUOTE_REPLAY_WINDOW_MS', 180_000);
const PROOF_MAX_BYTES = envNum('PROOF_MAX_BYTES', 16_384);
const RATE_WINDOW_MS = envNum('RATE_WINDOW_MS', 60_000);
const RATE_LIMIT_HANDSHAKE = envNum('RATE_LIMIT_HANDSHAKE', 60);
const RATE_LIMIT_QUOTE = envNum('RATE_LIMIT_QUOTE', 30);
const RATE_LIMIT_SUBMIT = envNum('RATE_LIMIT_SUBMIT', 20);
const RATE_LIMIT_STATUS = envNum('RATE_LIMIT_STATUS', 120);
const ABUSE_TTL_MS = envNum('ABUSE_TTL_MS', 900_000);
const ABUSE_BLOCK_THRESHOLD = envNum('ABUSE_BLOCK_THRESHOLD', 25);
const SERVER_KEY_ROTATE_MS = envNum('SERVER_KEY_ROTATE_MS', 3_600_000);
const DEPLOY_JSON_PATH = process.env.DEPLOY_JSON_PATH || '';
const DEPLOY_REFRESH_MS = envNum('DEPLOY_REFRESH_MS', 10_000);
const STORAGE_PRUNE_INTERVAL_MS = envNum('STORAGE_PRUNE_INTERVAL_MS', 300_000);
const QUOTE_RETENTION_MS = envNum('QUOTE_RETENTION_MS', 3_600_000);
const JOB_RETENTION_MS = envNum('JOB_RETENTION_MS', 86_400_000);
const ALERT_FAILURE_THRESHOLD = envNum('ALERT_FAILURE_THRESHOLD', 5);
const ALERT_WEBHOOK_URL = process.env.ALERT_WEBHOOK_URL || '';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '';
const TRUST_PROXY = envBool('TRUST_PROXY', false);
const ANON_LOGGING = envBool('ANON_LOGGING', true);
const ENFORCE_SESSION_BINDING = envBool('ENFORCE_SESSION_BINDING', true);
const TLS_REQUIRE_CLIENT_CERT = envBool('TLS_REQUIRE_CLIENT_CERT', false);
const SIGNER_MODE = (process.env.SIGNER_MODE || 'local').toLowerCase();
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const POOL_ALLOWLIST = new Set(
  (process.env.POOL_ALLOWLIST || '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean)
);

if (MIN_FEE_BPS > MAX_FEE_BPS) {
  throw new Error('MIN_FEE_BPS must be <= MAX_FEE_BPS');
}
if (process.env.NODE_ENV === 'production' && SIGNER_MODE !== 'remote') {
  throw new Error('Production requires SIGNER_MODE=remote for KMS/HSM-backed signing');
}

const logger = pino({ level: LOG_LEVEL });
const provider = new ethers.JsonRpcProvider(RPC_URL);
const storage = new DurableStorage({ postgresUrl: POSTGRES_URL, redisUrl: REDIS_URL });
const signer = createSigner({ provider, poolAbi });

const app = express();
if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}

app.use(
  pinoHttp({
    logger,
    genReqId(req, res) {
      const existing = req.headers['x-request-id'];
      const id = typeof existing === 'string' && existing.length > 0 ? existing : crypto.randomUUID();
      res.setHeader('x-request-id', id);
      return id;
    }
  })
);

app.use(helmet());
app.use(
  cors({
    origin: CORS_ORIGIN
      ? CORS_ORIGIN.split(',')
          .map((v) => v.trim())
          .filter(Boolean)
      : true
  })
);
app.use(express.json({ limit: '1mb' }));

const metrics = new Registry();
collectDefaultMetrics({ register: metrics, prefix: 'bluearc_' });

const requestDurationMs = new Histogram({
  name: 'bluearc_http_request_duration_ms',
  help: 'Relayer HTTP request duration in milliseconds',
  registers: [metrics],
  labelNames: ['method', 'route', 'status_code'],
  buckets: [5, 10, 25, 50, 100, 200, 500, 1000, 2000, 5000]
});

const jobTransitionsTotal = new Counter({
  name: 'bluearc_job_transitions_total',
  help: 'Count of relayer job state transitions',
  registers: [metrics],
  labelNames: ['state']
});

const quoteIssuedTotal = new Counter({
  name: 'bluearc_quote_issued_total',
  help: 'Total quotes issued',
  registers: [metrics]
});

const submitAcceptedTotal = new Counter({
  name: 'bluearc_submit_accepted_total',
  help: 'Total accepted submit requests',
  registers: [metrics]
});

const submitRejectedTotal = new Counter({
  name: 'bluearc_submit_rejected_total',
  help: 'Total rejected submit requests',
  registers: [metrics],
  labelNames: ['reason']
});

let signerAddress;
let consecutiveFailureCount = 0;
let keyMaterial = rotateServerKey();
let runtimePoolAddress = null;
let runtimeDeployLoadedAt = 0;

function rotateServerKey() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const kem = ml_kem768.keygen();
  const createdAt = Date.now();
  return {
    keyId: crypto.randomUUID(),
    ecdh,
    kemPublicKey: kem.publicKey,
    kemSecretKey: kem.secretKey,
    createdAt,
    expiresAt: createdAt + SERVER_KEY_ROTATE_MS
  };
}

function getActiveServerKey() {
  if (Date.now() >= keyMaterial.expiresAt) {
    keyMaterial = rotateServerKey();
  }
  return keyMaterial;
}

function loadDeployRuntimeConfig() {
  if (!DEPLOY_JSON_PATH) {
    runtimePoolAddress = null;
    runtimeDeployLoadedAt = Date.now();
    return;
  }

  try {
    if (!fs.existsSync(DEPLOY_JSON_PATH)) {
      runtimePoolAddress = null;
      runtimeDeployLoadedAt = Date.now();
      return;
    }
    const raw = fs.readFileSync(DEPLOY_JSON_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    const candidate = typeof parsed.privacyPool === 'string' ? parsed.privacyPool : '';
    runtimePoolAddress = ethers.isAddress(candidate) ? candidate : null;
    runtimeDeployLoadedAt = Date.now();
  } catch (error) {
    logger.warn({ error: error.message, path: DEPLOY_JSON_PATH }, 'failed to load deploy runtime config');
  }
}

function quoteDigest(quote) {
  return ethers.solidityPackedKeccak256(
    ['string', 'string', 'address', 'uint256', 'uint256', 'uint256', 'uint256'],
    ['BLUEARC_QUOTE_V1', quote.quoteId, quote.pool, BigInt(quote.feeBps), BigInt(quote.fee), BigInt(quote.chainId), BigInt(quote.expiresAt)]
  );
}

function ceilDiv(a, b) {
  return (a + b - 1n) / b;
}

function updateHashLenPrefixed(hash, value) {
  const bytes = Buffer.from(value);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(bytes.length);
  hash.update(len);
  hash.update(bytes);
}

function deriveHybridSessionKeyHex({
  keyId,
  clientEcdhPublicKey,
  serverEcdhPublicKey,
  pqKemCiphertext,
  classicalSecret,
  pqKemSharedSecret
}) {
  const hash = crypto.createHash('sha256');
  hash.update('BLUEARC_HYBRID_MLKEM_V1', 'utf8');
  updateHashLenPrefixed(hash, Buffer.from(keyId, 'utf8'));
  updateHashLenPrefixed(hash, clientEcdhPublicKey);
  updateHashLenPrefixed(hash, serverEcdhPublicKey);
  updateHashLenPrefixed(hash, pqKemCiphertext);
  updateHashLenPrefixed(hash, classicalSecret);
  updateHashLenPrefixed(hash, pqKemSharedSecret);
  return hash.digest('hex');
}

function clientAddress(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function clientFingerprint(req) {
  const agent = req.get('user-agent') || '';
  return crypto.createHash('sha256').update(`${clientAddress(req)}|${agent}`).digest('hex');
}

function proofBytes(hexData) {
  const value = hexData.startsWith('0x') ? hexData.slice(2) : hexData;
  return Math.ceil(value.length / 2);
}

function redactSensitive(input) {
  if (!ANON_LOGGING) {
    return input;
  }
  return Object.fromEntries(Object.keys(input).map((k) => [k, '<redacted>']));
}

async function sendAlert(message, details = {}) {
  if (!ALERT_WEBHOOK_URL) {
    return;
  }
  try {
    await fetch(ALERT_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        service: 'bluearc-relayer',
        message,
        details,
        ts: new Date().toISOString()
      })
    });
  } catch (error) {
    logger.warn({ error: error.message }, 'failed to send alert webhook');
  }
}

function routeLabel(req) {
  if (req.route?.path) {
    return req.route.path.toString();
  }
  if (req.path.startsWith('/status/')) {
    return '/status/:jobId';
  }
  return req.path;
}

app.use((req, res, next) => {
  const started = process.hrtime.bigint();
  res.on('finish', () => {
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    requestDurationMs.labels(req.method, routeLabel(req), String(res.statusCode)).observe(elapsedMs);
  });
  next();
});

function makeRedisRateLimiter(bucket, limit) {
  return async function redisRateLimiter(req, res, next) {
    try {
      const subject = clientAddress(req);
      const result = await storage.consumeRateLimit(bucket, subject, limit, RATE_WINDOW_MS);
      res.setHeader('x-ratelimit-limit', String(limit));
      res.setHeader('x-ratelimit-remaining', String(result.remaining));
      if (!result.allowed) {
        submitRejectedTotal.labels('rate_limit').inc();
        return res.status(429).json({ error: 'rate limited' });
      }
      return next();
    } catch (error) {
      req.log.error({ error: error.message }, 'rate limiter unavailable');
      return res.status(503).json({ error: 'rate limiter unavailable' });
    }
  };
}

async function recordAbuse(req, reason, points = 1) {
  try {
    const subject = clientAddress(req);
    const score = await storage.incrementAbuse(subject, ABUSE_TTL_MS, points);
    req.log.warn({ reason, score }, 'abuse score incremented');
    if (score >= ABUSE_BLOCK_THRESHOLD) {
      await sendAlert('abuse threshold reached', { subject, score, reason });
    }
    return score;
  } catch (error) {
    req.log.error({ error: error.message }, 'failed to record abuse score');
    return 0;
  }
}

function decryptEnvelope(sessionKeyHex, envelope, aadString) {
  const key = Buffer.from(sessionKeyHex, 'hex');
  if (key.length !== 32) {
    throw new Error('session key length invalid');
  }

  const iv = Buffer.from(envelope.iv, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  if (iv.length !== 12 || tag.length !== 16) {
    throw new Error('invalid aead envelope');
  }

  const aad = Buffer.from(envelope.aad || aadString, 'utf8');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

app.get('/health', async (_req, res) => {
  try {
    await storage.ping();
    const network = await provider.getNetwork();
    return res.json({
      ok: true,
      chainId: Number(network.chainId),
      signer: signerAddress,
      pqKemAlgorithm: 'ML-KEM-768',
      minFeeBps: MIN_FEE_BPS,
      maxFeeBps: MAX_FEE_BPS,
      proofMaxBytes: PROOF_MAX_BYTES,
      defaultPool: runtimePoolAddress,
      deployConfigLoadedAt: runtimeDeployLoadedAt
    });
  } catch (error) {
    return res.status(503).json({ ok: false, error: error.message });
  }
});

app.get('/config', async (_req, res) => {
  try {
    const network = await provider.getNetwork();
    return res.json({
      chainId: Number(network.chainId),
      signer: signerAddress,
      pqKemAlgorithm: 'ML-KEM-768',
      minFeeBps: MIN_FEE_BPS,
      maxFeeBps: MAX_FEE_BPS,
      proofMaxBytes: PROOF_MAX_BYTES,
      defaultPool: runtimePoolAddress,
      deployConfigLoadedAt: runtimeDeployLoadedAt
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get('/metrics', async (_req, res) => {
  res.setHeader('content-type', metrics.contentType);
  res.end(await metrics.metrics());
});

app.get('/handshake/server-key', makeRedisRateLimiter('handshake-key', RATE_LIMIT_HANDSHAKE), (req, res) => {
  const key = getActiveServerKey();
  req.log.info(redactSensitive({ keyId: key.keyId }), 'handshake server key requested');
  return res.json({
    keyId: key.keyId,
    curve: 'prime256v1',
    serverEcdhPublicKey: key.ecdh.getPublicKey('base64'),
    pqKemAlgorithm: 'ML-KEM-768',
    pqKemPublicKey: Buffer.from(key.kemPublicKey).toString('base64'),
    pqKemCiphertextBytes: ml_kem768.lengths.cipherText,
    expiresAt: key.expiresAt
  });
});

app.post('/handshake/open', makeRedisRateLimiter('handshake-open', RATE_LIMIT_HANDSHAKE), async (req, res) => {
  const parsed = handshakeOpenSchema.safeParse(req.body);
  if (!parsed.success) {
    submitRejectedTotal.labels('bad_handshake_payload').inc();
    await recordAbuse(req, 'bad_handshake_payload');
    return res.status(400).json({ error: 'invalid handshake payload' });
  }

  try {
    const key = getActiveServerKey();
    if (parsed.data.keyId && parsed.data.keyId !== key.keyId) {
      return res.status(409).json({ error: 'stale server key', currentKeyId: key.keyId });
    }

    const clientPub = Buffer.from(parsed.data.clientEcdhPublicKey, 'base64');
    const pqKemCiphertext = Buffer.from(parsed.data.pqKemCiphertext, 'base64');
    if (pqKemCiphertext.length !== ml_kem768.lengths.cipherText) {
      return res.status(400).json({ error: 'invalid pq kem ciphertext length' });
    }
    const classicalSecret = key.ecdh.computeSecret(clientPub);
    const pqPart = ml_kem768.decapsulate(new Uint8Array(pqKemCiphertext), key.kemSecretKey);
    const sessionKey = deriveHybridSessionKeyHex({
      keyId: key.keyId,
      clientEcdhPublicKey: new Uint8Array(clientPub),
      serverEcdhPublicKey: key.ecdh.getPublicKey(),
      pqKemCiphertext: new Uint8Array(pqKemCiphertext),
      classicalSecret: new Uint8Array(classicalSecret),
      pqKemSharedSecret: pqPart
    });
    const sessionId = crypto.randomUUID();
    const createdAt = Date.now();
    const expiresAt = createdAt + SESSION_TTL_MS;
    const fingerprint = clientFingerprint(req);

    await storage.createSession(
      sessionId,
      { sessionKey, keyId: key.keyId, createdAt, expiresAt, fingerprint },
      SESSION_TTL_MS
    );

    return res.json({
      sessionId,
      expiresInSec: Math.floor(SESSION_TTL_MS / 1000),
      keySchedule: 'sha256(bluearc_hybrid_mlkem_v1 transcript)',
      submitMode: 'encrypted-envelope-v1'
    });
  } catch (error) {
    submitRejectedTotal.labels('handshake_failed').inc();
    await recordAbuse(req, 'handshake_failed', 2);
    return res.status(400).json({ error: 'handshake failed' });
  }
});

app.post('/quote', makeRedisRateLimiter('quote', RATE_LIMIT_QUOTE), async (req, res) => {
  const parsed = quoteSchema.safeParse(req.body);
  if (!parsed.success) {
    submitRejectedTotal.labels('bad_quote_payload').inc();
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  try {
    const { pool } = parsed.data;
    const normalizedPool = pool.toLowerCase();
    if (POOL_ALLOWLIST.size > 0 && !POOL_ALLOWLIST.has(normalizedPool)) {
      return res.status(403).json({ error: 'pool not allowlisted' });
    }

    const requestedFeeBps = parsed.data.feeBps ?? MIN_FEE_BPS;
    if (requestedFeeBps < MIN_FEE_BPS || requestedFeeBps > MAX_FEE_BPS) {
      return res.status(400).json({ error: 'feeBps out of bounds' });
    }

    const poolContract = new ethers.Contract(pool, poolAbi, provider);
    const denomination = await poolContract.denomination();
    const baseRelayerFee = await poolContract.baseRelayerFee();
    const minBpsFromBase = Number(ceilDiv(baseRelayerFee * 10_000n, denomination));
    const feeBps = Math.max(requestedFeeBps, minBpsFromBase);
    if (feeBps > MAX_FEE_BPS) {
      return res.status(400).json({
        error: `pool baseRelayerFee requires at least ${minBpsFromBase} bps, above MAX_FEE_BPS=${MAX_FEE_BPS}`
      });
    }
    const fee = (denomination * BigInt(feeBps)) / 10_000n;
    const effectiveFee = fee < baseRelayerFee ? baseRelayerFee : fee;
    const quoteId = crypto.randomUUID();
    const now = Date.now();
    const chainId = Number((await provider.getNetwork()).chainId);
    const quote = {
      quoteId,
      pool,
      feeBps,
      fee: effectiveFee.toString(),
      chainId,
      expiresAt: now + QUOTE_TTL_MS,
      issuedAt: now
    };
    const digest = quoteDigest(quote);
    const signature = await signer.signDigest(digest);

    await storage.putQuote({
      ...quote,
      signature,
      createdAt: now
    });
    quoteIssuedTotal.inc();

    return res.json({
      quote,
      quoteSignature: signature,
      ttlSec: Math.floor(QUOTE_TTL_MS / 1000),
      signer: signerAddress,
      requestedFeeBps,
      baseRelayerFee: baseRelayerFee.toString(),
      minFeeBpsForPool: minBpsFromBase
    });
  } catch (error) {
    req.log.error({ error: error.message }, 'quote failed');
    return res.status(500).json({ error: `quote failed: ${error.message}` });
  }
});

app.post('/submit', makeRedisRateLimiter('submit', RATE_LIMIT_SUBMIT), async (req, res) => {
  let abuseScore = 0;
  try {
    abuseScore = await storage.getAbuseScore(clientAddress(req));
  } catch (error) {
    req.log.error({ error: error.message }, 'abuse score lookup failed');
    return res.status(503).json({ error: 'storage unavailable' });
  }
  if (abuseScore >= ABUSE_BLOCK_THRESHOLD) {
    submitRejectedTotal.labels('abuse_block').inc();
    return res.status(429).json({ error: 'abuse protection triggered' });
  }

  const parsedEnvelope = submitEnvelopeSchema.safeParse(req.body);
  if (!parsedEnvelope.success) {
    submitRejectedTotal.labels('bad_submit_envelope').inc();
    await recordAbuse(req, 'bad_submit_envelope');
    return res.status(400).json({ error: parsedEnvelope.error.flatten() });
  }

  const { sessionId, envelope } = parsedEnvelope.data;
  const session = await storage.getSession(sessionId);
  if (!session) {
    submitRejectedTotal.labels('invalid_session').inc();
    await recordAbuse(req, 'invalid_session', 2);
    return res.status(401).json({ error: 'invalid session' });
  }

  const now = Date.now();
  if (now > session.expiresAt) {
    await storage.deleteSession(sessionId);
    submitRejectedTotal.labels('session_expired').inc();
    return res.status(401).json({ error: 'session expired' });
  }

  if (ENFORCE_SESSION_BINDING && session.fingerprint !== clientFingerprint(req)) {
    submitRejectedTotal.labels('session_fingerprint_mismatch').inc();
    await recordAbuse(req, 'session_fingerprint_mismatch', 3);
    return res.status(401).json({ error: 'session fingerprint mismatch' });
  }

  let payload;
  try {
    const decoded = decryptEnvelope(session.sessionKey, envelope, sessionId);
    const parsedPayload = submitPayloadSchema.safeParse(decoded);
    if (!parsedPayload.success) {
      throw new Error('invalid submit payload');
    }
    payload = parsedPayload.data;
  } catch (_error) {
    submitRejectedTotal.labels('decrypt_or_parse_failed').inc();
    await recordAbuse(req, 'decrypt_or_parse_failed', 2);
    return res.status(400).json({ error: 'decrypt/parse failed' });
  }

  if (payload.expiresAt < now || payload.expiresAt > now + PAYLOAD_MAX_AGE_MS || payload.expiresAt > session.expiresAt) {
    submitRejectedTotal.labels('payload_expired').inc();
    await recordAbuse(req, 'payload_expired');
    return res.status(400).json({ error: 'payload expired' });
  }

  const replayTtl = Math.max(10_000, Math.min(NONCE_TTL_MS, payload.expiresAt - now + 30_000));
  const freshNonce = await storage.useNonce(sessionId, payload.nonce, replayTtl);
  if (!freshNonce) {
    submitRejectedTotal.labels('nonce_replay').inc();
    await recordAbuse(req, 'nonce_replay', 3);
    return res.status(409).json({ error: 'replay detected' });
  }

  if (payload.pool.toLowerCase() !== payload.quote.pool.toLowerCase()) {
    submitRejectedTotal.labels('quote_pool_mismatch').inc();
    await recordAbuse(req, 'quote_pool_mismatch');
    return res.status(400).json({ error: 'quote/pool mismatch' });
  }

  const storedQuote = await storage.getQuote(payload.quote.quoteId);
  if (!storedQuote) {
    submitRejectedTotal.labels('quote_missing').inc();
    await recordAbuse(req, 'quote_missing');
    return res.status(400).json({ error: 'invalid quote' });
  }
  if (now > storedQuote.expiresAt || now - storedQuote.createdAt > QUOTE_REPLAY_WINDOW_MS) {
    submitRejectedTotal.labels('quote_expired').inc();
    await recordAbuse(req, 'quote_expired');
    return res.status(400).json({ error: 'quote expired' });
  }

  if (
    payload.quote.expiresAt !== storedQuote.expiresAt ||
    payload.quote.fee !== storedQuote.fee ||
    payload.quote.feeBps !== storedQuote.feeBps ||
    payload.quote.chainId !== storedQuote.chainId
  ) {
    submitRejectedTotal.labels('quote_tamper').inc();
    await recordAbuse(req, 'quote_tamper', 2);
    return res.status(400).json({ error: 'quote tamper detected' });
  }

  const digest = quoteDigest(payload.quote);
  const recovered = ethers.verifyMessage(ethers.getBytes(digest), payload.quoteSignature);
  if (recovered.toLowerCase() !== signerAddress.toLowerCase()) {
    submitRejectedTotal.labels('quote_signature_invalid').inc();
    await recordAbuse(req, 'quote_signature_invalid', 2);
    return res.status(400).json({ error: 'invalid quote signature' });
  }
  if (payload.quoteSignature.toLowerCase() !== storedQuote.signature.toLowerCase()) {
    submitRejectedTotal.labels('quote_signature_mismatch').inc();
    await recordAbuse(req, 'quote_signature_mismatch', 2);
    return res.status(400).json({ error: 'signature mismatch' });
  }

  const liveChainId = Number((await provider.getNetwork()).chainId);
  if (payload.quote.chainId !== liveChainId) {
    submitRejectedTotal.labels('quote_chain_mismatch').inc();
    await recordAbuse(req, 'quote_chain_mismatch');
    return res.status(400).json({ error: 'quote chain mismatch' });
  }

  if (proofBytes(payload.proof) > PROOF_MAX_BYTES) {
    submitRejectedTotal.labels('proof_too_large').inc();
    await recordAbuse(req, 'proof_too_large');
    return res.status(400).json({ error: 'proof too large' });
  }

  const jobId = crypto.randomUUID();
  const txArgs = [
    payload.proof,
    payload.root,
    payload.nullifierHash,
    payload.recipient,
    signerAddress,
    BigInt(payload.quote.fee),
    BigInt(payload.refund)
  ];

  await storage.putJob(jobId, { status: 'queued', createdAt: now });
  jobTransitionsTotal.labels('queued').inc();
  submitAcceptedTotal.inc();

  req.log.info(redactSensitive({ jobId, pool: payload.pool, recipient: payload.recipient }), 'submit accepted');

  try {
    await storage.putJob(jobId, { status: 'broadcasting', createdAt: now });
    jobTransitionsTotal.labels('broadcasting').inc();

    const poolContract = new ethers.Contract(payload.pool, poolAbi, provider);
    const tx = await signer.sendWithdrawTx({
      poolContract,
      poolAddress: payload.pool,
      args: txArgs
    });

    await storage.putJob(jobId, { status: 'pending', txHash: tx.hash, createdAt: now });
    jobTransitionsTotal.labels('pending').inc();

    const receipt = await tx.wait();
    await storage.putJob(jobId, {
      status: 'confirmed',
      txHash: tx.hash,
      blockNumber: receipt.blockNumber,
      createdAt: now
    });
    jobTransitionsTotal.labels('confirmed').inc();
    consecutiveFailureCount = 0;

    return res.json({ jobId, txHash: tx.hash, status: 'pending' });
  } catch (error) {
    await storage.putJob(jobId, { status: 'failed', error: error.message, createdAt: now });
    jobTransitionsTotal.labels('failed').inc();
    submitRejectedTotal.labels('tx_failed').inc();
    await recordAbuse(req, 'tx_failed');

    consecutiveFailureCount += 1;
    if (consecutiveFailureCount >= ALERT_FAILURE_THRESHOLD) {
      await sendAlert('submit failure threshold reached', {
        consecutiveFailureCount,
        error: error.message
      });
      consecutiveFailureCount = 0;
    }

    return res.status(500).json({ error: error.message, jobId });
  }
});

app.get('/status/:jobId', makeRedisRateLimiter('status', RATE_LIMIT_STATUS), async (req, res) => {
  const job = await storage.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'job not found' });
  }
  return res.json(job);
});

app.use((err, req, res, _next) => {
  req.log.error({ error: err.message }, 'unhandled error');
  return res.status(500).json({ error: 'internal server error' });
});

function createServer() {
  const certPath = process.env.TLS_CERT_PATH;
  const keyPath = process.env.TLS_KEY_PATH;
  const caPath = process.env.TLS_CA_PATH;

  if ((certPath && !keyPath) || (!certPath && keyPath)) {
    throw new Error('TLS_CERT_PATH and TLS_KEY_PATH must both be set');
  }

  if (certPath && keyPath) {
    const options = {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
      requestCert: TLS_REQUIRE_CLIENT_CERT,
      rejectUnauthorized: TLS_REQUIRE_CLIENT_CERT
    };
    if (caPath) {
      options.ca = fs.readFileSync(caPath);
    }
    if (TLS_REQUIRE_CLIENT_CERT && !caPath) {
      throw new Error('TLS_REQUIRE_CLIENT_CERT=true requires TLS_CA_PATH');
    }
    return { server: https.createServer(options, app), protocol: 'https', mtls: TLS_REQUIRE_CLIENT_CERT };
  }

  if (TLS_REQUIRE_CLIENT_CERT) {
    throw new Error('mTLS requires TLS_CERT_PATH/TLS_KEY_PATH');
  }

  const allowInsecureHttp = envBool('ALLOW_INSECURE_HTTP', process.env.NODE_ENV !== 'production');
  if (!allowInsecureHttp) {
    throw new Error('Insecure HTTP disabled. Configure TLS_CERT_PATH/TLS_KEY_PATH or set ALLOW_INSECURE_HTTP=true.');
  }
  return { server: http.createServer(app), protocol: 'http', mtls: false };
}

async function start() {
  await storage.init();
  await storage.ping();
  signerAddress = await signer.getAddress();
  loadDeployRuntimeConfig();

  const pruneHandle = setInterval(async () => {
    try {
      await storage.pruneExpired({
        nowMs: Date.now(),
        quoteRetentionMs: QUOTE_RETENTION_MS,
        jobRetentionMs: JOB_RETENTION_MS
      });
    } catch (error) {
      logger.warn({ error: error.message }, 'failed to prune expired storage records');
    }
  }, STORAGE_PRUNE_INTERVAL_MS);
  pruneHandle.unref();

  const deployConfigHandle = setInterval(() => {
    loadDeployRuntimeConfig();
  }, DEPLOY_REFRESH_MS);
  deployConfigHandle.unref();

  const { server, protocol, mtls } = createServer();
  server.listen(PORT, HOST, () => {
    logger.info(
      {
        host: HOST,
        port: PORT,
        protocol,
        mtls,
        signer: signerAddress,
        minFeeBps: MIN_FEE_BPS,
        maxFeeBps: MAX_FEE_BPS
      },
      'bluearc relayer listening'
    );
  });

  const shutdown = async (signal) => {
    logger.info({ signal }, 'shutting down');
    server.close(async () => {
      await storage.close();
      process.exit(0);
    });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

start().catch((error) => {
  logger.error({ error: error.message }, 'failed to start relayer');
  process.exit(1);
});
