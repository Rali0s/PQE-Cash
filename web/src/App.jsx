import { useEffect, useMemo, useRef, useState } from 'react';
import { ethers } from 'ethers';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

const POOL_ABI = [
  'function deposit(bytes32 commitment) payable',
  'function currentRoot() view returns (bytes32)',
  'function denomination() view returns (uint256)',
  'function baseRelayerFee() view returns (uint256)',
  'function owner() view returns (address)',
  'function treasury() view returns (address)',
  'function protocolFeeBps() view returns (uint256)',
  'function relayerOnly() view returns (bool)',
  'function approvedRelayersOnly() view returns (bool)',
  'function approvedRelayers(address) view returns (bool)',
  'function setBaseRelayerFee(uint256 newBaseRelayerFee)',
  'function setProtocolFeeBps(uint256 newProtocolFeeBps)',
  'function setRelayerOnly(bool enabled)',
  'function setApprovedRelayersOnly(bool enabled)',
  'function setRelayerApproval(address relayer, bool approved)',
  'function setTreasury(address payable newTreasury)'
];

const TREASURY_ABI = [
  'function owner() view returns (address)',
  'function withdrawDelay() view returns (uint256)',
  'function nextRequestId() view returns (uint256)',
  'function requests(uint256) view returns (address to, uint256 amount, uint256 unlockTime, bool executed)',
  'function setWithdrawDelay(uint256 newWithdrawDelay)',
  'function queueWithdrawal(address payable to, uint256 amount) returns (uint256 requestId)',
  'function executeWithdrawal(uint256 requestId)'
];

const RELAYER_DEFAULT =
  import.meta.env.VITE_RELAYER_URL || 'https://relayer-production-86ea.up.railway.app';
const POOL_V2_HARDCODED = '0xBeBE31Bf60f55CfE7caC13162e88a628eB637667';
const MAINNET_POOL_V2 = '0xcDcdF747d7Ba38EeE6e899e0dEeccd1102449a8e';
const POOL_DEFAULT = import.meta.env.VITE_POOL_ADDRESS || POOL_V2_HARDCODED;
const PROOF_VERSION_DEFAULT = import.meta.env.VITE_PROOF_VERSION || 'bluearc-v2';
const POOL_VERSION_DEFAULT = import.meta.env.VITE_POOL_VERSION || 'v2';
const DEV_PROOF_DEFAULT = import.meta.env.VITE_DEV_PROOF || '0x01';
const NETWORK_DEFAULT = (import.meta.env.VITE_DEFAULT_NETWORK || 'sepolia').toLowerCase() === 'mainnet' ? 'mainnet' : 'sepolia';
const NETWORK_PROFILES = {
  sepolia: {
    id: 'sepolia',
    label: 'Testnet Live (Sepolia)',
    chainId: 11155111,
    poolAddress: POOL_V2_HARDCODED,
    relayerUrl: RELAYER_DEFAULT,
    proofVersion: 'bluearc-v2'
  },
  mainnet: {
    id: 'mainnet',
    label: 'Mainnet Live (Use at your own risk)',
    chainId: 1,
    poolAddress: MAINNET_POOL_V2,
    relayerUrl: '',
    proofVersion: 'bluearc-v2'
  }
};
const MAINNET_DEPLOYMENT = {
  deployer: '0xA01d4586f6258861dEfd4F1Ded795052C0E49d4e',
  externalVerifier: '0xe6740BcB7f03F5A6573D431B8aBEcAE8B195D3C2',
  poseidonHasher: '0xfD88A344b01A2c77bc8497808953cF1292E49e85',
  verifierAdapter: '0xE7289782a02388249CFC59962EA85f445041738a',
  privacyPoolV2: '0xcDcdF747d7Ba38EeE6e899e0dEeccd1102449a8e',
  denominationWei: '100000000000000000'
};
const RELAYER_API_OPTIONS = [
  {
    id: 'railway',
    label: 'BlueARC Relay (Railway)',
    url: 'https://relayer-production-86ea.up.railway.app'
  },
  { id: 'local', label: 'Local Relayer (127.0.0.1:8080)', url: 'http://127.0.0.1:8080' }
];

function randHex32() {
  return ethers.hexlify(ethers.randomBytes(32));
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function uint32BE(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function lenPrefixed(bytes) {
  return concatBytes([uint32BE(bytes.length), bytes]);
}

function formatDecimalString(value, maxDecimals = 6) {
  const [intRaw, fracRaw = ''] = value.split('.');
  const intNormalized = intRaw === '' ? '0' : intRaw;
  const intFormatted = new Intl.NumberFormat('en-US').format(BigInt(intNormalized));
  const fracTrimmed = fracRaw.slice(0, maxDecimals).replace(/0+$/, '');
  return fracTrimmed ? `${intFormatted}.${fracTrimmed}` : intFormatted;
}

function formatWeiToEth(wei) {
  if (!wei) return '-';
  try {
    const eth = ethers.formatEther(BigInt(wei));
    return `${formatDecimalString(eth, 6)} ETH`;
  } catch (_error) {
    return `${wei} wei`;
  }
}

function getProofInfo(proofHex, maxBytes) {
  const proof = (proofHex || '').trim();
  if (!proof) {
    return { valid: false, message: 'Enter proof hex', bytes: 0, overLimit: false };
  }
  if (!proof.startsWith('0x')) {
    return { valid: false, message: 'Proof must start with 0x', bytes: 0, overLimit: false };
  }
  const body = proof.slice(2);
  if (!/^[0-9a-fA-F]*$/.test(body)) {
    return { valid: false, message: 'Proof has non-hex characters', bytes: 0, overLimit: false };
  }
  if (body.length % 2 !== 0) {
    return { valid: false, message: 'Proof hex must have even length', bytes: 0, overLimit: false };
  }
  const bytes = body.length / 2;
  const overLimit = Number.isFinite(maxBytes) && maxBytes > 0 ? bytes > maxBytes : false;
  const kb = bytes / 1024;
  const sizeLabel = `${new Intl.NumberFormat('en-US').format(bytes)} bytes (${kb.toFixed(2)} KB)`;
  if (overLimit) {
    return { valid: false, message: `${sizeLabel} exceeds limit ${maxBytes} bytes`, bytes, overLimit: true };
  }
  return { valid: true, message: sizeLabel, bytes, overLimit: false };
}

function parseProofInput(input) {
  const raw = (input || '').trim();
  if (!raw) {
    return { ok: false, error: 'Enter proof input' };
  }

  if (raw.startsWith('0x')) {
    const body = raw.slice(2);
    if (!/^[0-9a-fA-F]*$/.test(body)) {
      return { ok: false, error: 'Hex proof has non-hex characters' };
    }
    if (body.length % 2 !== 0) {
      return { ok: false, error: 'Hex proof must have even length' };
    }
    return { ok: true, hex: raw, source: 'hex' };
  }

  if (raw.startsWith('base64:')) {
    const b64 = raw.slice('base64:'.length).trim();
    if (!b64) return { ok: false, error: 'Missing base64 payload after base64:' };
    try {
      const bytes = b64ToBytes(b64);
      if (bytes.length === 0) return { ok: false, error: 'Base64 proof decoded to 0 bytes' };
      return { ok: true, hex: ethers.hexlify(bytes), source: 'base64' };
    } catch (_error) {
      return { ok: false, error: 'Invalid base64 proof input' };
    }
  }

  return { ok: true, hex: ethers.hexlify(ethers.toUtf8Bytes(raw)), source: 'text' };
}

function shortHash(value, left = 8, right = 6) {
  if (!value || typeof value !== 'string') return '-';
  if (value.length <= left + right + 3) return value;
  return `${value.slice(0, left)}...${value.slice(-right)}`;
}

function txExplorerUrl(chainId, txHash) {
  if (!txHash) return '';
  const network = Number(chainId || 0);
  if (network === 11155111) {
    return `https://sepolia.etherscan.io/tx/${txHash}`;
  }
  if (network === 1) {
    return `https://etherscan.io/tx/${txHash}`;
  }
  return '';
}

function drawTigerBanner(canvas) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const width = canvas.width;
  const height = canvas.height;

  const bg = ctx.createLinearGradient(0, 0, width, height);
  bg.addColorStop(0, '#020617');
  bg.addColorStop(1, '#0b2a5a');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, width, height);

  for (let i = 0; i < 60; i += 1) {
    const x = (i * 37) % width;
    const y = (i * 53) % height;
    const c = i % 3 === 0 ? '#60a5fa' : '#1d4ed8';
    ctx.fillStyle = c;
    ctx.fillRect(x, y, 2, 6);
  }

  ctx.strokeStyle = '#93c5fd';
  ctx.lineWidth = 3;
  for (let i = 0; i < 5; i += 1) {
    ctx.beginPath();
    ctx.moveTo(240 + i * 20, 20);
    ctx.bezierCurveTo(370, 40 + i * 10, 300, 100 + i * 10, 410, 150);
    ctx.stroke();
  }

  ctx.fillStyle = '#111827';
  for (let i = 0; i < 16; i += 1) {
    const bx = 260 + i * 14;
    const bh = 15 + ((i * 13) % 35);
    ctx.fillRect(bx, height - bh, 10, bh);
  }

  ctx.fillStyle = '#e5e7eb';
  ctx.fillRect(42, 56, 84, 54);
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(52, 65, 64, 34);
  ctx.fillStyle = '#60a5fa';
  ctx.fillRect(58, 70, 16, 10);
  ctx.fillRect(93, 70, 16, 10);
  ctx.fillStyle = '#f97316';
  ctx.fillRect(72, 92, 22, 10);
  ctx.fillStyle = '#f8fafc';
  ctx.fillRect(77, 96, 3, 4);
  ctx.fillRect(85, 96, 3, 4);

  ctx.strokeStyle = '#93c5fd';
  ctx.lineWidth = 4;
  ctx.beginPath();
  ctx.moveTo(15, 130);
  ctx.lineTo(160, 130);
  ctx.stroke();

  ctx.fillStyle = '#bfdbfe';
  ctx.font = 'bold 18px monospace';
  ctx.fillText('BLUEARC // TIGER MODE', 145, 30);
}

function normalizeBaseUrl(base) {
  const trimmed = (base || '').trim();
  if (!trimmed) return '/api';
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
}

function buildApiUrl(base, path) {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  const cleanBase = normalizeBaseUrl(base);
  return `${cleanBase}${cleanPath}`;
}

async function fetchJson(base, path, options = {}) {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 12000;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(buildApiUrl(base, path), {
      ...options,
      signal: controller.signal,
      headers: {
        'content-type': 'application/json',
        ...(options.headers || {})
      }
    });

    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch (_error) {
      data = { raw: text };
    }

    if (!response.ok) {
      throw new Error(data?.error || `HTTP ${response.status}`);
    }

    return data;
  } finally {
    clearTimeout(timeout);
  }
}

async function deriveSessionArtifacts({ keyId, serverEcdhPublicKey, pqKemAlgorithm, pqKemPublicKey, pqKemCiphertextBytes }) {
  if (pqKemAlgorithm !== 'ML-KEM-768') {
    throw new Error(`Unsupported PQ KEM algorithm: ${pqKemAlgorithm}`);
  }

  const clientKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const clientPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', clientKeyPair.publicKey));
  const serverPubRaw = b64ToBytes(serverEcdhPublicKey);
  const serverPubKey = await crypto.subtle.importKey(
    'raw',
    serverPubRaw,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: serverPubKey },
    clientKeyPair.privateKey,
    256
  );

  const classicalSecret = new Uint8Array(sharedBits);
  const kemPublicKey = b64ToBytes(pqKemPublicKey);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(kemPublicKey);
  if (pqKemCiphertextBytes && cipherText.length !== pqKemCiphertextBytes) {
    throw new Error('PQ KEM ciphertext length mismatch');
  }

  const encoder = new TextEncoder();
  const transcript = concatBytes([
    encoder.encode('BLUEARC_HYBRID_MLKEM_V1'),
    lenPrefixed(encoder.encode(keyId || '')),
    lenPrefixed(clientPubRaw),
    lenPrefixed(serverPubRaw),
    lenPrefixed(cipherText),
    lenPrefixed(classicalSecret),
    lenPrefixed(sharedSecret)
  ]);
  const sessionHash = await crypto.subtle.digest('SHA-256', transcript);
  const sessionKeyBytes = new Uint8Array(sessionHash);

  return {
    clientPubB64: bytesToB64(clientPubRaw),
    pqKemCiphertextB64: bytesToB64(cipherText),
    sessionKeyHex: bytesToHex(sessionKeyBytes)
  };
}

async function encryptEnvelope(sessionKeyHex, sessionId, payload) {
  const keyBytes = hexToBytes(sessionKeyHex);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(sessionId);
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));

  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plaintext)
  );

  const tag = encrypted.slice(encrypted.length - 16);
  const ciphertext = encrypted.slice(0, encrypted.length - 16);

  return {
    iv: bytesToB64(iv),
    ciphertext: bytesToB64(ciphertext),
    tag: bytesToB64(tag),
    aad: sessionId
  };
}

export default function App() {
  const currentPath = window.location.pathname || '/';
  const shouldRedirectLegacyDocsPath =
    currentPath === '/docs' || currentPath === '/docs/' || currentPath.startsWith('/docs/');
  const isAdminRoute = window.location.pathname.startsWith('/admin');
  const isTigerDocsRoute = window.location.pathname.startsWith('/tiger-docs');
  const [networkProfile, setNetworkProfile] = useState(NETWORK_DEFAULT);
  const [defaultPoolAddress, setDefaultPoolAddress] = useState(NETWORK_PROFILES[NETWORK_DEFAULT].poolAddress);
  const matchedPreset = RELAYER_API_OPTIONS.find(
    (opt) => normalizeBaseUrl(opt.url) === normalizeBaseUrl(RELAYER_DEFAULT)
  );
  const [poolAddress, setPoolAddress] = useState(defaultPoolAddress || POOL_DEFAULT);
  const [relayerUrl, setRelayerUrl] = useState(RELAYER_DEFAULT);
  const [relayerMeshInput, setRelayerMeshInput] = useState(RELAYER_DEFAULT);
  const [relayerPreset, setRelayerPreset] = useState(matchedPreset ? matchedPreset.id : 'custom');
  const [customRelayerUrl, setCustomRelayerUrl] = useState(matchedPreset ? '' : RELAYER_DEFAULT);
  const [poolOverrideEnabled, setPoolOverrideEnabled] = useState(false);
  const [poolOverrideInput, setPoolOverrideInput] = useState('');
  const [recipient, setRecipient] = useState('');
  const [walletAddress, setWalletAddress] = useState('');
  const [walletChainId, setWalletChainId] = useState(null);
  const [walletBalanceWei, setWalletBalanceWei] = useState(0n);
  const [denominationWei, setDenominationWei] = useState(0n);
  const [baseRelayerFeeWei, setBaseRelayerFeeWei] = useState(0n);
  const [note, setNote] = useState('');
  const [root, setRoot] = useState('');
  const [nullifierHash, setNullifierHash] = useState('');
  const [proofInput, setProofInput] = useState(DEV_PROOF_DEFAULT);
  const [proofVersion, setProofVersion] = useState(PROOF_VERSION_DEFAULT);
  const [quote, setQuote] = useState(null);
  const [quoteSignature, setQuoteSignature] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [sessionKeyHex, setSessionKeyHex] = useState('');
  const [jobId, setJobId] = useState('');
  const [status, setStatus] = useState('idle');
  const [log, setLog] = useState('');
  const [relayerInfo, setRelayerInfo] = useState(null);
  const [relayerMonitor, setRelayerMonitor] = useState({});
  const [monitorEnabled, setMonitorEnabled] = useState(true);
  const [adminState, setAdminState] = useState(null);
  const [adminSetBaseFeeEth, setAdminSetBaseFeeEth] = useState('0.001');
  const [adminSetProtocolBps, setAdminSetProtocolBps] = useState('50');
  const [adminSetRelayerOnly, setAdminSetRelayerOnly] = useState('true');
  const [adminSetApprovedRelayersOnly, setAdminSetApprovedRelayersOnly] = useState('false');
  const [adminRelayerAddr, setAdminRelayerAddr] = useState('');
  const [adminRelayerApproved, setAdminRelayerApproved] = useState('true');
  const [adminSetTreasuryAddr, setAdminSetTreasuryAddr] = useState('');
  const [adminWithdrawDelaySec, setAdminWithdrawDelaySec] = useState('3600');
  const [adminQueueTo, setAdminQueueTo] = useState('');
  const [adminQueueAmountEth, setAdminQueueAmountEth] = useState('0.001');
  const [adminExecuteRequestId, setAdminExecuteRequestId] = useState('0');
  const [lastConfirmed, setLastConfirmed] = useState(null);
  const initRelayerLoadRef = useRef(false);
  const logDedupRef = useRef({ line: '', at: 0 });
  const relayerHealthRef = useRef({});
  const tigerCanvasRef = useRef(null);

  const provider = useMemo(() => (window.ethereum ? new ethers.BrowserProvider(window.ethereum) : null), []);
  const parsedProof = useMemo(() => parseProofInput(proofInput), [proofInput]);
  const proofInfo = useMemo(() => {
    if (!parsedProof.ok) {
      return { valid: false, message: parsedProof.error, bytes: 0, overLimit: false };
    }
    const base = getProofInfo(parsedProof.hex, relayerInfo?.proofMaxBytes);
    if (!base.valid) return base;
    const sourceLabel =
      parsedProof.source === 'hex'
        ? 'hex input'
        : parsedProof.source === 'base64'
          ? 'base64 input'
          : 'text input (UTF-8 encoded)';
    return { ...base, message: `${base.message} via ${sourceLabel}` };
  }, [parsedProof, relayerInfo]);
  const quoteFeeHuman = useMemo(() => formatWeiToEth(quote?.fee), [quote]);
  const walletBalanceHuman = useMemo(() => formatWeiToEth(walletBalanceWei.toString()), [walletBalanceWei]);
  const denominationHuman = useMemo(() => formatWeiToEth(denominationWei.toString()), [denominationWei]);
  const baseRelayerFeeHuman = useMemo(() => formatWeiToEth(baseRelayerFeeWei.toString()), [baseRelayerFeeWei]);
  const hasDepositFunds = denominationWei > 0n && walletBalanceWei >= denominationWei;
  const depositShortfallWei = denominationWei > walletBalanceWei ? denominationWei - walletBalanceWei : 0n;
  const depositShortfallHuman = useMemo(() => formatWeiToEth(depositShortfallWei.toString()), [depositShortfallWei]);
  const hasWithdrawInputs = Boolean(note && root && nullifierHash);
  const relayerCandidates = useMemo(() => {
    const fromInput = (relayerMeshInput || '')
      .split(/[\n,]/)
      .map((v) => normalizeBaseUrl(v))
      .filter(Boolean);
    const withCurrent = [normalizeBaseUrl(relayerUrl), ...fromInput].filter(Boolean);
    return Array.from(new Set(withCurrent));
  }, [relayerMeshInput, relayerUrl]);
  const activeRelayerKey = normalizeBaseUrl(relayerUrl);
  const activeRelayerHealth = relayerMonitor[activeRelayerKey] || null;
  const requiredProofVersion = relayerInfo?.requiredProofVersion || '';
  const displayPoolVersion = relayerInfo?.poolVersion || POOL_VERSION_DEFAULT || '-';
  const displayRequiredProofVersion = relayerInfo?.requiredProofVersion || PROOF_VERSION_DEFAULT || '-';
  const proofVersionMismatch =
    Boolean(requiredProofVersion) && (proofVersion || '').trim() !== requiredProofVersion;
  const effectiveUserAddress = adminState?.userAddress || walletAddress;
  const isPoolOwner = Boolean(
    effectiveUserAddress &&
      adminState?.poolOwner &&
      effectiveUserAddress.toLowerCase() === adminState.poolOwner.toLowerCase()
  );
  const isTreasuryOwner = Boolean(
    effectiveUserAddress &&
      adminState?.treasuryOwner &&
      effectiveUserAddress.toLowerCase() === adminState.treasuryOwner.toLowerCase()
  );

  const canDeposit = Boolean(provider && ethers.isAddress(poolAddress) && hasDepositFunds);
  const canOpenSession = Boolean(relayerUrl);
  const canQuote = Boolean(poolAddress && relayerUrl);
  const canSubmit = Boolean(
    relayerUrl &&
      sessionId &&
      sessionKeyHex &&
      quote &&
      quoteSignature &&
      poolAddress &&
      proofInfo.valid &&
      root &&
      nullifierHash &&
      recipient &&
      !proofVersionMismatch
  );

  function appendLog(line) {
    const now = Date.now();
    if (logDedupRef.current.line === line && now - logDedupRef.current.at < 1500) {
      return;
    }
    logDedupRef.current = { line, at: now };
    const stamp = new Date().toISOString().slice(11, 19);
    setLog((previous) => `${previous ? `${previous}\n` : ''}[${stamp}] ${line}`);
  }

  function friendlyError(error) {
    const message = error?.message || String(error);
    if (message.includes('INSUFFICIENT_FUNDS')) {
      if (message.includes('INSUFFICIENT_FUNDS_DEPOSIT')) {
        return message.replace('Error: INSUFFICIENT_FUNDS_DEPOSIT: ', '');
      }
      return `Insufficient ETH for deposit. Need ${denominationHuman} + gas, wallet has ${walletBalanceHuman}. If you already deposited, skip deposit and continue with Withdraw via Relayer.`;
    }
    if (message.includes('fee below base')) {
      return `Quote below pool base fee. Request a new quote (base fee floor is ${baseRelayerFeeHuman}).`;
    }
    if (message.includes('proof version mismatch')) {
      return `${message}. Set proof version to required value shown in Network panel.`;
    }
    return message;
  }

  async function runStep(label, fn) {
    try {
      setStatus(label);
      await fn();
    } catch (error) {
      const message = friendlyError(error);
      setStatus('error');
      appendLog(`${label} failed: ${message}`);
    }
  }

  async function refreshWalletPoolMeta() {
    if (!provider || !ethers.isAddress(poolAddress)) return;
    const pool = new ethers.Contract(poolAddress, POOL_ABI, provider);
    const [denom, baseFee] = await Promise.all([pool.denomination(), pool.baseRelayerFee()]);
    setDenominationWei(denom);
    setBaseRelayerFeeWei(baseFee);
    if (walletAddress) {
      const bal = await provider.getBalance(walletAddress);
      setWalletBalanceWei(bal);
    }
  }

  async function loadRelayerConfig() {
    let config;
    try {
      config = await fetchJson(relayerUrl, '/health', { method: 'GET' });
    } catch (_error) {
      config = await fetchJson(relayerUrl, '/config', { method: 'GET' });
      appendLog('Relayer /health unavailable, loaded /config fallback');
    }
    setRelayerInfo(config);
    if (!poolOverrideEnabled && !POOL_DEFAULT && !poolAddress && config.defaultPool) {
      setPoolAddress(config.defaultPool);
    }
    appendLog(
      `Relayer ok chain=${config.chainId} signer=${config.signer} defaultPool=${config.defaultPool || '-'}`
    );
    if (config.requiredProofVersion) {
      setProofVersion(config.requiredProofVersion);
    }
    if (!(proofInput || '').trim()) {
      setProofInput(DEV_PROOF_DEFAULT);
    }
    setStatus('relayer ready');
  }

  function generateDevProofHex() {
    if (!note || !root || !nullifierHash) {
      return DEV_PROOF_DEFAULT;
    }
    try {
      return ethers.keccak256(
        ethers.concat([
          ethers.toUtf8Bytes('bluearc-dev-proof-v1:'),
          ethers.getBytes(note),
          ethers.getBytes(root),
          ethers.getBytes(nullifierHash)
        ])
      );
    } catch (_error) {
      return DEV_PROOF_DEFAULT;
    }
  }

  async function pingRelayerHealth(baseUrl) {
    const started = performance.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    try {
      const response = await fetch(buildApiUrl(baseUrl, '/health'), {
        method: 'GET',
        signal: controller.signal
      });
      const latencyMs = Math.round(performance.now() - started);
      const text = await response.text();
      let data = {};
      try {
        data = text ? JSON.parse(text) : {};
      } catch (_error) {
        data = {};
      }
      if (!response.ok) {
        throw new Error(data?.error || `HTTP ${response.status}`);
      }
      return {
        ok: true,
        latencyMs,
        chainId: data.chainId ?? null,
        signer: data.signer || '',
        error: ''
      };
    } catch (error) {
      const latencyMs = Math.round(performance.now() - started);
      return {
        ok: false,
        latencyMs,
        chainId: null,
        signer: '',
        error: error?.message || 'health check failed'
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  async function checkRelayer(baseUrl, { silent = true } = {}) {
    const normalized = normalizeBaseUrl(baseUrl);
    if (!normalized) return;
    const result = await pingRelayerHealth(normalized);
    setRelayerMonitor((previous) => ({
      ...previous,
      [normalized]: {
        ...result,
        checkedAt: Date.now()
      }
    }));
    const previousOk = relayerHealthRef.current[normalized];
    relayerHealthRef.current[normalized] = result.ok;
    if (!silent && previousOk !== result.ok) {
      appendLog(`Relayer ${normalized} is now ${result.ok ? 'healthy' : 'unhealthy'} (${result.latencyMs}ms)`);
    }
  }

  async function refreshRelayerMesh({ silent = true } = {}) {
    await Promise.all(relayerCandidates.map((url) => checkRelayer(url, { silent })));
  }

  function switchToHealthyRelayer() {
    const current = normalizeBaseUrl(relayerUrl);
    const fallback = relayerCandidates.find((url) => url !== current && relayerMonitor[url]?.ok);
    if (!fallback) {
      throw new Error('No healthy fallback relayer found');
    }
    setRelayerUrl(fallback);
    appendLog(`Failover: switched active relayer to ${fallback}`);
    setStatus('relayer failover');
  }

  async function loadAdminState() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(poolAddress)) throw new Error('Invalid pool address');

    const signer = await provider.getSigner();
    const userAddress = await signer.getAddress();
    if (!walletAddress || walletAddress.toLowerCase() !== userAddress.toLowerCase()) {
      setWalletAddress(userAddress);
    }
    const pool = new ethers.Contract(poolAddress, POOL_ABI, provider);
    const poolBalanceWei = await provider.getBalance(poolAddress);
    const [poolOwner, treasury, protocolFeeBps, relayerOnly, approvedRelayersOnly, baseRelayerFee] = await Promise.all([
      pool.owner(),
      pool.treasury(),
      pool.protocolFeeBps(),
      pool.relayerOnly(),
      pool.approvedRelayersOnly(),
      pool.baseRelayerFee()
    ]);

    let relayerApproved = null;
    if (ethers.isAddress(adminRelayerAddr)) {
      relayerApproved = await pool.approvedRelayers(adminRelayerAddr);
    }

    let treasuryOwner = '';
    let withdrawDelay = 0n;
    let nextRequestId = 0n;
    let treasuryBalanceWei = 0n;
    if (ethers.isAddress(treasury)) {
      const treasuryContract = new ethers.Contract(treasury, TREASURY_ABI, provider);
      treasuryBalanceWei = await provider.getBalance(treasury);
      [treasuryOwner, withdrawDelay, nextRequestId] = await Promise.all([
        treasuryContract.owner(),
        treasuryContract.withdrawDelay(),
        treasuryContract.nextRequestId()
      ]);
    }

    setAdminState({
      poolOwner,
      treasury,
      protocolFeeBps: Number(protocolFeeBps),
      relayerOnly,
      approvedRelayersOnly,
      baseRelayerFee: baseRelayerFee.toString(),
      relayerApproved,
      treasuryOwner,
      withdrawDelay: Number(withdrawDelay),
      nextRequestId: Number(nextRequestId),
      poolBalanceWei: poolBalanceWei.toString(),
      treasuryBalanceWei: treasuryBalanceWei.toString(),
      loadedAt: Date.now(),
      userAddress
    });

    setAdminSetBaseFeeEth(ethers.formatEther(baseRelayerFee));
    setAdminSetProtocolBps(String(Number(protocolFeeBps)));
    setAdminSetRelayerOnly(String(Boolean(relayerOnly)));
    setAdminSetApprovedRelayersOnly(String(Boolean(approvedRelayersOnly)));
    if (ethers.isAddress(treasury)) {
      setAdminSetTreasuryAddr(treasury);
      setAdminQueueTo((previous) => previous || userAddress);
      setAdminWithdrawDelaySec(String(Number(withdrawDelay)));
      setAdminExecuteRequestId(String(Number(nextRequestId > 0n ? nextRequestId - 1n : 0n)));
    }

    appendLog(
      `Admin loaded owner=${shortHash(poolOwner, 10, 6)} treasury=${shortHash(treasury, 10, 6)} poolOwner=${
        userAddress.toLowerCase() === poolOwner.toLowerCase() ? 'yes' : 'no'
      }`
    );
    setStatus('admin ready');
  }

  async function adminSetBaseFee() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(poolAddress)) throw new Error('Invalid pool address');
    const value = ethers.parseEther(adminSetBaseFeeEth.trim() || '0');
    const signer = await provider.getSigner();
    const pool = new ethers.Contract(poolAddress, POOL_ABI, signer);
    const tx = await pool.setBaseRelayerFee(value);
    await tx.wait();
    appendLog(`Admin setBaseRelayerFee tx=${tx.hash}`);
    await loadAdminState();
  }

  async function adminSetProtocolFee() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(poolAddress)) throw new Error('Invalid pool address');
    const value = Number(adminSetProtocolBps);
    if (!Number.isFinite(value) || value < 0 || value > 10_000) {
      throw new Error('Protocol fee bps must be 0..10000');
    }
    const signer = await provider.getSigner();
    const pool = new ethers.Contract(poolAddress, POOL_ABI, signer);
    const tx = await pool.setProtocolFeeBps(value);
    await tx.wait();
    appendLog(`Admin setProtocolFeeBps tx=${tx.hash}`);
    await loadAdminState();
  }

  async function adminSetRelayerOnlyMode() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(poolAddress)) throw new Error('Invalid pool address');
    const enabled = adminSetRelayerOnly === 'true';
    const signer = await provider.getSigner();
    const pool = new ethers.Contract(poolAddress, POOL_ABI, signer);
    const tx = await pool.setRelayerOnly(enabled);
    await tx.wait();
    appendLog(`Admin setRelayerOnly=${enabled} tx=${tx.hash}`);
    await loadAdminState();
  }

  async function adminSetApprovedRelayersOnlyMode() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(poolAddress)) throw new Error('Invalid pool address');
    const enabled = adminSetApprovedRelayersOnly === 'true';
    const signer = await provider.getSigner();
    const pool = new ethers.Contract(poolAddress, POOL_ABI, signer);
    const tx = await pool.setApprovedRelayersOnly(enabled);
    await tx.wait();
    appendLog(`Admin setApprovedRelayersOnly=${enabled} tx=${tx.hash}`);
    await loadAdminState();
  }

  async function adminSetRelayerApproval() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(poolAddress)) throw new Error('Invalid pool address');
    if (!ethers.isAddress(adminRelayerAddr)) throw new Error('Relayer address invalid');
    const approved = adminRelayerApproved === 'true';
    const signer = await provider.getSigner();
    const pool = new ethers.Contract(poolAddress, POOL_ABI, signer);
    const tx = await pool.setRelayerApproval(adminRelayerAddr, approved);
    await tx.wait();
    appendLog(`Admin setRelayerApproval ${shortHash(adminRelayerAddr, 10, 6)}=${approved} tx=${tx.hash}`);
    await loadAdminState();
  }

  async function adminSetTreasury() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(poolAddress)) throw new Error('Invalid pool address');
    if (!ethers.isAddress(adminSetTreasuryAddr)) throw new Error('Treasury address invalid');
    const signer = await provider.getSigner();
    const pool = new ethers.Contract(poolAddress, POOL_ABI, signer);
    const tx = await pool.setTreasury(adminSetTreasuryAddr);
    await tx.wait();
    appendLog(`Admin setTreasury ${shortHash(adminSetTreasuryAddr, 10, 6)} tx=${tx.hash}`);
    await loadAdminState();
  }

  async function adminSetTreasuryDelay() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(adminState?.treasury || '')) throw new Error('Treasury address unavailable');
    const delay = Number(adminWithdrawDelaySec);
    if (!Number.isFinite(delay) || delay < 0) throw new Error('Withdraw delay must be >= 0');
    const signer = await provider.getSigner();
    const treasury = new ethers.Contract(adminState.treasury, TREASURY_ABI, signer);
    const tx = await treasury.setWithdrawDelay(delay);
    await tx.wait();
    appendLog(`Treasury setWithdrawDelay=${delay}s tx=${tx.hash}`);
    await loadAdminState();
  }

  async function adminQueueTreasuryWithdrawal() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(adminState?.treasury || '')) throw new Error('Treasury address unavailable');
    if (!ethers.isAddress(adminQueueTo)) throw new Error('Queue target address invalid');
    const amountWei = ethers.parseEther(adminQueueAmountEth.trim() || '0');
    if (amountWei <= 0n) throw new Error('Queue amount must be > 0');
    const signer = await provider.getSigner();
    const treasury = new ethers.Contract(adminState.treasury, TREASURY_ABI, signer);
    const tx = await treasury.queueWithdrawal(adminQueueTo, amountWei);
    await tx.wait();
    appendLog(`Treasury queueWithdrawal to=${shortHash(adminQueueTo, 10, 6)} amount=${adminQueueAmountEth} tx=${tx.hash}`);
    await loadAdminState();
  }

  async function adminExecuteTreasuryWithdrawal() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(adminState?.treasury || '')) throw new Error('Treasury address unavailable');
    const requestId = Number(adminExecuteRequestId);
    if (!Number.isFinite(requestId) || requestId < 0) throw new Error('Request ID invalid');
    const signer = await provider.getSigner();
    const treasury = new ethers.Contract(adminState.treasury, TREASURY_ABI, signer);
    const tx = await treasury.executeWithdrawal(requestId);
    await tx.wait();
    appendLog(`Treasury executeWithdrawal id=${requestId} tx=${tx.hash}`);
    await loadAdminState();
  }

  async function connectWallet() {
    if (!provider) throw new Error('No wallet found (window.ethereum missing)');
    await window.ethereum.request({ method: 'eth_requestAccounts' });
    const signer = await provider.getSigner();
    const address = await signer.getAddress();
    const network = await provider.getNetwork();
    setWalletAddress(address);
    setWalletChainId(Number(network.chainId));
    if (!recipient) {
      setRecipient(address);
    }
    appendLog(`Wallet connected ${address}`);
    setStatus('wallet connected');
  }

  async function makeDeposit() {
    if (!provider) throw new Error('Wallet provider unavailable');
    if (!ethers.isAddress(poolAddress)) throw new Error('Invalid pool address');
    const signer = await provider.getSigner();
    const signerAddress = await signer.getAddress();
    const contract = new ethers.Contract(poolAddress, POOL_ABI, signer);
    const [denomination, balance] = await Promise.all([contract.denomination(), provider.getBalance(signerAddress)]);
    setWalletBalanceWei(balance);
    if (balance < denomination) {
      const shortfall = denomination - balance;
      throw new Error(
        `INSUFFICIENT_FUNDS_DEPOSIT: Need ${formatWeiToEth(denomination.toString())} + gas, wallet has ${formatWeiToEth(balance.toString())}, short ${formatWeiToEth(shortfall.toString())}. You already have note/root/nullifier, so continue with Withdraw via Relayer instead of another deposit.`
      );
    }

    const localNote = randHex32();
    const commitment = ethers.keccak256(localNote);
    const nf = ethers.keccak256(ethers.concat([ethers.toUtf8Bytes('nf:'), ethers.getBytes(localNote)]));

    const tx = await contract.deposit(commitment, { value: denomination });
    await tx.wait();

    const newRoot = await contract.currentRoot();
    setNote(localNote);
    setRoot(newRoot);
    setNullifierHash(nf);
    appendLog(`Deposit confirmed tx=${tx.hash} root=${newRoot}`);
    setStatus('deposit confirmed');
  }

  function deriveNullifierFromNote() {
    const cleanNote = note.trim();
    if (!cleanNote) throw new Error('Missing note');
    if (!cleanNote.startsWith('0x')) throw new Error('Note must start with 0x');
    const nf = ethers.keccak256(ethers.concat([ethers.toUtf8Bytes('nf:'), ethers.getBytes(cleanNote)]));
    setNullifierHash(nf);
    if (!(proofInput || '').trim() || proofInput === DEV_PROOF_DEFAULT) {
      try {
        setProofInput(
          ethers.keccak256(
            ethers.concat([
              ethers.toUtf8Bytes('bluearc-dev-proof-v1:'),
              ethers.getBytes(cleanNote),
              ethers.getBytes(root || ethers.ZeroHash),
              ethers.getBytes(nf)
            ])
          )
        );
      } catch (_error) {
        setProofInput(DEV_PROOF_DEFAULT);
      }
    }
    appendLog('Derived nullifier hash from note');
  }

  async function openSession() {
    const keyData = await fetchJson(relayerUrl, '/handshake/server-key', { method: 'GET' });
    const derived = await deriveSessionArtifacts(keyData);

    const openData = await fetchJson(relayerUrl, '/handshake/open', {
      method: 'POST',
      body: JSON.stringify({
        keyId: keyData.keyId,
        clientEcdhPublicKey: derived.clientPubB64,
        pqKemCiphertext: derived.pqKemCiphertextB64
      })
    });

    setSessionId(openData.sessionId);
    setSessionKeyHex(derived.sessionKeyHex);
    appendLog(`Session opened id=${openData.sessionId}`);
    setStatus('session open');
  }

  async function requestQuote() {
    if (!ethers.isAddress(poolAddress)) throw new Error('Invalid pool address');
    const data = await fetchJson(relayerUrl, '/quote', {
      method: 'POST',
      body: JSON.stringify({ pool: poolAddress })
    });
    setQuote(data.quote);
    setQuoteSignature(data.quoteSignature);
    const adjusted =
      typeof data.requestedFeeBps === 'number' &&
      typeof data.quote?.feeBps === 'number' &&
      data.quote.feeBps > data.requestedFeeBps;
    appendLog(
      `Quote fee=${formatWeiToEth(data.quote.fee)} (${data.quote.fee} wei) bps=${data.quote.feeBps} ttl=${data.ttlSec}s${
        adjusted ? ` adjusted from ${data.requestedFeeBps} bps (pool base fee floor)` : ''
      }`
    );
    setStatus('quote ready');
  }

  async function submitWithdraw() {
    if (!quote) throw new Error('Missing quote');
    if (!sessionId || !sessionKeyHex) throw new Error('Missing encrypted session');
    if (!ethers.isAddress(recipient)) throw new Error('Invalid recipient address');
    if (proofVersionMismatch) {
      throw new Error(`proof version mismatch: expected ${requiredProofVersion}`);
    }

    const payload = {
      nonce: crypto.randomUUID(),
      expiresAt: Date.now() + 60_000,
      quote,
      quoteSignature,
      pool: poolAddress,
      proofVersion: proofVersion.trim() || undefined,
      proof: parsedProof.hex,
      root,
      nullifierHash,
      recipient,
      refund: '0'
    };

    const envelope = await encryptEnvelope(sessionKeyHex, sessionId, payload);
    const data = await fetchJson(relayerUrl, '/submit', {
      method: 'POST',
      body: JSON.stringify({ sessionId, envelope })
    });

    setJobId(data.jobId);
    appendLog(`Withdrawal submitted job=${data.jobId} tx=${data.txHash}`);
    setStatus(data.status || 'pending');
  }

  async function checkStatus() {
    if (!jobId) throw new Error('No job ID');
    const data = await fetchJson(relayerUrl, `/status/${jobId}`, { method: 'GET' });
    setStatus(data.status);
    appendLog(`Job ${jobId}: ${data.status}${data.txHash ? ` tx=${data.txHash}` : ''}`);
    if (data.status === 'confirmed') {
      setLastConfirmed({
        jobId,
        txHash: data.txHash || '',
        confirmedAt: Date.now()
      });
    }
  }

  useEffect(() => {
    if (!shouldRedirectLegacyDocsPath) return;
    const path = window.location.pathname || '/docs';
    const search = window.location.search || '';
    const hash = window.location.hash || '';
    const next =
      path === '/docs' || path === '/docs/'
        ? '/doc/'
        : `/doc/docs/${path.slice('/docs/'.length)}${search}${hash}`;
    window.location.replace(next);
  }, [shouldRedirectLegacyDocsPath]);

  useEffect(() => {
    if (initRelayerLoadRef.current) return;
    initRelayerLoadRef.current = true;
    runStep('loading relayer config', loadRelayerConfig);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!relayerUrl) return;
    const handle = setTimeout(() => {
      loadRelayerConfig().catch(() => {});
    }, 300);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [relayerUrl]);

  useEffect(() => {
    if (relayerPreset === 'custom') {
      setRelayerUrl(normalizeBaseUrl(customRelayerUrl || RELAYER_DEFAULT));
      return;
    }
    const selected = RELAYER_API_OPTIONS.find((opt) => opt.id === relayerPreset);
    if (selected) {
      setRelayerUrl(normalizeBaseUrl(selected.url));
    }
  }, [relayerPreset, customRelayerUrl]);

  useEffect(() => {
    const profile = NETWORK_PROFILES[networkProfile] || NETWORK_PROFILES.sepolia;
    setDefaultPoolAddress(profile.poolAddress);
    setProofVersion(profile.proofVersion);
    if (!poolOverrideEnabled) {
      setPoolAddress(profile.poolAddress);
    }

    const profileRelayer = (profile.relayerUrl || '').trim();
    if (!profileRelayer) {
      setRelayerPreset('custom');
      setCustomRelayerUrl('');
      setRelayerUrl('');
      setRelayerMeshInput('');
      setRelayerInfo(null);
      appendLog(`Network profile set to ${profile.label}. Configure relayer URL manually for this mode.`);
      return;
    }
    const selected = RELAYER_API_OPTIONS.find(
      (opt) => normalizeBaseUrl(opt.url) === normalizeBaseUrl(profileRelayer)
    );
    if (selected) {
      setRelayerPreset(selected.id);
      setCustomRelayerUrl('');
      setRelayerUrl(normalizeBaseUrl(selected.url));
    } else {
      setRelayerPreset('custom');
      setCustomRelayerUrl(profileRelayer);
      setRelayerUrl(normalizeBaseUrl(profileRelayer));
    }
    setRelayerMeshInput(profileRelayer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [networkProfile]);

  useEffect(() => {
    if (!poolOverrideEnabled) {
      setPoolAddress(defaultPoolAddress);
      return;
    }
    const next = poolOverrideInput.trim();
    if (next) {
      setPoolAddress(next);
    }
  }, [poolOverrideEnabled, poolOverrideInput, defaultPoolAddress]);

  useEffect(() => {
    if ((proofInput || '').trim()) return;
    if (!note || !root || !nullifierHash) return;
    setProofInput(generateDevProofHex());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [note, root, nullifierHash]);

  useEffect(() => {
    if (!provider || !ethers.isAddress(poolAddress)) return;
    runStep('loading pool meta', refreshWalletPoolMeta);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider, poolAddress, walletAddress]);

  useEffect(() => {
    if (!window.ethereum) return undefined;
    const onAccountsChanged = async (accounts) => {
      const next = Array.isArray(accounts) && accounts[0] ? accounts[0] : '';
      setWalletAddress(next);
      if (!next) {
        setWalletChainId(null);
        setStatus('wallet disconnected');
        appendLog('Wallet disconnected');
        return;
      }
      try {
        if (provider) {
          const network = await provider.getNetwork();
          setWalletChainId(Number(network.chainId));
        }
      } catch (_error) {}
      appendLog(`Wallet account changed ${next}`);
    };

    const onChainChanged = async () => {
      try {
        if (provider) {
          const network = await provider.getNetwork();
          setWalletChainId(Number(network.chainId));
          appendLog(`Wallet chain changed to ${Number(network.chainId)}`);
        }
      } catch (_error) {}
    };

    window.ethereum.on('accountsChanged', onAccountsChanged);
    window.ethereum.on('chainChanged', onChainChanged);
    return () => {
      window.ethereum.removeListener('accountsChanged', onAccountsChanged);
      window.ethereum.removeListener('chainChanged', onChainChanged);
    };
  }, [provider]);

  useEffect(() => {
    if (!jobId) return undefined;
    const handle = setInterval(() => {
      fetchJson(relayerUrl, `/status/${jobId}`, { method: 'GET' })
        .then((data) => {
          setStatus(data.status);
          if (data.status === 'confirmed' || data.status === 'failed') {
            appendLog(`Job ${jobId}: ${data.status}`);
            if (data.status === 'confirmed') {
              setLastConfirmed({
                jobId,
                txHash: data.txHash || '',
                confirmedAt: Date.now()
              });
            }
            clearInterval(handle);
          }
        })
        .catch(() => {});
    }, 5000);
    return () => clearInterval(handle);
  }, [jobId, relayerUrl]);

  useEffect(() => {
    if (!monitorEnabled || relayerCandidates.length === 0) return undefined;
    refreshRelayerMesh({ silent: true });
    const handle = setInterval(() => {
      refreshRelayerMesh({ silent: true }).catch(() => {});
    }, 15000);
    return () => clearInterval(handle);
  }, [monitorEnabled, relayerCandidates]);

  useEffect(() => {
    if (lastConfirmed) {
      drawTigerBanner(tigerCanvasRef.current);
    }
  }, [lastConfirmed]);

  const chainIdForExplorer = relayerInfo?.chainId || walletChainId || 0;
  const lastTxUrl = txExplorerUrl(chainIdForExplorer, lastConfirmed?.txHash);

  if (isTigerDocsRoute) {
    return (
      <div className="page">
        <section className="testnet-banner" role="status" aria-live="polite">
          <strong>BlueARC Tiger Docs</strong> <span>Sepolia Testnet Documentation</span>
        </section>
        <header className="hero">
          <h1>BLUEARC // TIGER DOCS</h1>
          <p>Post-quantum handshake + relayered private withdrawals, explained simply.</p>
          <img
            className="hero-art"
            src="/electrictiger.png"
            alt="BlueARC electric tiger 8-bit banner art"
          />
        </header>

        <section className="panel">
          <h2>How It Works</h2>
          <p>1. Deposit fixed amount into PrivacyPoolV2 and save your note.</p>
          <p>2. Open a relayer session with hybrid ML-KEM-768 + ECDH key exchange.</p>
          <p>3. Request a signed quote (fee + expiry + chain binding).</p>
          <p>4. Submit encrypted withdraw payload (AES-GCM envelope).</p>
          <p>5. Relayer validates quote/signatures/nonce and broadcasts withdraw.</p>
        </section>

        <section className="panel">
          <h2>Security Model</h2>
          <p>On-chain public: deposit/withdraw tx metadata, timing, recipient, relayer address, fee.</p>
          <p>Protected in transit: withdraw payload via session key encryption.</p>
          <p>Critical secret: your note. Losing it means losing spend access.</p>
        </section>

        <section className="panel">
          <h2>Quick Links</h2>
          <p>
            App: <a href="/">/</a>
          </p>
          <p>
            Admin: <a href="/admin">/admin</a>
          </p>
          <p>
            Relayer Health:{' '}
            <a href="https://relayer-production-86ea.up.railway.app/health" target="_blank" rel="noreferrer">
              /health
            </a>
          </p>
        </section>
      </div>
    );
  }

  return (
    <div className="page">
      <section className={`testnet-banner ${networkProfile === 'mainnet' ? 'risk' : ''}`} role="status" aria-live="polite">
        <strong>Testnet Live. Mainnet Live At Your Own Risk.</strong>{' '}
        <span>
          Need test ETH?{' '}
          <a href="https://sepolia-faucet.pk910.de/#/" target="_blank" rel="noreferrer">
            Open Sepolia Faucet
          </a>
        </span>
      </section>
      <header className="hero">
        <h1>BLUEARC // 8BIT</h1>
        <p>On-chain privacy pool with encrypted relayed withdrawals.</p>
        <img
          className="hero-art"
          src="/electrictiger.png"
          alt="BlueARC electric tiger 8-bit banner art"
        />
      </header>

      <section className="panel">
        <h2>Network</h2>
        <label>Environment</label>
        <select value={networkProfile} onChange={(e) => setNetworkProfile(e.target.value)}>
          <option value="sepolia">Testnet | Sepolia</option>
          <option value="mainnet">Mainnet | Ethereum</option>
        </select>
        <p>
          Active profile: <strong>{NETWORK_PROFILES[networkProfile]?.label || '-'}</strong>
        </p>
        {networkProfile === 'mainnet' ? (
          <p className="hint warn">
            Mainnet mode is live-risk. Verify addresses, fees, relayer policy, and wallet chain before any action.
          </p>
        ) : null}
        <p>Default Pool (V2): <code>{defaultPoolAddress || POOL_DEFAULT}</code></p>
        <label>Relayer API</label>
        <select value={relayerPreset} onChange={(e) => setRelayerPreset(e.target.value)}>
          {RELAYER_API_OPTIONS.map((opt) => (
            <option key={opt.id} value={opt.id}>
              {opt.label}
            </option>
          ))}
          <option value="custom">Custom URL</option>
        </select>
        {relayerPreset === 'custom' ? (
          <input
            value={customRelayerUrl}
            onChange={(e) => setCustomRelayerUrl(e.target.value.trim())}
            placeholder="Custom relayer URL"
          />
        ) : null}
        <div className="row">
          <button onClick={() => runStep('loading relayer config', loadRelayerConfig)}>Load Relayer Config</button>
          <button onClick={() => runStep('connecting wallet', connectWallet)}>Connect Wallet</button>
        </div>
        <p>Wallet: {walletAddress || '-'}</p>
        <p>Wallet Balance: {walletAddress ? walletBalanceHuman : '-'}</p>
        <p>Wallet Chain: {walletChainId ?? '-'}</p>
        <p>Relayer Chain: {relayerInfo?.chainId ?? '-'}</p>
        <p>Relayer Signer: {relayerInfo?.signer || '-'}</p>
        <p>Pool Version: {displayPoolVersion}</p>
        <p>Required Proof Version: {displayRequiredProofVersion}</p>
        <p>Pool Denomination: {denominationWei > 0n ? denominationHuman : '-'}</p>
        <p>Pool Base Relayer Fee: {baseRelayerFeeWei > 0n ? baseRelayerFeeHuman : '-'}</p>
        <details>
          <summary>Advanced Network</summary>
          <div className="row">
            <label>
              <input
                type="checkbox"
                checked={poolOverrideEnabled}
                onChange={(e) => setPoolOverrideEnabled(e.target.checked)}
              />{' '}
              Override Pool Address
            </label>
          </div>
          {poolOverrideEnabled ? (
            <input
              value={poolOverrideInput}
              onChange={(e) => setPoolOverrideInput(e.target.value)}
              placeholder="Custom pool address (0x...)"
            />
          ) : null}
          <input
            value={relayerMeshInput}
            onChange={(e) => setRelayerMeshInput(e.target.value)}
            placeholder="Relayer mesh URLs (comma-separated)"
          />
        </details>
      </section>

      <section className="panel">
        <h2>Mainnet Live Notice</h2>
        <p>Network: mainnet (chainId=1)</p>
        <p>Deployer: <code>{MAINNET_DEPLOYMENT.deployer}</code></p>
        <p>ExternalVerifier (bytes backend): <code>{MAINNET_DEPLOYMENT.externalVerifier}</code></p>
        <p>PoseidonHasher: <code>{MAINNET_DEPLOYMENT.poseidonHasher}</code></p>
        <p>PqVerifierAdapter: <code>{MAINNET_DEPLOYMENT.verifierAdapter}</code></p>
        <p>PrivacyPool(v2): <code>{MAINNET_DEPLOYMENT.privacyPoolV2}</code></p>
        <p>Denomination (wei): <code>{MAINNET_DEPLOYMENT.denominationWei}</code></p>
        <p className="hint warn">Use mainnet only if you understand operational and privacy tradeoffs.</p>
      </section>

      <section className="panel">
        <h2>Relayer Monitor</h2>
        <p>
          Active: <code>{activeRelayerKey || '-'}</code>{' '}
          <span className={`badge ${activeRelayerHealth?.ok ? 'ok' : 'warn'}`}>
            {activeRelayerHealth ? (activeRelayerHealth.ok ? 'healthy' : 'unhealthy') : 'unknown'}
          </span>
        </p>
        <p>
          Last Check:{' '}
          {activeRelayerHealth?.checkedAt ? new Date(activeRelayerHealth.checkedAt).toLocaleTimeString() : '-'} | Latency:{' '}
          {activeRelayerHealth?.latencyMs != null ? `${activeRelayerHealth.latencyMs} ms` : '-'}
        </p>
        <div className="row">
          <button onClick={() => runStep('checking relayer mesh', () => refreshRelayerMesh({ silent: false }))}>
            Check Relayers Now
          </button>
          <button onClick={() => setMonitorEnabled((v) => !v)}>{monitorEnabled ? 'Pause Monitor' : 'Resume Monitor'}</button>
          <button onClick={() => runStep('switching relayer', switchToHealthyRelayer)}>Failover to Healthy Relayer</button>
        </div>
        <details>
          <summary>Relayer Mesh Status</summary>
          {relayerCandidates.length === 0 ? (
            <p>No relayer URLs configured.</p>
          ) : (
            relayerCandidates.map((url) => {
              const state = relayerMonitor[url];
              return (
                <p key={url}>
                  <code>{url}</code> |{' '}
                  <span className={`badge ${state?.ok ? 'ok' : 'warn'}`}>{state ? (state.ok ? 'healthy' : 'down') : 'unknown'}</span>{' '}
                  | {state?.latencyMs != null ? `${state.latencyMs} ms` : '-'} | chain {state?.chainId ?? '-'} | signer{' '}
                  {state?.signer ? shortHash(state.signer, 10, 6) : '-'}
                </p>
              );
            })
          )}
        </details>
        <details>
          <summary>Contingency Plan</summary>
          <p>1) Run Check Relayers Now. 2) Click Failover to Healthy Relayer. 3) Re-open session and request a fresh quote.</p>
          <p>4) If all are down, stop submits, keep note/root/nullifier safe, and retry when one relayer is healthy.</p>
        </details>
      </section>

      {isAdminRoute ? (
      <section className="panel">
        <h2>Admin Portal (/admin)</h2>
        <p>
          Pool Owner: {adminState?.poolOwner || '-'}{' '}
          <span className={`badge ${isPoolOwner ? 'ok' : 'warn'}`}>{isPoolOwner ? 'owner' : 'read-only'}</span>
        </p>
        <p>Active Signer: {effectiveUserAddress || '-'}</p>
        <p>Treasury Owner: {adminState?.treasuryOwner || '-'}</p>
        <p>Pool Balance: {adminState ? formatWeiToEth(adminState.poolBalanceWei) : '-'}</p>
        <p>Treasury Balance: {adminState ? formatWeiToEth(adminState.treasuryBalanceWei) : '-'}</p>
        <p>Base Relayer Fee: {adminState ? formatWeiToEth(adminState.baseRelayerFee) : '-'}</p>
        <p>Protocol Fee: {adminState ? `${adminState.protocolFeeBps} bps (${(adminState.protocolFeeBps / 100).toFixed(2)}%)` : '-'}</p>
        <p>relayerOnly: {adminState ? String(adminState.relayerOnly) : '-'} | approvedRelayersOnly: {adminState ? String(adminState.approvedRelayersOnly) : '-'}</p>
        <p>Treasury Delay: {adminState ? `${adminState.withdrawDelay}s` : '-'} | Next Treasury Request ID: {adminState?.nextRequestId ?? '-'}</p>
        <div className="row">
          <button onClick={() => runStep('loading admin state', loadAdminState)}>Load Admin State</button>
        </div>
        <details>
          <summary>Pool Controls (Owner)</summary>
          <div className="row">
            <input value={adminSetBaseFeeEth} onChange={(e) => setAdminSetBaseFeeEth(e.target.value.trim())} placeholder="Base relayer fee (ETH)" />
            <button disabled={!isPoolOwner} onClick={() => runStep('admin set base fee', adminSetBaseFee)}>
              Set Base Fee
            </button>
          </div>
          <div className="row">
            <input value={adminSetProtocolBps} onChange={(e) => setAdminSetProtocolBps(e.target.value.trim())} placeholder="Protocol fee (bps)" />
            <button disabled={!isPoolOwner} onClick={() => runStep('admin set protocol fee', adminSetProtocolFee)}>
              Set Protocol Fee
            </button>
          </div>
          <div className="row">
            <select value={adminSetRelayerOnly} onChange={(e) => setAdminSetRelayerOnly(e.target.value)}>
              <option value="true">relayerOnly = true</option>
              <option value="false">relayerOnly = false</option>
            </select>
            <button disabled={!isPoolOwner} onClick={() => runStep('admin set relayerOnly', adminSetRelayerOnlyMode)}>
              Apply
            </button>
          </div>
          <div className="row">
            <select value={adminSetApprovedRelayersOnly} onChange={(e) => setAdminSetApprovedRelayersOnly(e.target.value)}>
              <option value="true">approvedRelayersOnly = true</option>
              <option value="false">approvedRelayersOnly = false</option>
            </select>
            <button
              disabled={!isPoolOwner}
              onClick={() => runStep('admin set approvedRelayersOnly', adminSetApprovedRelayersOnlyMode)}
            >
              Apply
            </button>
          </div>
          <div className="row">
            <input value={adminSetTreasuryAddr} onChange={(e) => setAdminSetTreasuryAddr(e.target.value.trim())} placeholder="Treasury address (0x...)" />
            <button disabled={!isPoolOwner} onClick={() => runStep('admin set treasury', adminSetTreasury)}>
              Set Treasury
            </button>
          </div>
          <div className="row">
            <input value={adminRelayerAddr} onChange={(e) => setAdminRelayerAddr(e.target.value.trim())} placeholder="Relayer address (0x...)" />
            <select value={adminRelayerApproved} onChange={(e) => setAdminRelayerApproved(e.target.value)}>
              <option value="true">approved</option>
              <option value="false">not approved</option>
            </select>
            <button disabled={!isPoolOwner} onClick={() => runStep('admin set relayer approval', adminSetRelayerApproval)}>
              Set Relayer Approval
            </button>
          </div>
          <p>Selected relayer approved: {adminState?.relayerApproved == null ? '-' : String(adminState.relayerApproved)}</p>
        </details>
        <details>
          <summary>Treasury Controls (Owner)</summary>
          <div className="row">
            <input value={adminWithdrawDelaySec} onChange={(e) => setAdminWithdrawDelaySec(e.target.value.trim())} placeholder="Withdraw delay seconds" />
            <button disabled={!isTreasuryOwner} onClick={() => runStep('treasury set delay', adminSetTreasuryDelay)}>
              Set Delay
            </button>
          </div>
          <div className="row">
            <input value={adminQueueTo} onChange={(e) => setAdminQueueTo(e.target.value.trim())} placeholder="Queue to address (0x...)" />
            <input value={adminQueueAmountEth} onChange={(e) => setAdminQueueAmountEth(e.target.value.trim())} placeholder="Queue amount (ETH)" />
            <button disabled={!isTreasuryOwner} onClick={() => runStep('treasury queue withdrawal', adminQueueTreasuryWithdrawal)}>
              Queue Withdrawal
            </button>
          </div>
          <div className="row">
            <input value={adminExecuteRequestId} onChange={(e) => setAdminExecuteRequestId(e.target.value.trim())} placeholder="Request ID" />
            <button
              disabled={!isTreasuryOwner}
              onClick={() => runStep('treasury execute withdrawal', adminExecuteTreasuryWithdrawal)}
            >
              Execute Withdrawal
            </button>
          </div>
        </details>
      </section>
      ) : (
        <section className="panel">
          <h2>Admin</h2>
          <p>Admin controls are hidden from the public flow.</p>
          <p>
            Open <a href="/admin">/admin</a> with your owner wallet connected to manage pool and treasury controls.
          </p>
        </section>
      )}

      <section className="panel">
        <h2>Security & Risk</h2>
        <details open>
          <summary>What is secure in this flow</summary>
          <p>
            Withdraw payloads sent to the relayer are encrypted in transit with a hybrid session key (ECDH + ML-KEM),
            and on-chain withdraw validity is enforced by root/nullifier/proof checks in the pool contract.
          </p>
          <p>
            Your note is the spend secret. Anyone without the note cannot generate a valid spend path for that deposit.
          </p>
        </details>
        <details>
          <summary>What data is public / at risk</summary>
          <p>
            Ethereum is public. Deposit/withdraw transactions, timestamps, gas patterns, recipient, relayer address, and
            fees are observable metadata.
          </p>
          <p>
            The relayer decrypts submit payloads to broadcast them, so a relayer operator can see payload fields for jobs
            they process.
          </p>
        </details>
        <details>
          <summary>Operational safety rules</summary>
          <p>
            Keep notes offline and backed up. Reusing addresses, withdrawing immediately after deposit, or repeated exact
            behavior patterns can reduce privacy.
          </p>
          <p>
            Prefer relayed withdrawals, vary timing where possible, and verify chain/network before submitting.
          </p>
        </details>
        <details>
          <summary>Future: BlueArc-v3</summary>
          <p>
            BlueArc-v3 is planned to incorporate deeper on-chain ZK proof workflows, stronger proof system integration,
            and additional protocol hardening beyond the current release.
          </p>
        </details>
      </section>

      <section className="panel grid">
        <div>
          <h2>Deposit</h2>
          <button disabled={!canDeposit} onClick={() => runStep('depositing', makeDeposit)}>
            Deposit Fixed Amount
          </button>
          {walletAddress && denominationWei > 0n ? (
            <p className={`hint ${hasDepositFunds ? 'ok' : 'warn'}`}>
              {hasDepositFunds
                ? `Ready to deposit ${denominationHuman} (+ gas).`
                : `Insufficient ETH for a new deposit. Short by ${depositShortfallHuman} (+ gas).`}
            </p>
          ) : null}
          {!hasDepositFunds && denominationWei > 0n && walletAddress ? (
            <p className="hint warn">Need {denominationHuman} + gas. Current wallet balance is {walletBalanceHuman}.</p>
          ) : null}
          {hasWithdrawInputs ? (
            <p className="hint action">
              {'Deposit data is ready. Continue with Withdraw via Relayer: Open Session -> Get Quote -> Submit Encrypted.'}
            </p>
          ) : (
            <p className="hint">After deposit confirms, this app fills Note, Root, and Nullifier automatically.</p>
          )}
          <input value={note} onChange={(e) => setNote(e.target.value.trim())} placeholder="Note (0x...)" />
          <input value={root} onChange={(e) => setRoot(e.target.value.trim())} placeholder="Merkle Root (0x...)" />
          <div className="row">
            <input value={nullifierHash} onChange={(e) => setNullifierHash(e.target.value.trim())} placeholder="Nullifier Hash (0x...)" />
            <button onClick={() => runStep('deriving nullifier', deriveNullifierFromNote)}>Derive from Note</button>
          </div>
        </div>

        <div>
          <h2>Withdraw via Relayer</h2>
          <input value={recipient} onChange={(e) => setRecipient(e.target.value.trim())} placeholder="Recipient 0x..." />
          <textarea
            value={proofInput}
            onChange={(e) => setProofInput(e.target.value)}
            placeholder="Proof input: hex (0x...), base64:<...>, or plain text"
          />
          <input
            value={proofVersion}
            onChange={(e) => setProofVersion(e.target.value.trim())}
            placeholder="Proof version (example: bluearc-v2)"
          />
          {proofVersionMismatch ? (
            <p className="hint warn">Proof version mismatch. Required: {requiredProofVersion}</p>
          ) : null}
          <div className="row">
            <button onClick={() => setProofInput(DEV_PROOF_DEFAULT)}>Use Dev Proof ({DEV_PROOF_DEFAULT})</button>
            <button onClick={() => setProofInput(generateDevProofHex())}>Generate Dev Proof From Inputs</button>
            <button onClick={() => setProofInput('')}>Clear Proof</button>
          </div>
          <p className={`hint ${proofInfo.valid ? 'ok' : 'warn'}`}>Proof Size: {proofInfo.message}</p>
          <p className="hint">
            Submit Hex: {parsedProof.ok ? parsedProof.hex : '-'}
          </p>
          <div className="row">
            <button disabled={!canOpenSession} onClick={() => runStep('opening session', openSession)}>
              Open Session
            </button>
            <button disabled={!canQuote} onClick={() => runStep('requesting quote', requestQuote)}>
              Get Quote
            </button>
            <button disabled={!canSubmit} onClick={() => runStep('submitting withdraw', submitWithdraw)}>
              Submit Encrypted
            </button>
          </div>
          <p>Session: {sessionId || '-'}</p>
          <p>Quote ID: {quote?.quoteId || '-'}</p>
          <p>Quote Fee: {quote ? `${quoteFeeHuman} (${quote.fee} wei)` : '-'}</p>
          <p>Quote Rate: {quote ? `${quote.feeBps} bps (${(quote.feeBps / 100).toFixed(2)}%)` : '-'}</p>
          <p>Job ID: {jobId || '-'}</p>
          <button disabled={!jobId} onClick={() => runStep('checking status', checkStatus)}>
            Check Status
          </button>
        </div>
      </section>

      <section className="panel">
        <h2>Console</h2>
        <p>Status: {status}</p>
        <pre>{log || 'No logs yet.'}</pre>
      </section>

      {lastConfirmed ? (
        <section className="panel" aria-live="polite">
          <h2>Last Confirmed Withdrawal</h2>
          <canvas
            ref={tigerCanvasRef}
            width={480}
            height={180}
            style={{ width: '100%', maxWidth: 640, border: '2px solid #1ed2ff', imageRendering: 'pixelated' }}
          />
          <p>Job: {lastConfirmed.jobId}</p>
          <p>Tx: {shortHash(lastConfirmed.txHash)}</p>
          <p>Confirmed: {new Date(lastConfirmed.confirmedAt).toLocaleString()}</p>
          {lastTxUrl ? (
            <p>
              Explorer:{' '}
              <a href={lastTxUrl} target="_blank" rel="noreferrer">
                Open Transaction
              </a>
            </p>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}
