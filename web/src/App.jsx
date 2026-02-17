import { useMemo, useState } from 'react';
import { ethers } from 'ethers';

const POOL_ABI = [
  'function deposit(bytes32 commitment) payable',
  'function currentRoot() view returns (bytes32)',
  'function denomination() view returns (uint256)'
];

const RELAYER_DEFAULT = 'http://127.0.0.1:8080';

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

async function deriveSessionKey(serverPubB64, pqSecretBytes) {
  const clientKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const clientPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', clientKeyPair.publicKey));
  const serverPubRaw = b64ToBytes(serverPubB64);
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
  const concat = new Uint8Array(classicalSecret.length + pqSecretBytes.length);
  concat.set(classicalSecret, 0);
  concat.set(pqSecretBytes, classicalSecret.length);

  const sessionHash = await crypto.subtle.digest('SHA-256', concat);
  const sessionKeyBytes = new Uint8Array(sessionHash);

  return {
    clientPubB64: bytesToB64(clientPubRaw),
    pqSecretB64: bytesToB64(pqSecretBytes),
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
  const [poolAddress, setPoolAddress] = useState('');
  const [relayerUrl, setRelayerUrl] = useState(RELAYER_DEFAULT);
  const [recipient, setRecipient] = useState('');
  const [note, setNote] = useState('');
  const [root, setRoot] = useState('');
  const [nullifierHash, setNullifierHash] = useState('');
  const [proof, setProof] = useState('0x1234');
  const [quote, setQuote] = useState(null);
  const [quoteSignature, setQuoteSignature] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [sessionKeyHex, setSessionKeyHex] = useState('');
  const [jobId, setJobId] = useState('');
  const [status, setStatus] = useState('idle');
  const [log, setLog] = useState('');

  const provider = useMemo(() => new ethers.BrowserProvider(window.ethereum), []);

  async function connectWallet() {
    if (!window.ethereum) throw new Error('No wallet found');
    await window.ethereum.request({ method: 'eth_requestAccounts' });
    setStatus('wallet connected');
  }

  async function makeDeposit() {
    const signer = await provider.getSigner();
    const contract = new ethers.Contract(poolAddress, POOL_ABI, signer);
    const denomination = await contract.denomination();

    const localNote = randHex32();
    const commitment = ethers.keccak256(localNote);
    const nf = ethers.keccak256(ethers.concat([ethers.toUtf8Bytes('nf:'), ethers.getBytes(localNote)]));

    const tx = await contract.deposit(commitment, { value: denomination });
    await tx.wait();

    const newRoot = await contract.currentRoot();

    setNote(localNote);
    setRoot(newRoot);
    setNullifierHash(nf);
    setLog(`Deposit confirmed. tx=${tx.hash}`);
  }

  async function openSession() {
    const keyResp = await fetch(`${relayerUrl}/handshake/server-key`);
    const keyData = await keyResp.json();
    if (!keyResp.ok) throw new Error(JSON.stringify(keyData));

    const pqSecret = crypto.getRandomValues(new Uint8Array(32));
    const derived = await deriveSessionKey(keyData.serverEcdhPublicKey, pqSecret);

    const openResp = await fetch(`${relayerUrl}/handshake/open`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientEcdhPublicKey: derived.clientPubB64,
        pqSharedSecret: derived.pqSecretB64
      })
    });

    const openData = await openResp.json();
    if (!openResp.ok) throw new Error(openData.error || 'handshake failed');

    setSessionId(openData.sessionId);
    setSessionKeyHex(derived.sessionKeyHex);
    setLog(`Session opened. mode=${openData.submitMode}`);
  }

  async function requestQuote() {
    const resp = await fetch(`${relayerUrl}/quote`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pool: poolAddress })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(JSON.stringify(data));
    setQuote(data.quote);
    setQuoteSignature(data.quoteSignature);
    setLog(`Quote fee=${data.quote.fee} signer=${data.signer}`);
  }

  async function submitWithdraw() {
    const nonce = crypto.randomUUID();
    const expiresAt = Date.now() + 60_000;
    const payload = {
      nonce,
      expiresAt,
      quote,
      quoteSignature,
      pool: poolAddress,
      proof,
      root,
      nullifierHash,
      recipient,
      refund: '0'
    };

    const envelope = await encryptEnvelope(sessionKeyHex, sessionId, payload);

    const resp = await fetch(`${relayerUrl}/submit`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId, envelope })
    });

    const data = await resp.json();
    if (!resp.ok) throw new Error(JSON.stringify(data));

    setJobId(data.jobId);
    setLog(`Withdrawal submitted tx=${data.txHash}`);
  }

  async function checkStatus() {
    const resp = await fetch(`${relayerUrl}/status/${jobId}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(JSON.stringify(data));
    setStatus(data.status);
    setLog(JSON.stringify(data, null, 2));
  }

  return (
    <div className="page">
      <header className="hero">
        <h1>BLUEARC // 8BIT</h1>
        <p>On-chain privacy pool with encrypted relayed withdrawals.</p>
      </header>

      <section className="panel">
        <h2>Network</h2>
        <input value={poolAddress} onChange={(e) => setPoolAddress(e.target.value)} placeholder="Pool address" />
        <input value={relayerUrl} onChange={(e) => setRelayerUrl(e.target.value)} placeholder="Relayer URL" />
        <button onClick={connectWallet}>Connect Wallet</button>
      </section>

      <section className="panel grid">
        <div>
          <h2>Deposit</h2>
          <button onClick={makeDeposit}>Deposit Fixed Amount</button>
          <p>Note: {note || '-'}</p>
          <p>Root: {root || '-'}</p>
          <p>Nullifier: {nullifierHash || '-'}</p>
        </div>

        <div>
          <h2>Withdraw via Relayer</h2>
          <input value={recipient} onChange={(e) => setRecipient(e.target.value)} placeholder="Recipient 0x..." />
          <input value={proof} onChange={(e) => setProof(e.target.value)} placeholder="Proof bytes hex" />
          <div className="row">
            <button onClick={openSession}>Open Session</button>
            <button onClick={requestQuote}>Get Quote</button>
            <button onClick={submitWithdraw}>Submit Encrypted</button>
          </div>
          <p>Session: {sessionId || '-'}</p>
          <p>Quote ID: {quote?.quoteId || '-'}</p>
          <p>Job ID: {jobId || '-'}</p>
          <button onClick={checkStatus}>Check Status</button>
        </div>
      </section>

      <section className="panel">
        <h2>Console</h2>
        <p>Status: {status}</p>
        <pre>{log}</pre>
      </section>
    </div>
  );
}
