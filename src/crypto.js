const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');

function toBase64Url(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return buf.toString('base64url');
}

function fromBase64Url(base64urlStr) {
  return Buffer.from(base64urlStr, 'base64url');
}

function normalizeDomain(rawDomain) {
  if (!rawDomain) return '';
  let str = String(rawDomain).trim().toLowerCase();
  if (str === '*') return '*';
  // Remove protocol
  str = str.replace(/^[a-z]+:\/\//i, '');
  // Remove path, query string, hash
  str = str.split('/')[0].split('?')[0].split('#')[0];
  // Remove port
  str = str.split(':')[0];
  // Remove leading www.
  str = str.replace(/^www\./i, '');
  return str;
}

function ensureKeysDirectory() {
  if (!fs.existsSync(config.keysDir)) {
    fs.mkdirSync(config.keysDir, { recursive: true, mode: 0o700 });
  }
}

function initKeypair() {
  ensureKeysDirectory();

  const privateKeyExists = fs.existsSync(config.keyPath);
  const publicKeyExists = fs.existsSync(config.publicKeyPath);

  if (!privateKeyExists || !publicKeyExists) {
    if (!config.autoGenerateKeys && !privateKeyExists) {
      throw new Error(`Private key not found at ${config.keyPath} and AUTO_GENERATE_KEYS is false`);
    }

    // Generate 2048-bit RSA key pair
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    // Write private key with 0600 permissions
    fs.writeFileSync(config.keyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(config.publicKeyPath, publicKey, { mode: 0o644 });

    console.log(`[crypto] Generated new RSA keypair at ${config.keyPath} and ${config.publicKeyPath}`);
  }
}

function getPrivateKey() {
  if (!fs.existsSync(config.keyPath)) {
    initKeypair();
  }
  return fs.readFileSync(config.keyPath, 'utf8');
}

function getPublicKey() {
  if (!fs.existsSync(config.publicKeyPath)) {
    initKeypair();
  }
  return fs.readFileSync(config.publicKeyPath, 'utf8');
}

function checkKeypair() {
  try {
    const priv = getPrivateKey();
    const pub = getPublicKey();
    const nonce = Buffer.from('keypair_check_nonce_' + Date.now());
    const sig = crypto.sign('sha256', nonce, priv);
    return crypto.verify('sha256', nonce, pub, sig);
  } catch {
    return false;
  }
}

/**
 * Sign raw data (string or object) with RSA-SHA256 and produce the payload.signature format
 */
function signLicense(payloadObject) {
  const privateKey = getPrivateKey();
  const publicKey = getPublicKey();
  const raw = typeof payloadObject === 'string' ? payloadObject : JSON.stringify(payloadObject);

  const sig = crypto.sign('sha256', Buffer.from(raw, 'utf8'), privateKey);

  // Self-verification check before key leaves server (P0 auto-contrôle)
  const isOk = crypto.verify('sha256', Buffer.from(raw, 'utf8'), publicKey, sig);
  if (!isOk) {
    throw new Error('Emission refusée : private.pem ne correspond pas à public.pem');
  }

  const payloadB64 = toBase64Url(raw);
  const signatureB64 = toBase64Url(sig);
  const key = `${payloadB64}.${signatureB64}`;

  return {
    raw,
    payload: payloadB64,
    signature: signatureB64,
    key
  };
}

/**
 * Sign an envelope for CRL or update manifests:
 * { "payload": "<base64url(raw)>", "signature": "<base64url(sig)>" }
 */
function signEnvelope(dataObject) {
  const privateKey = getPrivateKey();
  const publicKey = getPublicKey();
  const raw = typeof dataObject === 'string' ? dataObject : JSON.stringify(dataObject);

  const sig = crypto.sign('sha256', Buffer.from(raw, 'utf8'), privateKey);

  // Self-verification check before envelope leaves server
  const isOk = crypto.verify('sha256', Buffer.from(raw, 'utf8'), publicKey, sig);
  if (!isOk) {
    throw new Error('Emission refusée : private.pem ne correspond pas à public.pem');
  }

  return {
    payload: toBase64Url(raw),
    signature: toBase64Url(sig)
  };
}

/**
 * Verify signed license key (payload.signature)
 */
function verifyLicenseKey(licenseKey) {
  if (!licenseKey || typeof licenseKey !== 'string') {
    return { valid: false, error: 'Invalid key format' };
  }

  const parts = licenseKey.trim().split('.');
  if (parts.length !== 2) {
    return { valid: false, error: 'Key must have payload.signature structure' };
  }

  const [payloadB64, signatureB64] = parts;

  try {
    const raw = fromBase64Url(payloadB64).toString('utf8');
    const sig = fromBase64Url(signatureB64);
    const publicKey = getPublicKey();

    const verifier = crypto.createVerify('SHA256');
    verifier.update(raw);
    const isSignatureValid = verifier.verify(publicKey, sig);

    if (!isSignatureValid) {
      return { valid: false, error: 'Signature verification failed' };
    }

    const payload = JSON.parse(raw);
    return {
      valid: true,
      raw,
      payload
    };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

/**
 * Verify signed envelope { payload, signature }
 */
function verifyEnvelope(envelope) {
  if (!envelope || !envelope.payload || !envelope.signature) {
    return { valid: false, error: 'Invalid envelope structure' };
  }

  try {
    const raw = fromBase64Url(envelope.payload).toString('utf8');
    const sig = fromBase64Url(envelope.signature);
    const publicKey = getPublicKey();

    const verifier = crypto.createVerify('SHA256');
    verifier.update(raw);
    const isSignatureValid = verifier.verify(publicKey, sig);

    if (!isSignatureValid) {
      return { valid: false, error: 'Signature verification failed' };
    }

    const data = JSON.parse(raw);
    return { valid: true, data, raw };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

function sha256File(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function sha256Buffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

module.exports = {
  toBase64Url,
  fromBase64Url,
  normalizeDomain,
  initKeypair,
  checkKeypair,
  getPrivateKey,
  getPublicKey,
  signLicense,
  signEnvelope,
  verifyLicenseKey,
  verifyEnvelope,
  sha256File,
  sha256Buffer
};
