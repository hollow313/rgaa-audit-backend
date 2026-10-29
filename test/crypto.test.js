const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeDomain,
  signLicense,
  verifyLicenseKey,
  signEnvelope,
  verifyEnvelope,
  toBase64Url,
  fromBase64Url
} = require('../src/crypto');

describe('Crypto Module', () => {
  it('should correctly normalize domains', () => {
    assert.equal(normalizeDomain('https://www.exemple.fr'), 'exemple.fr');
    assert.equal(normalizeDomain('http://www.exemple.fr:8080/path/sub'), 'exemple.fr');
    assert.equal(normalizeDomain('WWW.TEST.COM'), 'test.com');
    assert.equal(normalizeDomain('sub.domain.org/wp-admin'), 'sub.domain.org');
    assert.equal(normalizeDomain('*'), '*');
    assert.equal(normalizeDomain(''), '');
  });

  it('should encode and decode base64url without padding', () => {
    const text = 'test+string/with=chars';
    const b64url = toBase64Url(text);
    assert.ok(!b64url.includes('+'));
    assert.ok(!b64url.includes('/'));
    assert.ok(!b64url.includes('='));

    const decoded = fromBase64Url(b64url).toString('utf8');
    assert.equal(decoded, text);
  });

  it('should sign and verify a license key', () => {
    const raw = {
      plan: 'solo',
      sites: 1,
      expires: '2028-01-01',
      domain: 'exemple.fr'
    };

    const signed = signLicense(raw);
    assert.ok(signed.key.includes('.'));

    const verifyResult = verifyLicenseKey(signed.key);
    assert.equal(verifyResult.valid, true);
    assert.equal(verifyResult.payload.plan, 'solo');
    assert.equal(verifyResult.payload.domain, 'exemple.fr');
  });

  it('should reject tampered license key payload', () => {
    const raw = {
      plan: 'solo',
      sites: 1,
      expires: '2028-01-01',
      domain: 'exemple.fr'
    };

    const signed = signLicense(raw);
    const [payloadB64, sigB64] = signed.key.split('.');

    // Tamper with payload (change plan to agence)
    const tamperedPayload = JSON.stringify({
      ...raw,
      plan: 'agence'
    });
    const tamperedPayloadB64 = toBase64Url(tamperedPayload);
    const tamperedKey = `${tamperedPayloadB64}.${sigB64}`;

    const verifyResult = verifyLicenseKey(tamperedKey);
    assert.equal(verifyResult.valid, false);
  });

  it('should sign and verify signed envelope for CRL / manifest', () => {
    const crlData = {
      version: 1,
      issued_at: new Date().toISOString(),
      revoked: [{ license_id: '123', revoked_at: new Date().toISOString(), reason: 'refund' }]
    };

    const envelope = signEnvelope(crlData);
    assert.ok(envelope.payload);
    assert.ok(envelope.signature);

    const verified = verifyEnvelope(envelope);
    assert.equal(verified.valid, true);
    assert.equal(verified.data.version, 1);
    assert.equal(verified.data.revoked[0].license_id, '123');
  });
});
