const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const app = require('../src/server');
const db = require('../src/db');
const { signLicense, initKeypair } = require('../src/crypto');

describe('API Endpoints', () => {
  let server;
  let port;
  let baseUrl;

  before(async () => {
    initKeypair();
    db.getDb();
    server = http.createServer(app);
    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it('GET / returns HTML dashboard', async () => {
    const res = await fetch(`${baseUrl}/`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('RGAA Audit'));
    assert.ok(html.includes('licenses-table'));
  });

  it('Web UI API: POST /api/licenses creates license and returns signed key', async () => {
    const res = await fetch(`${baseUrl}/api/licenses`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'webuser@example.com',
        plan: 'solo',
        sites: 1,
        domain: 'webtest.fr',
        expires: '2029-10-10'
      })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.ok, true);
    assert.ok(data.key.includes('.'));
    assert.equal(data.license.domain, 'webtest.fr');
  });

  it('Web UI API: GET /api/licenses lists licenses with keys', async () => {
    const res = await fetch(`${baseUrl}/api/licenses`);
    assert.equal(res.status, 200);
    const list = await res.json();
    assert.ok(Array.isArray(list));
    assert.ok(list.some(l => l.domain === 'webtest.fr' && l.key));
  });

  it('Web UI API: GET /api/stats returns counts', async () => {
    const res = await fetch(`${baseUrl}/api/stats`);
    assert.equal(res.status, 200);
    const stats = await res.json();
    assert.ok(typeof stats.total === 'number');
    assert.ok(typeof stats.active === 'number');
  });

  it('GET /healthz returns ok and db status', async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.ok, true);
    assert.equal(data.db, true);
  });

  it('GET /v1/public-key returns PEM public key', async () => {
    const res = await fetch(`${baseUrl}/v1/public-key`);
    assert.equal(res.status, 200);
    const text = await res.text();
    assert.ok(text.includes('BEGIN PUBLIC KEY'));
  });

  it('POST /v1/activate validates active license', async () => {
    const licenseId = 'test-lic-' + Date.now();
    db.createLicense({
      id: licenseId,
      email: 'client@example.com',
      plan: 'solo',
      sites: 1,
      domain: 'mywebsite.fr',
      expires_at: '2029-12-31',
      status: 'active'
    });

    const signed = signLicense({
      id: licenseId,
      license_id: licenseId,
      plan: 'solo',
      sites: 1,
      domain: 'mywebsite.fr',
      expires: '2029-12-31'
    });

    const res = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: signed.key,
        domain: 'https://www.mywebsite.fr/wp-admin',
        plugin_version: '0.2.0'
      })
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.valid, true);
    assert.equal(body.plan, 'solo');
    assert.ok(body.next_update);
  });

  it('POST /v1/activate rejects domain mismatch', async () => {
    const licenseId = 'test-mismatch-' + Date.now();
    db.createLicense({
      id: licenseId,
      email: 'client@example.com',
      plan: 'solo',
      sites: 1,
      domain: 'authorized.com',
      expires_at: '2029-12-31',
      status: 'active'
    });

    const signed = signLicense({
      id: licenseId,
      license_id: licenseId,
      plan: 'solo',
      sites: 1,
      domain: 'authorized.com',
      expires: '2029-12-31'
    });

    const res = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: signed.key,
        domain: 'otherdomain.org',
        plugin_version: '0.2.0'
      })
    });

    assert.equal(res.status, 409);
    const body = await res.json();
    assert.equal(body.error, 'domain_mismatch');
  });

  it('POST /v1/activate rejects revoked license', async () => {
    const licenseId = 'test-revoked-' + Date.now();
    db.createLicense({
      id: licenseId,
      email: 'client@example.com',
      plan: 'solo',
      sites: 1,
      domain: 'site.fr',
      expires_at: '2029-12-31',
      status: 'active'
    });

    const signed = signLicense({
      id: licenseId,
      license_id: licenseId,
      plan: 'solo',
      sites: 1,
      domain: 'site.fr',
      expires: '2029-12-31'
    });

    // Revoke license
    db.updateLicenseStatus(licenseId, 'revoked', 'chargeback');

    const res = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: signed.key,
        domain: 'site.fr',
        plugin_version: '0.2.0'
      })
    });

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.error, 'license_revoked');
  });

  it('GET /v1/crl returns signed CRL with revoked licenses', async () => {
    const res = await fetch(`${baseUrl}/v1/crl`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.payload);
    assert.ok(body.signature);

    const crl = JSON.parse(Buffer.from(body.payload, 'base64url').toString('utf8'));
    assert.equal(crl.version, 1);
    assert.ok(Array.isArray(crl.revoked));
    assert.ok(crl.revoked.some(r => r.reason === 'chargeback'));
  });

  it('POST /v1/webhook/polar handles idempotency', async () => {
    const eventId = 'evt_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        customer_email: 'buyer@test.org',
        plan: 'agence',
        sites: 5,
        domain: 'agency-site.com',
        order_id: 'ord_' + Date.now()
      }
    };

    // First request
    const res1 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    assert.equal(res1.status, 200);
    const b1 = await res1.json();
    assert.equal(b1.status, 'license_issued');

    // Second request with same event ID (replay)
    const res2 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    assert.equal(res2.status, 200);
    const b2 = await res2.json();
    assert.equal(b2.status, 'already_processed');
  });
});
