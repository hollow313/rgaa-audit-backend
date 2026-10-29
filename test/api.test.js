const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const app = require('../src/server');
const db = require('../src/db');
const config = require('../src/config');
const { signLicense, initKeypair } = require('../src/crypto');

function makeWebhookHeaders(provider, payload, secret, options = {}) {
  const timestamp = options.timestamp !== undefined ? options.timestamp : Math.floor(Date.now() / 1000);
  const rawBody = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const delimiter = provider === 'paddle' ? ':' : '.';
  const signString = `${timestamp}${delimiter}${rawBody}`;
  const sig = options.badSignature ? 'deadbeef1234' : crypto.createHmac('sha256', secret).update(signString).digest('hex');

  const headers = { 'Content-Type': 'application/json' };
  if (options.noHeaders) return headers;

  if (provider === 'paddle') {
    headers['paddle-signature'] = `ts=${timestamp};h1=${sig}`;
  } else {
    headers['webhook-timestamp'] = String(timestamp);
    headers['webhook-signature'] = `v1=${sig}`;
  }
  return headers;
}

describe('API Endpoints', () => {
  let server;
  let port;
  let baseUrl;

  before(async () => {
    config.polarWebhookSecret = 'test_polar_secret_key_12345';
    config.paddleWebhookSecret = 'test_paddle_secret_key_12345';
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

  /* ----------------------------------------------------
     P0 Tests: Webhook HMAC security, timestamp window & idempotency
  ---------------------------------------------------- */
  it('P0: POST /v1/webhook/polar rejects anonymous request without signature headers with 401', async () => {
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 'evt_no_sig', type: 'order.paid' })
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, 'unauthorized');
  });

  it('P0: POST /v1/webhook/polar rejects invalid signature with 401', async () => {
    const payload = { id: 'evt_bad_sig', type: 'order.paid' };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret, { badSignature: true });
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 401);
  });

  it('P0: POST /v1/webhook/polar rejects expired timestamp (> 300 s) with 401', async () => {
    const payload = { id: 'evt_expired_ts', type: 'order.paid' };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret, { timestamp: 1 });
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 401);
  });

  it('P0: POST /v1/webhook/polar accepts valid signature and creates a single license', async () => {
    const eventId = 'evt_valid_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        customer_email: 'buyer@test.org',
        plan: 'solo',
        sites: 1,
        domain: 'polar-test.org',
        order_id: 'ord_p0_' + Date.now()
      }
    };

    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res1 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res1.status, 200);
    const b1 = await res1.json();
    assert.equal(b1.status, 'license_issued');
    assert.ok(b1.id);

    // Replay with identical event ID
    const res2 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res2.status, 200);
    const b2 = await res2.json();
    assert.equal(b2.status, 'already_processed');
  });

  it('P0: POST /v1/webhook/paddle enforces HMAC and accepts valid signature', async () => {
    const payload = {
      event_id: 'pdl_evt_' + Date.now(),
      event_type: 'transaction.completed',
      data: {
        customer: { email: 'paddle-user@test.org' },
        custom_data: { plan: 'solo', sites: 1, domain: 'paddle-site.com' },
        id: 'txn_' + Date.now()
      }
    };

    // Anonymous should be rejected with 401
    const resNoSig = await fetch(`${baseUrl}/v1/webhook/paddle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    assert.equal(resNoSig.status, 401);

    // Valid signature should succeed with 200
    const headers = makeWebhookHeaders('paddle', payload, config.paddleWebhookSecret);
    const resValid = await fetch(`${baseUrl}/v1/webhook/paddle`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(resValid.status, 200);
    const bValid = await resValid.json();
    assert.equal(bValid.status, 'license_issued');
  });

  it('P0: Security test licenses from audit recipe are revoked', () => {
    const id1 = '24fcfea8-238f-4f67-8366-f11ffd673f2b';
    const id2 = '2b263539-976d-401e-bee1-ee8451ab2f21';

    // Even if inserted, db.revokeSecurityTestLicenses() marks them revoked
    db.createLicense({
      id: id1,
      email: 'test@example.com',
      domain: 'test.fr',
      expires_at: '2030-01-01',
      status: 'active'
    });
    db.revokeSecurityTestLicenses();

    const lic1 = db.getLicenseById(id1);
    assert.equal(lic1.status, 'revoked');
    assert.equal(lic1.revoke_reason, 'security-test');
  });

  /* ----------------------------------------------------
     Expiration & Revocation Policy on Updates Manifest
  ---------------------------------------------------- */
  it('Policy: GET /v1/updates rejects expired license with 403 license_expired', async () => {
    const expLicenseId = 'test-exp-' + Date.now();
    db.createLicense({
      id: expLicenseId,
      email: 'expired@test.fr',
      plan: 'solo',
      sites: 1,
      domain: 'expired.fr',
      expires_at: '2020-01-01',
      status: 'active'
    });

    const signed = signLicense({
      id: expLicenseId,
      plan: 'solo',
      sites: 1,
      domain: 'expired.fr',
      expires: '2020-01-01'
    });

    const res = await fetch(`${baseUrl}/v1/updates?key=${signed.key}`);
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.error, 'license_expired');
  });

  it('Policy: GET /v1/updates rejects revoked license with 403 license_revoked', async () => {
    const revLicenseId = 'test-rev-upd-' + Date.now();
    db.createLicense({
      id: revLicenseId,
      email: 'rev@test.fr',
      plan: 'solo',
      sites: 1,
      domain: 'rev.fr',
      expires_at: '2029-01-01',
      status: 'revoked'
    });

    const signed = signLicense({
      id: revLicenseId,
      plan: 'solo',
      sites: 1,
      domain: 'rev.fr',
      expires: '2029-01-01'
    });

    const res = await fetch(`${baseUrl}/v1/updates?key=${signed.key}`);
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.error, 'license_revoked');
  });

  /* ----------------------------------------------------
     B-01 Tests: Route aliases & JSON 404/500
  ---------------------------------------------------- */
  it('B-01: GET /v1/updates and /v1/updates/rgaa-audit return identical response bytes and status', async () => {
    const res1 = await fetch(`${baseUrl}/v1/updates`);
    const res2 = await fetch(`${baseUrl}/v1/updates/rgaa-audit`);

    assert.equal(res1.status, res2.status);
    assert.equal(res1.headers.get('content-type'), res2.headers.get('content-type'));

    const text1 = await res1.text();
    const text2 = await res2.text();
    assert.equal(text1, text2, 'Both routes must return the exact same response body octet for octet');
  });

  it('B-01: Non-existent route returns 404 with JSON { "error": "not_found" }', async () => {
    const res = await fetch(`${baseUrl}/inexistant`);
    assert.equal(res.status, 404);
    assert.ok(res.headers.get('content-type')?.includes('application/json'));
    const body = await res.json();
    assert.deepEqual(body, { error: 'not_found' });
  });

  /* ----------------------------------------------------
     B-02 Tests: CRL caching, stable ETag & 304 Not Modified
  ---------------------------------------------------- */
  it('B-02: Consecutive GET /v1/crl calls return identical ETag and payload', async () => {
    const res1 = await fetch(`${baseUrl}/v1/crl`);
    const etag1 = res1.headers.get('etag');
    const body1 = await res1.text();

    const res2 = await fetch(`${baseUrl}/v1/crl`);
    const etag2 = res2.headers.get('etag');
    const body2 = await res2.text();

    assert.ok(etag1, 'ETag must be present');
    assert.equal(etag1, etag2, 'ETags must be identical on consecutive calls');
    assert.equal(body1, body2, 'Body must be identical on consecutive calls');
  });

  it('B-02: GET /v1/crl with If-None-Match matching ETag returns 304 with empty body', async () => {
    const res1 = await fetch(`${baseUrl}/v1/crl`);
    const etag = res1.headers.get('etag');

    const res304 = await fetch(`${baseUrl}/v1/crl`, {
      headers: { 'If-None-Match': etag }
    });
    assert.equal(res304.status, 304);
    assert.equal(res304.headers.get('etag'), etag);
    assert.equal(res304.headers.get('cache-control'), 'public, max-age=3600');
    const text = await res304.text();
    assert.equal(text, '', '304 response body must be empty');
  });

  it('B-02: Revoking a license invalidates CRL cache and updates ETag', async () => {
    const resBefore = await fetch(`${baseUrl}/v1/crl`);
    const etagBefore = resBefore.headers.get('etag');

    // Create and revoke a new license
    const licId = 'revoc-check-' + Date.now();
    db.createLicense({
      id: licId,
      email: 'revoc@test.fr',
      plan: 'solo',
      sites: 1,
      domain: 'revoc.fr',
      expires_at: '2028-01-01',
      status: 'active'
    });
    db.updateLicenseStatus(licId, 'revoked', 'user_request');
    app.invalidateCrlCache();

    const resAfter = await fetch(`${baseUrl}/v1/crl`);
    const etagAfter = resAfter.headers.get('etag');
    assert.notEqual(etagBefore, etagAfter, 'ETag must change after revoking a license');

    const bodyAfter = await resAfter.json();
    const crl = JSON.parse(Buffer.from(bodyAfter.payload, 'base64url').toString('utf8'));
    assert.ok(crl.revoked.some(r => r.license_id === licId));
  });

  /* ----------------------------------------------------
     U-04 Tests: GDPR & Event Purge
  ---------------------------------------------------- */
  it('U-04: CRL payload never contains email addresses', async () => {
    const res = await fetch(`${baseUrl}/v1/crl`);
    const body = await res.json();
    const crl = JSON.parse(Buffer.from(body.payload, 'base64url').toString('utf8'));
    const rawCrlText = JSON.stringify(crl);
    assert.ok(!rawCrlText.includes('@'), 'CRL must never contain @ email addresses');
    for (const item of crl.revoked) {
      assert.ok(item.license_id, 'Item must have license_id');
      assert.ok(!item.email, 'Item must not have email property');
    }
  });

  it('U-04: db.purgeOldEvents purges events older than 90 days', () => {
    // Insert old event directly into DB
    const oldTimestamp = new Date(Date.now() - 95 * 24 * 3600 * 1000).toISOString();
    const recentTimestamp = new Date().toISOString();
    const dbInst = db.getDb();
    dbInst.prepare(`INSERT OR REPLACE INTO events (id, type, received_at) VALUES ('old_evt_1', 'order.paid', ?)`).run(oldTimestamp);
    dbInst.prepare(`INSERT OR REPLACE INTO events (id, type, received_at) VALUES ('recent_evt_1', 'order.paid', ?)`).run(recentTimestamp);

    const purged = db.purgeOldEvents(90);
    assert.ok(purged >= 1);

    const oldRow = dbInst.prepare(`SELECT * FROM events WHERE id = 'old_evt_1'`).get();
    const recentRow = dbInst.prepare(`SELECT * FROM events WHERE id = 'recent_evt_1'`).get();
    assert.equal(oldRow, undefined, 'Old event should be purged');
    assert.ok(recentRow, 'Recent event should be retained');
  });

  /* ----------------------------------------------------
     U-05 Tests: Rate Limiting
  ---------------------------------------------------- */
  it('U-05: Rate limiting rejects more than 10 requests per minute with 429 and Retry-After', async () => {
    const testKey = 'testkey_rate_limit_' + Date.now();
    let got429 = false;
    let retryAfterHeader = null;

    // Send 11 requests rapidly with the same key
    for (let i = 0; i < 11; i++) {
      const res = await fetch(`${baseUrl}/v1/updates?key=${testKey}`);
      if (res.status === 429) {
        got429 = true;
        retryAfterHeader = res.headers.get('retry-after');
        const json = await res.json();
        assert.equal(json.error, 'too_many_requests');
        break;
      }
    }

    assert.equal(got429, true, 'The 11th request should receive HTTP 429');
    assert.equal(retryAfterHeader, '60');
  });
});
