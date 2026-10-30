const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const fs = require('node:fs');
const path = require('node:path');
const app = require('../src/server');
const db = require('../src/db');
const config = require('../src/config');
const mailer = require('../src/mailer');
const { signLicense, initKeypair, verifyLicenseKey } = require('../src/crypto');

function makeWebhookHeaders(provider, payload, secret, options = {}) {
  const timestamp = options.timestamp !== undefined ? options.timestamp : Math.floor(Date.now() / 1000);
  const rawBody = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const headers = { 'Content-Type': 'application/json' };
  if (options.noHeaders) return headers;

  if (provider === 'paddle') {
    const signString = `${timestamp}:${rawBody}`;
    const sig = options.badSignature ? 'deadbeef1234' : crypto.createHmac('sha256', secret).update(signString).digest('hex');
    headers['paddle-signature'] = `ts=${timestamp};h1=${sig}`;
  } else {
    // Polar / Standard Webhooks: {id}.{ts}.{rawBody}
    const id = options.id || ('msg_test_' + Date.now());
    headers['webhook-id'] = id;
    headers['webhook-timestamp'] = String(timestamp);

    let keyBuf;
    if (secret.startsWith('whsec_')) {
      keyBuf = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
    } else {
      keyBuf = Buffer.from(secret, 'utf8');
    }
    const toSign = Buffer.concat([Buffer.from(`${id}.${timestamp}.`), Buffer.from(rawBody, 'utf8')]);
    const sig = options.badSignature ? 'deadbeef1234' : crypto.createHmac('sha256', keyBuf).update(toSign).digest('base64');
    headers['webhook-signature'] = `v1,${sig}`;
  }
  return headers;
}

describe('API Endpoints', () => {
  let server;
  let port;
  let baseUrl;

  before(async () => {
    config.adminToken = 'test_admin_token_secret_12345';
    config.polarWebhookSecret = 'test_polar_secret_key_12345';
    config.paddleWebhookSecret = 'test_paddle_secret_key_12345';
    mailer.setMockTransporter({ sendMail: async () => ({ messageId: 'mock-id' }) });
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
    mailer.setMockTransporter(null);
    await new Promise((resolve) => server.close(resolve));
  });

  it('GET / rejects unauthenticated request with 401 without WWW-Authenticate header', async () => {
    const res = await fetch(`${baseUrl}/`);
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('www-authenticate'), null, 'Must NOT send WWW-Authenticate header to avoid browser user/password dialog');
    const html = await res.text();
    assert.ok(html.includes('ADMIN_TOKEN'));
    assert.ok(!html.includes('admin-login-modal'), 'Must not serve dashboard HTML without authentication');
  });

  it('GET / with valid token query parameter serves full HTML dashboard with 200', async () => {
    const res = await fetch(`${baseUrl}/?token=${config.adminToken}`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('admin-login-modal'));
    assert.ok(html.includes('login-token-input'));
  });

  it('P0: Web UI API: POST /api/licenses rejects unauthenticated call with 401', async () => {
    const res = await fetch(`${baseUrl}/api/licenses`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'attacker@example.com',
        plan: 'solo',
        sites: 1,
        domain: 'attack.com',
        expires: '2029-10-10'
      })
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.deepEqual(body, { error: 'unauthorized' });
  });

  it('P0: Web UI API: POST /api/licenses rejects invalid Bearer token with 401', async () => {
    const res = await fetch(`${baseUrl}/api/licenses`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer wrong_token_value'
      },
      body: JSON.stringify({
        email: 'attacker@example.com',
        plan: 'solo',
        sites: 1,
        domain: 'attack.com',
        expires: '2029-10-10'
      })
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.deepEqual(body, { error: 'unauthorized' });
  });

  it('Web UI API: POST /api/licenses creates license and returns signed key with valid ADMIN_TOKEN', async () => {
    const res = await fetch(`${baseUrl}/api/licenses`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.adminToken}`
      },
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

  it('Web UI API: GET /api/licenses lists licenses with keys with valid ADMIN_TOKEN', async () => {
    const res = await fetch(`${baseUrl}/api/licenses`, {
      headers: { 'Authorization': `Bearer ${config.adminToken}` }
    });
    assert.equal(res.status, 200);
    const list = await res.json();
    assert.ok(Array.isArray(list));
    assert.ok(list.some(l => l.domain === 'webtest.fr' && l.key));
  });

  it('Web UI API: GET /api/stats returns counts with valid ADMIN_TOKEN', async () => {
    const res = await fetch(`${baseUrl}/api/stats`, {
      headers: { 'Authorization': `Bearer ${config.adminToken}` }
    });
    assert.equal(res.status, 200);
    const stats = await res.json();
    assert.ok(typeof stats.total === 'number');
    assert.ok(typeof stats.active === 'number');
  });

  it('GET /healthz returns ok, db status and mail: true when configured', async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.ok, true);
    assert.equal(data.db, true);
    assert.equal(data.mail, true);
  });

  it('GET /healthz returns mail: false when SMTP is not configured (without returning 503)', async () => {
    mailer.setMockTransporter(null);
    const prevUrl = config.smtpUrl;
    config.smtpUrl = '';
    try {
      const res = await fetch(`${baseUrl}/healthz`);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.ok, true);
      assert.equal(data.db, true);
      assert.equal(data.mail, false);
    } finally {
      config.smtpUrl = prevUrl;
      mailer.setMockTransporter({ sendMail: async () => ({ messageId: 'mock-id' }) });
    }
  });

  it('GET /healthz returns 503 webhook_secret_missing when secrets are not configured', async () => {
    const prevPolar = config.polarWebhookSecret;
    const prevPaddle = config.paddleWebhookSecret;
    try {
      config.polarWebhookSecret = '';
      const res = await fetch(`${baseUrl}/healthz`);
      assert.equal(res.status, 503);
      const data = await res.json();
      assert.equal(data.error, 'webhook_secret_missing');
    } finally {
      config.polarWebhookSecret = prevPolar;
      config.paddleWebhookSecret = prevPaddle;
    }
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
    assert.equal(body.activations, 1);
    assert.equal(body.sites, 1);
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

  it('P1 & P2: POST /v1/activate enforces site quota (rejects with 409 quota_exceeded when limit reached)', async () => {
    const licenseId = 'test-quota-' + Date.now();
    db.createLicense({
      id: licenseId,
      email: 'client@example.com',
      plan: 'solo',
      sites: 1,
      domain: '*',
      expires_at: '2029-12-31',
      status: 'active'
    });

    const signed = signLicense({
      id: licenseId,
      license_id: licenseId,
      plan: 'solo',
      sites: 1,
      domain: '*',
      expires: '2029-12-31'
    });

    // 1. First activation on site-a.fr succeeds
    const res1 = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: signed.key, domain: 'site-a.fr' })
    });
    assert.equal(res1.status, 200);
    const body1 = await res1.json();
    assert.equal(body1.valid, true);
    assert.equal(body1.activations, 1);
    assert.equal(body1.sites, 1);

    // 2. Re-activation of the SAME domain site-a.fr succeeds (updates last_seen without exceeding quota)
    const resReactivate = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: signed.key, domain: 'site-a.fr' })
    });
    assert.equal(resReactivate.status, 200);
    const bodyReactivate = await resReactivate.json();
    assert.equal(bodyReactivate.activations, 1);
    assert.equal(bodyReactivate.sites, 1);

    // 3. Second activation on DIFFERENT domain site-b.fr is rejected with 409 quota_exceeded
    const res2 = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: signed.key, domain: 'site-b.fr' })
    });
    assert.equal(res2.status, 409);
    const body2 = await res2.json();
    assert.equal(body2.error, 'quota_exceeded');
    assert.equal(body2.activations, 1);
    assert.equal(body2.sites, 1);
  });

  it('P1: POST /v1/deactivate frees a site activation slot allowing migration', async () => {
    const licenseId = 'test-deact-' + Date.now();
    db.createLicense({
      id: licenseId,
      email: 'client@example.com',
      plan: 'solo',
      sites: 1,
      domain: '*',
      expires_at: '2029-12-31',
      status: 'active'
    });

    const signed = signLicense({
      id: licenseId,
      license_id: licenseId,
      plan: 'solo',
      sites: 1,
      domain: '*',
      expires: '2029-12-31'
    });

    // 1. Activate site-old.com
    await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: signed.key, domain: 'site-old.com' })
    });

    // 2. Deactivate site-old.com
    const deactRes = await fetch(`${baseUrl}/v1/deactivate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: signed.key, domain: 'site-old.com' })
    });
    assert.equal(deactRes.status, 200);
    const deactBody = await deactRes.json();
    assert.equal(deactBody.deactivated, true);
    assert.equal(deactBody.activations, 0);

    // 3. Now activate site-new.com (succeeds because slot was freed)
    const actRes = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: signed.key, domain: 'site-new.com' })
    });
    assert.equal(actRes.status, 200);
    const actBody = await actRes.json();
    assert.equal(actBody.activations, 1);
    assert.equal(actBody.sites, 1);
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
    assert.deepEqual(body, { error: 'unauthorized' });
  });

  it('P0: POST /v1/webhook/polar rejects invalid signature with 401 { error: "unauthorized" }', async () => {
    const payload = { id: 'evt_bad_sig', type: 'order.paid' };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret, { badSignature: true });
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.deepEqual(body, { error: 'unauthorized' });
  });

  it('P0: POST /v1/webhook/polar rejects expired timestamp (> 300 s) with 401 { error: "unauthorized" }', async () => {
    const payload = { id: 'evt_expired_ts', type: 'order.paid' };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret, { timestamp: 1 });
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.deepEqual(body, { error: 'unauthorized' });
  });

  it('P0: POST /v1/webhook/polar accepts valid signature and creates a single license', async () => {
    const eventId = 'evt_valid_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        customer: { email: 'buyer@test.org' },
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

  it('P0: POST /v1/webhook/polar handles Standard Webhooks with whsec_ base64 secret', async () => {
    const prevSecret = config.polarWebhookSecret;
    try {
      const rawSecretBytes = crypto.randomBytes(32);
      config.polarWebhookSecret = 'whsec_' + rawSecretBytes.toString('base64');

      const eventId = 'evt_sw_' + Date.now();
      const payload = {
        id: eventId,
        type: 'order.paid',
        data: {
          customer: { email: 'buyer-sw@test.org' },
          plan: 'solo',
          sites: 1,
          domain: 'standardwebhooks.org',
          order_id: 'ord_sw_' + Date.now()
        }
      };

      const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
      const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.status, 'license_issued');
      assert.ok(body.id);
      assert.ok(body.key);
    } finally {
      config.polarWebhookSecret = prevSecret;
    }
  });

  it('P0: POST /v1/webhook/polar reads nested customer.email and maps Agence product to 10 sites', async () => {
    const eventId = 'evt_agence_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        customer: { email: 'agence-client@entreprise.fr' },
        product_id: '6ae706ed-6bf4-40c1-85d7-dd65b9455984',
        domain: 'agence-site.com',
        order_id: 'ord_ag_' + Date.now()
      }
    };

    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'license_issued');

    const lic = db.getLicenseById(body.id);
    assert.equal(lic.email, 'agence-client@entreprise.fr');
    assert.equal(lic.plan, 'agence');
    assert.equal(lic.sites, 10);
  });

  it('P0: POST /v1/webhook/polar rejects missing customer email with 422', async () => {
    const payload = {
      id: 'evt_no_email_' + Date.now(),
      type: 'order.paid',
      data: {
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7',
        order_id: 'ord_no_email'
      }
    };

    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 422);
    const body = await res.json();
    assert.equal(body.error, 'missing_customer_email');
  });

  it('P0: POST /v1/webhook/polar subscription.canceled sets auto_renew=0 without revoking license', async () => {
    const licId = 'lic_sub_cancel_' + Date.now();
    const subId = 'sub_polar_' + Date.now();
    db.createLicense({
      id: licId,
      email: 'sub@test.fr',
      plan: 'solo',
      sites: 1,
      domain: 'sub.fr',
      expires_at: '2028-10-30',
      status: 'active',
      provider: 'polar',
      provider_ref: subId,
      auto_renew: 1
    });

    const payload = {
      id: 'evt_cancel_' + Date.now(),
      type: 'subscription.canceled',
      data: {
        id: subId,
        subscription_id: subId
      }
    };

    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'auto_renew_disabled');

    const updatedLic = db.getLicenseById(licId);
    assert.equal(updatedLic.auto_renew, 0);
    assert.equal(updatedLic.status, 'active', 'Cancellation must NOT revoke license');
  });

  it('P0: POST /v1/webhook/polar order.refunded revokes license immediately', async () => {
    const licId = 'lic_refund_' + Date.now();
    const orderId = 'ord_ref_' + Date.now();
    db.createLicense({
      id: licId,
      email: 'refund@test.fr',
      plan: 'solo',
      sites: 1,
      domain: 'refund.fr',
      expires_at: '2028-10-30',
      status: 'active',
      provider: 'polar',
      provider_ref: orderId
    });

    const payload = {
      id: 'evt_ref_' + Date.now(),
      type: 'order.refunded',
      data: {
        id: orderId,
        order_id: orderId
      }
    };

    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'license_revoked');

    const updatedLic = db.getLicenseById(licId);
    assert.equal(updatedLic.status, 'revoked');
  });

  it('P1: POST /v1/webhook/polar subscription.cycled extends license expiration date and re-signs key', async () => {
    const licId = 'lic_cycle_' + Date.now();
    const subId = 'sub_cycle_' + Date.now();
    db.createLicense({
      id: licId,
      email: 'renew@test.fr',
      plan: 'solo',
      sites: 1,
      domain: 'renew.fr',
      expires_at: '2027-10-30',
      status: 'active',
      provider: 'polar',
      provider_ref: subId
    });

    const payload = {
      id: 'evt_cycle_' + Date.now(),
      type: 'subscription.cycled',
      data: {
        id: subId,
        subscription_id: subId,
        subscription: {
          current_period_end: '2028-10-30T12:00:00Z'
        }
      }
    };

    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'license_renewed');
    assert.equal(body.expires, '2028-10-30');
    assert.ok(body.key, 'Must return new signed key on renewal');

    // Check database
    const updatedLic = db.getLicenseById(licId);
    assert.equal(updatedLic.expires_at, '2028-10-30');
    assert.equal(updatedLic.signed_key, body.key, 'Stored signed key must match new key');

    // Cryptographic offline verification of the renewed key
    const verification = verifyLicenseKey(body.key);
    assert.equal(verification.valid, true);
    assert.equal(verification.payload.expires, '2028-10-30');
  });

  it('P1: Webhook retry on error (failed event is retried and not burned by idempotency)', async () => {
    const eventId = 'evt_retry_test_' + Date.now();
    const badPayload = {
      id: eventId,
      type: 'order.paid',
      data: {
        product_id: 'unknown-product-uuid-1234',
        customer: { email: 'retry-buyer@example.com' },
        order_id: 'ord_retry_' + Date.now()
      }
    };

    const headers = makeWebhookHeaders('polar', badPayload, config.polarWebhookSecret);
    const res1 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(badPayload)
    });
    assert.equal(res1.status, 500);

    // Event should be recorded as 'failed', not burned
    const evt1 = db.getEvent(eventId);
    assert.equal(evt1.status, 'failed');

    // Polar retries with corrected data using the SAME eventId
    const retryPayload = {
      id: eventId,
      type: 'order.paid',
      data: {
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7', // Valid Solo product
        customer: { email: 'retry-buyer@example.com' },
        order_id: 'ord_retry_' + Date.now(),
        custom_field_data: {
          domain: 'retry-buyer.org'
        }
      }
    };
    const retryHeaders = makeWebhookHeaders('polar', retryPayload, config.polarWebhookSecret);
    const res2 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: retryHeaders,
      body: JSON.stringify(retryPayload)
    });
    assert.equal(res2.status, 200);
    const b2 = await res2.json();
    assert.equal(b2.status, 'license_issued');

    // Now event status is 'processed'
    const evt2 = db.getEvent(eventId);
    assert.equal(evt2.status, 'processed');

    // Further duplicate replays return already_processed
    const res3 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: retryHeaders,
      body: JSON.stringify(retryPayload)
    });
    assert.equal(res3.status, 200);
    const b3 = await res3.json();
    assert.equal(b3.status, 'already_processed');
  });

  it('P1: POST /v1/activate rate limit allows up to 30 requests/minute for agency multi-site setups', async () => {
    const licenseId = 'test-agency-limit-' + Date.now();
    db.createLicense({
      id: licenseId,
      email: 'agency@example.com',
      plan: 'agence',
      sites: 15,
      domain: '*',
      expires_at: '2029-12-31',
      status: 'active'
    });

    const signed = signLicense({
      id: licenseId,
      license_id: licenseId,
      plan: 'agence',
      sites: 15,
      domain: '*',
      expires: '2029-12-31'
    });

    // Fire 15 consecutive activation calls for 15 distinct domains (under 30/min limit)
    for (let i = 1; i <= 15; i++) {
      const res = await fetch(`${baseUrl}/v1/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: signed.key, domain: `site-${i}.agency.com` })
      });
      assert.equal(res.status, 200, `Call ${i} should succeed without hitting 429`);
    }
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

    const dbInst = db.getDb();
    dbInst.prepare(`
      INSERT INTO licenses (id, email, plan, sites, domain, expires_at, status, provider, created_at)
      VALUES (?, 'test@example.com', 'solo', 1, 'test.fr', '2030-01-01', 'active', 'test', datetime('now'))
      ON CONFLICT(id) DO UPDATE SET status = 'active', revoke_reason = NULL
    `).run(id1);

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

  it('Recette 2 Point 3: test.local end-to-end accepted (200/404) then revoked (403 license_revoked)', async () => {
    const licId = 'test-local-uuid-' + Date.now();
    const payload = {
      id: licId,
      plan: 'solo',
      sites: 1,
      domain: 'test.local',
      expires: '2028-12-31',
      issued_at: new Date().toISOString()
    };
    const signed = signLicense(payload);

    // 1. Émettre la licence en base (active)
    db.createLicense({
      id: licId,
      email: 'client@test.local',
      plan: 'solo',
      sites: 1,
      domain: 'test.local',
      expires_at: '2028-12-31',
      status: 'active',
      signed_key: signed.key
    });

    // 2. Appel /v1/updates/rgaa-audit?key=... (licence acceptée -> statut 404 si pas de release ou 200 si release existe)
    const resActive = await fetch(`${baseUrl}/v1/updates/rgaa-audit?key=${signed.key}`);
    assert.notEqual(resActive.status, 403, 'Active license key must not be rejected with 403');
    assert.ok(resActive.status === 200 || resActive.status === 404);

    // 3. Passer la licence en revoked
    db.updateLicenseStatus(licId, 'revoked', 'user_cancellation');

    // 4. Rappeler la même URL avec la même clé -> doit répondre 403 license_revoked
    const resRevoked = await fetch(`${baseUrl}/v1/updates/rgaa-audit?key=${signed.key}`);
    assert.equal(resRevoked.status, 403);
    const bodyRevoked = await resRevoked.json();
    assert.equal(bodyRevoked.error, 'license_revoked');
  });

  /* ----------------------------------------------------
     B-01 & P2 Tests: Route aliases, key requirement & JSON 404/500
  ---------------------------------------------------- */
  it('P2 & B-01: GET /v1/updates and /v1/updates/rgaa-audit require key (403) and return identical response bytes', async () => {
    const res1 = await fetch(`${baseUrl}/v1/updates`);
    const res2 = await fetch(`${baseUrl}/v1/updates/rgaa-audit`);

    assert.equal(res1.status, 403);
    assert.equal(res2.status, 403);
    assert.equal(res1.headers.get('content-type'), res2.headers.get('content-type'));

    const text1 = await res1.text();
    const text2 = await res2.text();
    assert.equal(text1, text2, 'Both routes must return the exact same response body octet for octet');
    assert.deepEqual(JSON.parse(text1), { error: 'license_key_required' });
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

  it('P0: Rate limiting on /api/* rejects more than 10 requests per minute with 429', async () => {
    let got429 = false;
    let retryAfterHeader = null;

    for (let i = 0; i < 11; i++) {
      const res = await fetch(`${baseUrl}/api/stats`, {
        headers: { 'Authorization': 'Bearer bad_token_attempt' }
      });
      if (res.status === 429) {
        got429 = true;
        retryAfterHeader = res.headers.get('retry-after');
        break;
      }
    }

    assert.equal(got429, true, 'The 11th request to /api/* must receive HTTP 429');
    assert.equal(retryAfterHeader, '60');
    app.resetRateLimits();
  });

  /* ----------------------------------------------------
     M-01 Tests: Email Delivery Tracking, Failure Retries & Resend
  ---------------------------------------------------- */
  it('M-01: Two successive POSTs of same webhook-id with broken SMTP produce a single license, mail_attempts = 2, emailed_at null, and two 5xx responses', async () => {
    mailer.setMockTransporter({
      sendMail: async () => {
        throw new Error('EAUTH: Invalid login');
      }
    });

    const eventId = 'evt_broken_smtp_' + Date.now();
    const orderId = 'ord_broken_smtp_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        customer: { email: 'loic.huon.automation@gmail.com' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7', // Solo
        domain: 'broken-mail.fr',
        order_id: orderId
      }
    };

    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);

    // First attempt -> 500 mail_delivery_failed
    const res1 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res1.status, 500);
    const b1 = await res1.json();
    assert.equal(b1.error, 'mail_delivery_failed');

    // Second attempt (Polar retry) -> 500
    const res2 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res2.status, 500);

    // Exactly one license in DB, mail_attempts = 2, emailed_at null
    const lics = db.getDb().prepare("SELECT * FROM licenses WHERE email = 'loic.huon.automation@gmail.com' AND provider_ref = ?").all(orderId);
    assert.equal(lics.length, 1, 'Must create only ONE license across retries');
    assert.equal(lics[0].mail_attempts, 2);
    assert.equal(lics[0].emailed_at, null);
    assert.ok(lics[0].mail_last_error.includes('EAUTH'));

    // SMTP fixed: 3rd retry succeeds
    mailer.setMockTransporter({ sendMail: async () => ({ messageId: 'fixed-msg' }) });
    const res3 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res3.status, 200);
    const b3 = await res3.json();
    assert.equal(b3.status, 'license_issued');

    const licsAfterFix = db.getDb().prepare("SELECT * FROM licenses WHERE email = 'loic.huon.automation@gmail.com' AND provider_ref = ?").all(orderId);
    assert.equal(licsAfterFix.length, 1, 'Still only 1 license');
    assert.ok(licsAfterFix[0].emailed_at !== null, 'emailed_at must now be set');

    // 4th replay: already processed
    const res4 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res4.status, 200);
    const b4 = await res4.json();
    assert.equal(b4.status, 'already_processed');
  });

  it('M-01: POST /v1/resend-key resends email without creating new license', async () => {
    const licId = 'lic_resend_' + Date.now();
    db.createLicense({
      id: licId,
      email: 'resend-client@domain.fr',
      plan: 'solo',
      sites: 1,
      domain: 'resend.fr',
      expires_at: '2028-10-10',
      status: 'active',
      signed_key: 'signed.key.test'
    });

    const res = await fetch(`${baseUrl}/v1/resend-key`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: JSON.stringify({ license_id: licId })
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.sent, true);
    assert.equal(body.license_id, licId);

    const updated = db.getLicenseById(licId);
    assert.ok(updated.emailed_at !== null);
  });

  it('M-01: /api/stats exposes emails_pending and emails_failed', async () => {
    const res = await fetch(`${baseUrl}/api/stats`, {
      headers: { 'Authorization': `Bearer ${config.adminToken}` }
    });
    assert.equal(res.status, 200);
    const stats = await res.json();
    assert.ok(typeof stats.emails_pending === 'number');
    assert.ok(typeof stats.emails_failed === 'number');
  });

  /* ----------------------------------------------------
     M-02 Tests: License Deletion & Purge
  ---------------------------------------------------- */
  it('M-02: DELETE /api/licenses/:id deletes license, returns 204 and removes from CRL', async () => {
    const licId = 'lic_delete_test_' + Date.now();
    db.createLicense({
      id: licId,
      email: 'delete-me@test.local',
      plan: 'solo',
      sites: 1,
      domain: 'delete-me.fr',
      expires_at: '2028-10-10',
      status: 'revoked'
    });

    const delRes = await fetch(`${baseUrl}/api/licenses/${licId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${config.adminToken}` }
    });
    assert.equal(delRes.status, 204);

    assert.equal(db.getLicenseById(licId), undefined);

    const crlRes = await fetch(`${baseUrl}/v1/crl`);
    const crlBody = await crlRes.json();
    const crlData = JSON.parse(Buffer.from(crlBody.payload, 'base64url').toString('utf8'));
    assert.ok(!crlData.revoked.some(r => r.id === licId));
  });

  it('M-02: POST /api/licenses/purge with filter test purges test licenses and /v1/updates returns 403 invalid_license', async () => {
    const testLicId = 'test_purge_' + Date.now();
    const signed = signLicense({
      id: testLicId,
      license_id: testLicId,
      plan: 'solo',
      sites: 1,
      domain: 'test-purge.local',
      expires: '2029-12-31'
    });
    db.createLicense({
      id: testLicId,
      email: 'auto-test@example.com',
      plan: 'solo',
      sites: 1,
      domain: 'test-purge.local',
      expires_at: '2029-12-31',
      status: 'active',
      provider: 'manual',
      signed_key: signed.key
    });

    // Reject without confirm 'PURGE'
    const rejRes = await fetch(`${baseUrl}/api/licenses/purge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: JSON.stringify({ confirm: 'NO', filter: 'test' })
    });
    assert.equal(rejRes.status, 400);

    // Confirm PURGE
    const purgeRes = await fetch(`${baseUrl}/api/licenses/purge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: JSON.stringify({ confirm: 'PURGE', filter: 'test' })
    });
    assert.equal(purgeRes.status, 200);
    const purgeBody = await purgeRes.json();
    assert.ok(purgeBody.purged >= 1);

    // Deleted key -> /v1/updates returns 403 invalid_license
    const updRes = await fetch(`${baseUrl}/v1/updates?key=${signed.key}`);
    assert.equal(updRes.status, 403);
    const updBody = await updRes.json();
    assert.equal(updBody.error, 'invalid_license');
  });

  /* ----------------------------------------------------
     M-03 & M-04: Releases API & Dynamic Email Download URL
  ---------------------------------------------------- */

  function makePluginZip(version, files = null) {
    const list = files || [
      { name: 'rgaa-audit/rgaa-audit.php', data: `<?php\n/*\n * Plugin Name: RGAA Audit\n * Version: ${version}\n */\n` },
      { name: 'rgaa-audit/readme.txt', data: `=== RGAA Audit ===\nStable tag: ${version}\n` }
    ];

    const localHeaders = [];
    const cdHeaders = [];
    let offset = 0;

    for (const f of list) {
      const fnBuf = Buffer.from(f.name, 'utf8');
      const dataBuf = Buffer.from(f.data, 'utf8');
      const deflated = zlib.deflateRawSync(dataBuf);
      const compSize = deflated.length;
      const uncompSize = dataBuf.length;

      const lh = Buffer.alloc(30 + fnBuf.length);
      lh.writeUInt32LE(0x04034b50, 0);
      lh.writeUInt16LE(20, 4);
      lh.writeUInt16LE(0, 6);
      lh.writeUInt16LE(8, 8);
      lh.writeUInt32LE(0, 10);
      lh.writeUInt32LE(0, 14);
      lh.writeUInt32LE(compSize, 18);
      lh.writeUInt32LE(uncompSize, 22);
      lh.writeUInt16LE(fnBuf.length, 26);
      lh.writeUInt16LE(0, 28);
      fnBuf.copy(lh, 30);

      const localChunk = Buffer.concat([lh, deflated]);
      localHeaders.push(localChunk);

      const cd = Buffer.alloc(46 + fnBuf.length);
      cd.writeUInt32LE(0x02014b50, 0);
      cd.writeUInt16LE(20, 4);
      cd.writeUInt16LE(20, 6);
      cd.writeUInt16LE(0, 8);
      cd.writeUInt16LE(8, 10);
      cd.writeUInt32LE(0, 12);
      cd.writeUInt32LE(0, 16);
      cd.writeUInt32LE(compSize, 20);
      cd.writeUInt32LE(uncompSize, 24);
      cd.writeUInt16LE(fnBuf.length, 28);
      cd.writeUInt16LE(0, 30);
      cd.writeUInt16LE(0, 32);
      cd.writeUInt16LE(0, 34);
      cd.writeUInt16LE(0, 36);
      cd.writeUInt32LE(0, 38);
      cd.writeUInt32LE(offset, 42);
      fnBuf.copy(cd, 46);
      cdHeaders.push(cd);

      offset += localChunk.length;
    }

    const cdBuf = Buffer.concat(cdHeaders);
    const cdOffset = offset;
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(0, 4);
    eocd.writeUInt16LE(0, 6);
    eocd.writeUInt16LE(list.length, 8);
    eocd.writeUInt16LE(list.length, 10);
    eocd.writeUInt32LE(cdBuf.length, 12);
    eocd.writeUInt32LE(cdOffset, 16);
    eocd.writeUInt16LE(0, 20);

    return Buffer.concat([...localHeaders, cdBuf, eocd]);
  }

  it('M-03: POST /api/releases rejects unauthenticated request with 401', async () => {
    app.resetRateLimits();
    const res = await fetch(`${baseUrl}/api/releases?version=0.2.2`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/zip' },
      body: Buffer.from('dummy')
    });
    assert.equal(res.status, 401);
  });

  it('M-03: POST /api/releases rejects non-semver version with 400', async () => {
    app.resetRateLimits();
    const res = await fetch(`${baseUrl}/api/releases?version=latest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/zip',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: Buffer.from('dummy')
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, 'invalid_version');
  });

  it('M-03: POST /api/releases rejects zip with invalid root directory with 422 and writes no file', async () => {
    app.resetRateLimits();
    const badZip = makePluginZip('0.2.2', [
      { name: 'wrong-folder/rgaa-audit.php', data: '<?php /* Version: 0.2.2 */' }
    ]);
    const res = await fetch(`${baseUrl}/api/releases?version=0.2.2`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/zip',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: badZip
    });
    assert.equal(res.status, 422);
    const body = await res.json();
    assert.equal(body.error, 'invalid_root_directory');

    // Verify no file was written to disk
    const targetFile = path.join(config.releasesDir, 'rgaa-audit-0.2.2.zip');
    assert.equal(fs.existsSync(targetFile), false);
  });

  it('M-03: POST /api/releases rejects version mismatch with 422 and writes no file', async () => {
    app.resetRateLimits();
    // Declared: 0.2.2, but internal PHP header: 0.2.1
    const mismatchZip = makePluginZip('0.2.1');
    const res = await fetch(`${baseUrl}/api/releases?version=0.2.2`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/zip',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: mismatchZip
    });
    assert.equal(res.status, 422);
    const body = await res.json();
    assert.equal(body.error, 'version_mismatch');
    assert.equal(body.zip_version, '0.2.1');
    assert.equal(body.declared, '0.2.2');

    // Verify no file written
    const targetFile = path.join(config.releasesDir, 'rgaa-audit-0.2.2.zip');
    assert.equal(fs.existsSync(targetFile), false);
  });

  it('M-03: POST /api/releases publishes valid 0.2.2 zip, returns 201 with sha256 and size matching file on disk', async () => {
    app.resetRateLimits();
    const validZip = makePluginZip('0.2.2');
    const res = await fetch(`${baseUrl}/api/releases?version=0.2.2&requires=6.5&tested=7.1&requires_php=8.1`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/zip',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: validZip
    });
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.version, '0.2.2');
    assert.ok(body.sha256);
    assert.equal(typeof body.size, 'number');

    // Check file on disk
    const targetFile = path.join(config.releasesDir, 'rgaa-audit-0.2.2.zip');
    assert.ok(fs.existsSync(targetFile));
    const diskContent = fs.readFileSync(targetFile);
    const diskSha = crypto.createHash('sha256').update(diskContent).digest('hex');
    assert.equal(body.sha256, diskSha);
    assert.equal(body.size, diskContent.length);

    // Verify DB record
    const relDb = db.getRelease('0.2.2');
    assert.ok(relDb);
    assert.equal(relDb.sha256, diskSha);
    assert.equal(relDb.requires, '6.5');
    assert.equal(relDb.tested, '7.1');
    assert.equal(relDb.requires_php, '8.1');
  });

  it('M-03 & M-04: GET /v1/updates and /v1/download immediately serve release 0.2.2 without cache delay', async () => {
    app.resetRateLimits();
    // Generate valid test license key
    const testId = 'lic_rel_test_' + Date.now();
    const signed = signLicense({
      id: testId,
      plan: 'solo',
      sites: 1,
      domain: 'rel-test.org',
      expires: '2029-12-31'
    });
    db.createLicense({
      id: testId,
      email: 'rel-test@org.fr',
      plan: 'solo',
      sites: 1,
      domain: 'rel-test.org',
      expires_at: '2029-12-31',
      status: 'active',
      signed_key: signed.key
    });

    const updRes = await fetch(`${baseUrl}/v1/updates/rgaa-audit?key=${signed.key}`);
    assert.equal(updRes.status, 200);
    const envelope = await updRes.json();
    const manifest = JSON.parse(Buffer.from(envelope.payload, 'base64url').toString('utf8'));
    assert.equal(manifest.version, '0.2.2');
    assert.ok(manifest.download_url.includes('/v1/download/0.2.2.zip'));

    // Download the zip
    const dlRes = await fetch(`${baseUrl}/v1/download/0.2.2.zip?key=${signed.key}`);
    assert.equal(dlRes.status, 200);
    assert.equal(dlRes.headers.get('content-type'), 'application/zip');
    const dlBuf = Buffer.from(await dlRes.arrayBuffer());
    const dlSha = crypto.createHash('sha256').update(dlBuf).digest('hex');
    assert.equal(dlSha, manifest.sha256);

    // Download counter should increment
    const relAfterDl = db.getRelease('0.2.2');
    assert.ok(relAfterDl.download_count >= 1);
  });

  it('M-03: DELETE /api/releases/:version returns 409 cannot_delete_latest for newest release', async () => {
    app.resetRateLimits();
    const res = await fetch(`${baseUrl}/api/releases/0.2.2`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${config.adminToken}`
      }
    });
    assert.equal(res.status, 409);
    const body = await res.json();
    assert.equal(body.error, 'cannot_delete_latest');
  });

  it('M-03 & M-04: Publish 0.2.3, then delete older 0.2.2 succeeds with 204', async () => {
    app.resetRateLimits();
    // 1. Publish 0.2.3
    const zip023 = makePluginZip('0.2.3');
    const pubRes = await fetch(`${baseUrl}/api/releases?version=0.2.3`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/zip',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: zip023
    });
    assert.equal(pubRes.status, 201);

    // Verify 0.2.3 is now latest
    const latest = db.getLatestRelease();
    assert.equal(latest.version, '0.2.3');

    // 2. Delete older 0.2.2
    app.resetRateLimits();
    const delRes = await fetch(`${baseUrl}/api/releases/0.2.2`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${config.adminToken}`
      }
    });
    assert.equal(delRes.status, 204);
    assert.equal(Boolean(db.getRelease('0.2.2')), false);
    assert.equal(fs.existsSync(path.join(config.releasesDir, 'rgaa-audit-0.2.2.zip')), false);

    // 3. GET /api/releases lists 0.2.3
    app.resetRateLimits();
    const listRes = await fetch(`${baseUrl}/api/releases`, {
      headers: { 'Authorization': `Bearer ${config.adminToken}` }
    });
    assert.equal(listRes.status, 200);
    const listBody = await listRes.json();
    assert.ok(Array.isArray(listBody.releases));
    assert.equal(listBody.releases[0].version, '0.2.3');
  });

  it('M-04: License email contains version 0.2.3 download link (not hardcoded 0.2.0)', async () => {
    app.resetRateLimits();
    let capturedEmail = null;
    mailer.setMockTransporter({
      sendMail: async (opts) => {
        capturedEmail = opts;
        return { messageId: 'msg_023' };
      }
    });

    const eventId = 'evt_buy_023_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        customer: { email: 'buyer-023@test.org' },
        plan: 'solo',
        sites: 1,
        domain: 'buyer023.org',
        order_id: 'ord_023_' + Date.now()
      }
    };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    assert.ok(capturedEmail);
    assert.ok(capturedEmail.text.includes('/v1/download/0.2.3.zip?key='));
    assert.ok(capturedEmail.html.includes('/v1/download/0.2.3.zip?key='));
    assert.ok(capturedEmail.html.includes('Télécharger la version 0.2.3 (.zip)'));
    assert.ok(!capturedEmail.text.includes('0.2.0.zip'));
  });

  it('M-04: When no releases exist in DB, email sends in 200 without download block', async () => {
    app.resetRateLimits();
    let capturedEmail = null;
    mailer.setMockTransporter({
      sendMail: async (opts) => {
        capturedEmail = opts;
        return { messageId: 'msg_norelease' };
      }
    });

    // Temporarily delete all releases
    db.getDb().prepare('DELETE FROM releases').run();
    app.invalidateManifestCache();

    const eventId = 'evt_buy_norel_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        customer: { email: 'buyer-norel@test.org' },
        plan: 'solo',
        sites: 1,
        domain: 'buyernorel.org',
        order_id: 'ord_norel_' + Date.now()
      }
    };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    assert.ok(capturedEmail);
    // Email should NOT contain download block or dead link
    assert.ok(!capturedEmail.text.includes('Téléchargement de l\'extension :'));
    assert.ok(!capturedEmail.text.includes('/v1/download/'));
    assert.ok(!capturedEmail.html.includes('Téléchargement de l\'extension :'));
  });

  it('M-04: Publishing 0.2.4 dynamically updates email in subsequent purchase and renewal without container restart', async () => {
    app.resetRateLimits();
    // 1. Publish 0.2.4
    const zip024 = makePluginZip('0.2.4');
    const pubRes = await fetch(`${baseUrl}/api/releases?version=0.2.4`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/zip',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: zip024
    });
    assert.equal(pubRes.status, 201);

    let capturedEmail = null;
    mailer.setMockTransporter({
      sendMail: async (opts) => {
        capturedEmail = opts;
        return { messageId: 'msg_024' };
      }
    });

    // 2. Initial purchase immediately gets 0.2.4
    const eventId = 'evt_buy_024_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        customer: { email: 'buyer-024@test.org' },
        plan: 'solo',
        sites: 1,
        domain: 'buyer024.org',
        order_id: 'ord_024_' + Date.now()
      }
    };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    assert.ok(capturedEmail);
    assert.ok(capturedEmail.text.includes('/v1/download/0.2.4.zip?key='));
    assert.ok(capturedEmail.html.includes('Télécharger la version 0.2.4 (.zip)'));

    // 3. Renewal also gets 0.2.4
    capturedEmail = null;
    const renewalId = 'evt_renew_024_' + Date.now();
    const renewalPayload = {
      id: renewalId,
      type: 'subscription.cycled',
      data: {
        id: payload.data.order_id,
        current_period_end: '2030-01-01T00:00:00Z'
      }
    };
    const renewalHeaders = makeWebhookHeaders('polar', renewalPayload, config.polarWebhookSecret);
    const renewRes = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: renewalHeaders,
      body: JSON.stringify(renewalPayload)
    });
    assert.equal(renewRes.status, 200);
    assert.ok(capturedEmail);
    assert.ok(capturedEmail.text.includes('/v1/download/0.2.4.zip?key='));
    assert.ok(capturedEmail.html.includes('Télécharger la version 0.2.4 (.zip)'));
  });

  /* ----------------------------------------------------
     M-05: Sign license key with customer domain
  ---------------------------------------------------- */
  it('M-05 (Critère 1): order.paid without domain returns 422 missing_domain, no license created, event marked failed, replay returns 422', async () => {
    app.resetRateLimits();
    const eventId = 'evt_m05_nodomain_' + Date.now();
    const orderId = 'ord_m05_nodomain_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        id: orderId,
        billing_reason: 'purchase',
        customer: { email: 'client-nodomain@test.org' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7'
      }
    };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res1 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res1.status, 422);
    const b1 = await res1.json();
    assert.equal(b1.error, 'missing_domain');

    // No license created
    const lic = db.getLicenseByProviderRef('polar', orderId);
    assert.ok(!lic, 'No license should be created');

    // Event marked failed
    const ev = db.getEvent(eventId);
    assert.equal(ev.status, 'failed');
    assert.equal(ev.last_error, 'missing_domain');

    // Replay of same webhook-id returns 422 again, not already_processed
    const res2 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res2.status, 422);
    const b2 = await res2.json();
    assert.equal(b2.error, 'missing_domain');
  });

  let savedKeyM05 = null;
  let savedOrderIdM05 = null;

  it('M-05 (Critères 2, 8, 9, 10): custom_field_data.domain Mon-Site.FR signs normalized mon-site.fr, stores domain_raw, validates domain on WP activate and updates', async () => {
    app.resetRateLimits();
    const eventId = 'evt_m05_c2_' + Date.now();
    savedOrderIdM05 = 'ord_m05_c2_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        id: savedOrderIdM05,
        billing_reason: 'purchase',
        customer: { email: 'client-c2@test.org' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7',
        custom_field_data: { domain: 'Mon-Site.FR' }
      }
    };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'license_issued');
    savedKeyM05 = body.key;

    // Check payload of signed key
    const verification = verifyLicenseKey(savedKeyM05);
    assert.equal(verification.valid, true);
    assert.equal(verification.payload.domain, 'mon-site.fr');

    // Check database record
    const lic = db.getLicenseById(body.id);
    assert.ok(lic);
    assert.equal(lic.domain, 'mon-site.fr');
    assert.equal(lic.domain_raw, 'Mon-Site.FR');

    // Critère 8: activate on mismatched domain (autre-site.fr) -> 409 domain_mismatch
    const actBad = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: savedKeyM05, domain: 'autre-site.fr' })
    });
    assert.equal(actBad.status, 409);
    const badBody = await actBad.json();
    assert.equal(badBody.error, 'domain_mismatch');

    // Critère 9: activate on mon-site.fr -> 200 valid
    const actGood = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: savedKeyM05, domain: 'mon-site.fr' })
    });
    assert.equal(actGood.status, 200);
    const goodBody = await actGood.json();
    assert.equal(goodBody.valid, true);

    // Critère 10: GET /v1/updates with this key returns 200
    const updRes = await fetch(`${baseUrl}/v1/updates/rgaa-audit?key=${encodeURIComponent(savedKeyM05)}`);
    assert.equal(updRes.status, 200);
  });

  it('M-05 (Critère 3): custom_field_data.domain "https://www.mon-site.fr/contact" normalizes to mon-site.fr', async () => {
    app.resetRateLimits();
    const eventId = 'evt_m05_c3_' + Date.now();
    const orderId = 'ord_m05_c3_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        id: orderId,
        billing_reason: 'purchase',
        customer: { email: 'client-c3@test.org' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7',
        custom_field_data: { domain: 'https://www.mon-site.fr/contact' }
      }
    };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    const verification = verifyLicenseKey(body.key);
    assert.equal(verification.payload.domain, 'mon-site.fr');
    const lic = db.getLicenseById(body.id);
    assert.equal(lic.domain, 'mon-site.fr');
    assert.equal(lic.domain_raw, 'https://www.mon-site.fr/contact');
  });

  it('M-05 (Critère 4): custom_field_data.domain with spaces " mon-site.fr " normalizes to mon-site.fr', async () => {
    app.resetRateLimits();
    const eventId = 'evt_m05_c4_' + Date.now();
    const orderId = 'ord_m05_c4_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        id: orderId,
        billing_reason: 'purchase',
        customer: { email: 'client-c4@test.org' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7',
        custom_field_data: { domain: ' mon-site.fr ' }
      }
    };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    const verification = verifyLicenseKey(body.key);
    assert.equal(verification.payload.domain, 'mon-site.fr');
  });

  it('M-05 (Critère 5): custom_field_data.domain "" or "   " or "*" rejects with 422 missing_domain', async () => {
    app.resetRateLimits();
    const payload1 = {
      id: 'evt_m05_empty_' + Date.now(),
      type: 'order.paid',
      data: {
        id: 'ord_m05_empty_' + Date.now(),
        customer: { email: 'client-empty@test.org' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7',
        custom_field_data: { domain: '   ' }
      }
    };
    const res1 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: makeWebhookHeaders('polar', payload1, config.polarWebhookSecret),
      body: JSON.stringify(payload1)
    });
    assert.equal(res1.status, 422);
    const b1 = await res1.json();
    assert.equal(b1.error, 'missing_domain');

    app.resetRateLimits();
    const payload2 = {
      id: 'evt_m05_star_' + Date.now(),
      type: 'order.paid',
      data: {
        id: 'ord_m05_star_' + Date.now(),
        customer: { email: 'client-star@test.org' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7',
        custom_field_data: { domain: '*' }
      }
    };
    const res2 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: makeWebhookHeaders('polar', payload2, config.polarWebhookSecret),
      body: JSON.stringify(payload2)
    });
    assert.equal(res2.status, 422);
    const b2 = await res2.json();
    assert.equal(b2.error, 'missing_domain');
  });

  it('M-05 (Critère 6): POST /api/licenses with domain: "*" issues key with "*" (manual issuance preserved)', async () => {
    app.resetRateLimits();
    const res = await fetch(`${baseUrl}/api/licenses`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.adminToken}`
      },
      body: JSON.stringify({
        email: 'manual-star@test.org',
        plan: 'agence',
        sites: 10,
        domain: '*',
        expires: '2029-12-31'
      })
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    const verification = verifyLicenseKey(body.key);
    assert.equal(verification.payload.domain, '*');
    assert.equal(body.license.domain, '*');
  });

  it('M-05 (Critère 7): subscription.cycled on mon-site.fr license keeps domain unchanged', async () => {
    app.resetRateLimits();
    assert.ok(savedOrderIdM05, 'savedOrderIdM05 from critère 2 must exist');
    const renewalPayload = {
      id: 'evt_renew_m05_' + Date.now(),
      type: 'subscription.cycled',
      data: {
        id: savedOrderIdM05,
        current_period_end: '2031-10-29T00:00:00Z'
      }
    };
    const headers = makeWebhookHeaders('polar', renewalPayload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(renewalPayload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'license_renewed');
    const verification = verifyLicenseKey(body.key);
    assert.equal(verification.payload.domain, 'mon-site.fr');
    assert.equal(body.expires, '2031-10-29');

    // DB verification
    const lic = db.getLicenseById(body.id);
    assert.equal(lic.domain, 'mon-site.fr');
    assert.equal(lic.domain_raw, 'Mon-Site.FR');
  });

  /* ----------------------------------------------------
     M-06: Agence multi-sites (10 sites) signed with domain: "*"
  ---------------------------------------------------- */
  let savedAgencyKeyM06 = null;
  let savedAgencyOrderIdM06 = null;
  let savedAgencyLicIdM06 = null;

  it('M-06 (Critère 1): order.paid produit Agence (6ae706ed...) avec domain: "client.fr" signs domain: "*", sites: 10, DB domain="*", domain_raw="client.fr"', async () => {
    app.resetRateLimits();
    const eventId = 'evt_m06_agence_' + Date.now();
    const orderId = 'ord_m06_agence_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        id: orderId,
        billing_reason: 'purchase',
        customer: { email: 'contact-agence@web-experts.fr' },
        product_id: '6ae706ed-6bf4-40c1-85d7-dd65b9455984', // Agence 10 sites
        custom_field_data: {
          domain: 'client.fr'
        }
      }
    };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'license_issued');
    assert.ok(body.key, 'Signed license key must be returned');

    savedAgencyKeyM06 = body.key;
    savedAgencyOrderIdM06 = orderId;
    savedAgencyLicIdM06 = body.id;

    // Cryptographic offline verification
    const verification = verifyLicenseKey(body.key);
    assert.equal(verification.valid, true);
    assert.equal(verification.payload.domain, '*', 'Key must be signed with domain: "*"');
    assert.equal(verification.payload.sites, 10, 'Key must have sites: 10');
    assert.equal(verification.payload.plan, 'agence');

    // Database verification
    const lic = db.getLicenseById(body.id);
    assert.ok(lic);
    assert.equal(lic.domain, '*', 'DB domain must be stored as "*"');
    assert.equal(lic.domain_raw, 'client.fr', 'DB domain_raw must retain original declared domain');
    assert.equal(lic.sites, 10);
    assert.equal(lic.plan, 'agence');
  });

  it('M-06 (Critères 2 & 3): Même clé Agence sur 10 domaines via /v1/activate donne 200 (compteur n/10), et 11ème domaine donne 409 quota_exceeded', async () => {
    app.resetRateLimits();
    assert.ok(savedAgencyKeyM06, 'Agency key must exist from Critère 1');

    // Activate 10 distinct domains -> all succeed
    for (let i = 1; i <= 10; i++) {
      const actRes = await fetch(`${baseUrl}/v1/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          key: savedAgencyKeyM06,
          domain: `https://site-client-${i}.fr/blog`,
          plugin_version: '0.2.4'
        })
      });
      assert.equal(actRes.status, 200, `Activation for site ${i} must succeed with 200`);
      const actBody = await actRes.json();
      assert.equal(actBody.valid, true);
      assert.equal(actBody.activations, i, `Activation count should be ${i}`);
      assert.equal(actBody.sites, 10);
    }

    // 11th distinct domain -> rejected with 409 quota_exceeded
    const act11Res = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: savedAgencyKeyM06,
        domain: 'https://site-client-11.fr',
        plugin_version: '0.2.4'
      })
    });
    assert.equal(act11Res.status, 409, '11th distinct site must return 409');
    const act11Body = await act11Res.json();
    assert.equal(act11Body.error, 'quota_exceeded');
    assert.equal(act11Body.activations, 10);
    assert.equal(act11Body.sites, 10);
  });

  it('M-06 (Critère 4): La clé reste acceptée par /v1/updates après le 409 quota_exceeded', async () => {
    app.resetRateLimits();
    assert.ok(savedAgencyKeyM06);
    const updatesRes = await fetch(`${baseUrl}/v1/updates/rgaa-audit?key=${encodeURIComponent(savedAgencyKeyM06)}`);
    assert.equal(updatesRes.status, 200, 'Updates manifest must return 200 even after quota is reached');
    const envelope = await updatesRes.json();
    assert.ok(envelope.payload && envelope.signature);
    const manifest = JSON.parse(Buffer.from(envelope.payload, 'base64url').toString('utf8'));
    assert.ok(manifest.version, 'Manifest must contain version');
  });

  it('M-06 (Critère 5): order.paid produit Solo (e6ad51d6...) avec domain: "client.fr" signs domain: "client.fr"', async () => {
    app.resetRateLimits();
    const eventId = 'evt_m06_solo_' + Date.now();
    const orderId = 'ord_m06_solo_' + Date.now();
    const payload = {
      id: eventId,
      type: 'order.paid',
      data: {
        id: orderId,
        billing_reason: 'purchase',
        customer: { email: 'client-solo-m06@test.org' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7', // Solo product (1 site)
        custom_field_data: {
          domain: 'client.fr'
        }
      }
    };
    const headers = makeWebhookHeaders('polar', payload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'license_issued');

    const verification = verifyLicenseKey(body.key);
    assert.equal(verification.valid, true);
    assert.equal(verification.payload.domain, 'client.fr', 'Solo key must be signed with client.fr');
    assert.equal(verification.payload.sites, 1);

    const lic = db.getLicenseById(body.id);
    assert.equal(lic.domain, 'client.fr');
    assert.equal(lic.domain_raw, 'client.fr');
  });

  it('M-06 (Critère 6): Produit Solo sans domaine ou avec domain: "*" renvoie 422 missing_domain', async () => {
    app.resetRateLimits();
    const eventId1 = 'evt_m06_solo_nodom_' + Date.now();
    const payloadNoDom = {
      id: eventId1,
      type: 'order.paid',
      data: {
        id: 'ord_m06_solo_nodom_' + Date.now(),
        billing_reason: 'purchase',
        customer: { email: 'client-solo-nodom@test.org' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7',
        custom_field_data: {
          domain: '   '
        }
      }
    };
    const headers1 = makeWebhookHeaders('polar', payloadNoDom, config.polarWebhookSecret);
    const res1 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: headers1,
      body: JSON.stringify(payloadNoDom)
    });
    assert.equal(res1.status, 422);
    const b1 = await res1.json();
    assert.equal(b1.error, 'missing_domain');

    // With "*"
    const eventId2 = 'evt_m06_solo_star_' + Date.now();
    const payloadStar = {
      id: eventId2,
      type: 'order.paid',
      data: {
        id: 'ord_m06_solo_star_' + Date.now(),
        billing_reason: 'purchase',
        customer: { email: 'client-solo-star@test.org' },
        product_id: 'e6ad51d6-2e68-48b0-abdd-7038c571c6e7',
        custom_field_data: {
          domain: '*'
        }
      }
    };
    const headers2 = makeWebhookHeaders('polar', payloadStar, config.polarWebhookSecret);
    const res2 = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers: headers2,
      body: JSON.stringify(payloadStar)
    });
    assert.equal(res2.status, 422);
    const b2 = await res2.json();
    assert.equal(b2.error, 'missing_domain');
  });

  it('M-06 (Critère 7): Renouvellement d\'une Agence re-signe domain: "*", sites: 10, prolonge expires', async () => {
    app.resetRateLimits();
    assert.ok(savedAgencyOrderIdM06);
    const renewalPayload = {
      id: 'evt_renew_agency_m06_' + Date.now(),
      type: 'subscription.cycled',
      data: {
        id: savedAgencyOrderIdM06,
        current_period_end: '2032-10-30T00:00:00Z'
      }
    };
    const headers = makeWebhookHeaders('polar', renewalPayload, config.polarWebhookSecret);
    const res = await fetch(`${baseUrl}/v1/webhook/polar`, {
      method: 'POST',
      headers,
      body: JSON.stringify(renewalPayload)
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'license_renewed');
    assert.equal(body.expires, '2032-10-30');

    // Cryptographic verification of renewed key
    const verification = verifyLicenseKey(body.key);
    assert.equal(verification.valid, true);
    assert.equal(verification.payload.domain, '*', 'Renewed Agency key must retain domain: "*"');
    assert.equal(verification.payload.sites, 10, 'Renewed Agency key must retain sites: 10');
    assert.equal(verification.payload.plan, 'agence');
    assert.equal(verification.payload.expires, '2032-10-30');

    // Database verification
    const lic = db.getLicenseById(body.id);
    assert.equal(lic.domain, '*');
    assert.equal(lic.domain_raw, 'client.fr');
    assert.equal(lic.sites, 10);
    assert.equal(lic.expires_at, '2032-10-30');
  });
});
