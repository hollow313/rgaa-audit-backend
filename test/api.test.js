const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const app = require('../src/server');
const db = require('../src/db');
const config = require('../src/config');
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

  it('GET /healthz returns ok and db status when webhook secrets configured', async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.ok, true);
    assert.equal(data.db, true);
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
          customer_email: 'buyer-sw@test.org',
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
        order_id: 'ord_retry_' + Date.now()
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
  });
});
