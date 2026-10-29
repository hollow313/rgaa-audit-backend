const express = require('express');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');
const db = require('./db');
const {
  normalizeDomain,
  signLicense,
  signEnvelope,
  verifyLicenseKey,
  getPublicKey,
  initKeypair
} = require('./crypto');
const { sendLicenseEmail } = require('./mailer');

const app = express();

// Parse json with raw body capture for webhooks
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Serve static frontend files from public/
const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
}

// In-memory rate limiting maps
const keyLimits = new Map();
const ipLimits = new Map();

// Periodic cleanup of rate limits every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of keyLimits.entries()) {
    if (now - v.start > 60000) keyLimits.delete(k);
  }
  for (const [k, v] of ipLimits.entries()) {
    if (now - v.start > 3600000) ipLimits.delete(k);
  }
}, 10 * 60 * 1000).unref();

function rateLimit(map, key, maxRequests, windowMs) {
  const now = Date.now();
  let record = map.get(key);
  if (!record || now - record.start > windowMs) {
    record = { start: now, count: 0 };
    map.set(key, record);
  }
  record.count++;
  return record.count <= maxRequests;
}

// Structured JSON logger (no emails, no license keys in stdout)
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    // Only log API requests, skip static asset spam
    if (req.path.startsWith('/v1/') || req.path.startsWith('/api/') || req.path === '/healthz') {
      const duration = Date.now() - start;
      const logEntry = {
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.baseUrl + req.path,
        status: res.statusCode,
        duration_ms: duration,
        ip: req.ip || req.socket.remoteAddress
      };
      process.stdout.write(JSON.stringify(logEntry) + '\n');
    }
  });
  next();
});

// Admin authorization middleware
function requireAdmin(req, res, next) {
  if (!config.adminApiKey) {
    return next();
  }
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : req.headers['x-admin-key'];
  if (token !== config.adminApiKey) {
    return res.status(401).json({ error: 'unauthorized', message: 'Invalid admin credentials' });
  }
  next();
}

/* ----------------------------------------------------
   Web UI Dashboard API
---------------------------------------------------- */

// Serve index.html explicitly on root
app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  res.send('RGAA License Server is running.');
});

// Stats for dashboard
app.get('/api/stats', (req, res) => {
  try {
    const stats = db.getLicenseStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// List licenses with signed keys for the dashboard
app.get('/api/licenses', (req, res) => {
  try {
    const rawLicenses = db.listLicenses();
    const licensesWithKeys = rawLicenses.map(lic => {
      let key = lic.signed_key;
      if (!key) {
        const signed = signLicense({
          id: lic.id,
          license_id: lic.id,
          plan: lic.plan,
          sites: lic.sites,
          expires: lic.expires_at,
          domain: lic.domain,
          issued_at: lic.created_at
        });
        key = signed.key;
      }
      const activations = db.getActivations(lic.id);
      return {
        ...lic,
        key,
        activations
      };
    });
    res.json(licensesWithKeys);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Issue license from Web UI
app.post('/api/licenses', (req, res) => {
  try {
    const { email, plan, sites, domain, expires } = req.body || {};
    if (!email || !domain || !expires) {
      return res.status(400).json({ error: 'Email, domaine et date d\'expiration requis.' });
    }

    const licenseId = crypto.randomUUID();
    const normalizedDomain = normalizeDomain(domain);
    const sitesCount = sites ? parseInt(sites, 10) : 1;

    const payload = {
      id: licenseId,
      license_id: licenseId,
      plan: plan || 'solo',
      sites: sitesCount,
      expires: expires,
      domain: normalizedDomain,
      issued_at: new Date().toISOString()
    };

    const signed = signLicense(payload);

    const record = db.createLicense({
      id: licenseId,
      email,
      plan: payload.plan,
      sites: sitesCount,
      domain: normalizedDomain,
      expires_at: expires,
      provider: 'web',
      status: 'active',
      signed_key: signed.key
    });

    res.json({
      ok: true,
      license: record,
      key: signed.key
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Revoke license from Web UI
app.post('/api/licenses/:id/revoke', (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body || {};
    const updated = db.updateLicenseStatus(id, 'revoked', reason || 'web_revocation');
    if (!updated) {
      return res.status(404).json({ error: 'Licence introuvable' });
    }
    res.json({ ok: true, license: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Shared licenses for dashboard alerts
app.get('/api/shared', (req, res) => {
  try {
    const shared = db.getSharedLicenses();
    res.json(shared);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ----------------------------------------------------
   Endpoints
---------------------------------------------------- */

// Healthcheck (§8 Ops)
app.get('/healthz', (req, res) => {
  try {
    const row = db.getDb().prepare('SELECT 1 as ok').get();
    res.json({ ok: true, db: Boolean(row && row.ok === 1) });
  } catch (err) {
    res.status(500).json({ ok: false, db: false, error: err.message });
  }
});

// Public key retrieval
app.get('/v1/public-key', (req, res) => {
  try {
    const pub = getPublicKey();
    res.type('text/plain').send(pub);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Activation (§4)
app.post('/v1/activate', (req, res) => {
  const ip = req.ip || req.socket.remoteAddress;
  if (!rateLimit(ipLimits, ip, 60, 60 * 60 * 1000)) {
    return res.status(429).json({ error: 'rate_limited', message: 'Too many requests from this IP' });
  }

  const { key, domain, plugin_version } = req.body || {};
  if (!key || !domain) {
    return res.status(400).json({ error: 'bad_request', message: 'Missing key or domain' });
  }

  // Rate limit by key (10 req/min)
  if (!rateLimit(keyLimits, key, 10, 60 * 1000)) {
    return res.status(429).json({ error: 'rate_limited', message: 'Too many requests for this license key' });
  }

  // Verify signature
  const verification = verifyLicenseKey(key);
  if (!verification.valid) {
    return res.status(403).json({ error: 'invalid_license', message: 'License signature verification failed' });
  }

  const payload = verification.payload;
  const licenseId = payload.license_id || payload.id;

  // Domain verification (host normalized)
  const clientDomainNorm = normalizeDomain(domain);
  const payloadDomainNorm = normalizeDomain(payload.domain);

  if (payloadDomainNorm !== '*' && payloadDomainNorm !== clientDomainNorm) {
    return res.status(409).json({
      error: 'domain_mismatch',
      message: `Domain ${clientDomainNorm} does not match licensed domain ${payloadDomainNorm}`
    });
  }

  // Check expiration date
  if (payload.expires) {
    const expDate = new Date(payload.expires);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (!isNaN(expDate.getTime()) && expDate < today) {
      return res.status(403).json({ error: 'license_expired', message: 'License has expired' });
    }
  }

  // If license ID exists in DB, check revocation status
  if (licenseId) {
    const licenseInDb = db.getLicenseById(licenseId);
    if (licenseInDb) {
      if (licenseInDb.status === 'revoked' || licenseInDb.status === 'refunded') {
        return res.status(403).json({ error: 'license_revoked', message: 'License has been revoked' });
      }
    }
    // Record activation
    db.recordActivation({
      license_id: licenseId,
      domain: clientDomainNorm,
      plugin_version: plugin_version || null
    });
  }

  const nextUpdate = new Date(Date.now() + config.crlValidityHours * 3600 * 1000).toISOString();

  res.json({
    valid: true,
    plan: payload.plan || 'solo',
    expires: payload.expires,
    next_update: nextUpdate
  });
});

// CRL (Certificate Revocation List) (§1.2 & §4)
app.get('/v1/crl', (req, res) => {
  const revoked = db.getRevokedLicenses();
  const now = new Date();
  const nextUpdate = new Date(now.getTime() + config.crlValidityHours * 3600 * 1000);

  const crl = {
    version: 1,
    issued_at: now.toISOString(),
    next_update: nextUpdate.toISOString(),
    revoked: revoked.map(r => ({
      license_id: r.license_id,
      revoked_at: r.revoked_at,
      reason: r.reason || 'revoked'
    }))
  };

  const signed = signEnvelope(crl);

  const rawJson = JSON.stringify(signed);
  const etag = `W/"${crypto.createHash('sha256').update(rawJson).digest('hex').substring(0, 16)}"`;

  if (req.headers['if-none-match'] === etag) {
    return res.status(304).end();
  }

  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('ETag', etag);
  res.json(signed);
});

// Plugin updates manifest (§1.3 & §4)
app.get('/v1/updates/:slug', (req, res) => {
  const { slug } = req.params;
  const key = req.query.key;

  // If key is supplied, verify it
  if (key) {
    const verification = verifyLicenseKey(key);
    if (!verification.valid) {
      return res.status(403).json({ error: 'invalid_license' });
    }
  }

  const release = db.getLatestRelease();
  if (!release) {
    return res.status(404).json({ error: 'no_release_found' });
  }

  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.get('host');
  const baseUrl = `${protocol}://${host}`;

  const manifest = {
    slug,
    version: release.version,
    requires: release.requires || '6.5',
    tested: release.tested || '6.8',
    requires_php: release.requires_php || '8.1',
    download_url: release.download_url || `${baseUrl}/v1/download/${release.version}.zip`,
    sha256: release.sha256,
    published_at: release.published_at,
    changelog: release.changelog || ''
  };

  const signed = signEnvelope(manifest);
  res.json(signed);
});

// Plugin zip download (§4)
app.get('/v1/download/:version.zip', (req, res) => {
  const { version } = req.params;
  const key = req.query.key;

  if (!key) {
    return res.status(403).json({ error: 'license_key_required' });
  }

  const verification = verifyLicenseKey(key);
  if (!verification.valid) {
    return res.status(403).json({ error: 'invalid_license' });
  }

  const release = db.getRelease(version);
  if (!release || !fs.existsSync(release.zip_path)) {
    return res.status(404).json({ error: 'release_not_found' });
  }

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('ETag', `"${release.sha256}"`);
  res.sendFile(path.resolve(release.zip_path));
});

// Webhook Polar (§4)
app.post('/v1/webhook/polar', async (req, res) => {
  const event = req.body;
  if (!event || !event.type || !event.id) {
    return res.status(400).json({ error: 'invalid_webhook_payload' });
  }

  // Idempotency check (§3, §4, §6)
  const isNew = db.recordEvent(event.id, event.type);
  if (!isNew) {
    return res.status(200).json({ status: 'already_processed' });
  }

  try {
    if (event.type === 'subscription.created' || event.type === 'order.paid') {
      const data = event.data || {};
      const licenseId = crypto.randomUUID();
      const email = data.customer_email || data.email || 'customer@example.com';
      const plan = data.plan || 'solo';
      const sites = data.sites || 1;
      const domain = data.domain || '*';

      const expiresDate = new Date();
      expiresDate.setFullYear(expiresDate.getFullYear() + 1);
      const expires = expiresDate.toISOString().split('T')[0];

      const payload = {
        id: licenseId,
        license_id: licenseId,
        plan,
        sites,
        expires,
        domain: normalizeDomain(domain),
        issued_at: new Date().toISOString()
      };

      const signed = signLicense(payload);

      db.createLicense({
        id: licenseId,
        email,
        plan,
        sites,
        domain: normalizeDomain(domain),
        expires_at: expires,
        provider: 'polar',
        provider_ref: data.subscription_id || data.order_id || event.id,
        status: 'active',
        signed_key: signed.key
      });

      // Async email sending
      sendLicenseEmail({
        to: email,
        plan,
        domain,
        expires,
        key: signed.key
      }).catch(err => console.error(`[webhook] Mail error: ${err.message}`));

      return res.status(200).json({ status: 'license_issued', id: licenseId });
    }

    if (event.type === 'subscription.cancelled' || event.type === 'order.refunded') {
      const data = event.data || {};
      const ref = data.subscription_id || data.order_id;
      if (ref) {
        const lic = db.getLicenseByProviderRef('polar', ref);
        if (lic) {
          db.updateLicenseStatus(lic.id, 'revoked', event.type);
        }
      }
      return res.status(200).json({ status: 'license_revoked' });
    }

    res.status(200).json({ status: 'ignored' });
  } catch (err) {
    console.error(`[webhook] Polar handler error: ${err.message}`);
    res.status(500).json({ error: 'internal_error' });
  }
});

// Webhook Paddle (§4)
app.post('/v1/webhook/paddle', async (req, res) => {
  const event = req.body;
  const eventId = event?.event_id || event?.id;
  const eventType = event?.event_type || event?.type;

  if (!eventId || !eventType) {
    return res.status(400).json({ error: 'invalid_webhook_payload' });
  }

  const isNew = db.recordEvent(eventId, eventType);
  if (!isNew) {
    return res.status(200).json({ status: 'already_processed' });
  }

  try {
    if (eventType === 'subscription.created' || eventType === 'transaction.completed') {
      const data = event.data || {};
      const licenseId = crypto.randomUUID();
      const email = data.customer?.email || 'customer@example.com';
      const plan = data.custom_data?.plan || 'solo';
      const sites = data.custom_data?.sites || 1;
      const domain = data.custom_data?.domain || '*';

      const expiresDate = new Date();
      expiresDate.setFullYear(expiresDate.getFullYear() + 1);
      const expires = expiresDate.toISOString().split('T')[0];

      const payload = {
        id: licenseId,
        license_id: licenseId,
        plan,
        sites,
        expires,
        domain: normalizeDomain(domain),
        issued_at: new Date().toISOString()
      };

      const signed = signLicense(payload);

      db.createLicense({
        id: licenseId,
        email,
        plan,
        sites,
        domain: normalizeDomain(domain),
        expires_at: expires,
        provider: 'paddle',
        provider_ref: data.subscription_id || data.id || eventId,
        status: 'active',
        signed_key: signed.key
      });

      sendLicenseEmail({
        to: email,
        plan,
        domain,
        expires,
        key: signed.key
      }).catch(err => console.error(`[webhook] Mail error: ${err.message}`));

      return res.status(200).json({ status: 'license_issued', id: licenseId });
    }

    if (eventType === 'subscription.canceled' || eventType === 'adjustment.created') {
      const data = event.data || {};
      const ref = data.subscription_id || data.id;
      if (ref) {
        const lic = db.getLicenseByProviderRef('paddle', ref);
        if (lic) {
          db.updateLicenseStatus(lic.id, 'revoked', eventType);
        }
      }
      return res.status(200).json({ status: 'license_revoked' });
    }

    res.status(200).json({ status: 'ignored' });
  } catch (err) {
    console.error(`[webhook] Paddle handler error: ${err.message}`);
    res.status(500).json({ error: 'internal_error' });
  }
});

/* ----------------------------------------------------
   Admin Endpoints
---------------------------------------------------- */

// Issue license via API
app.post('/v1/admin/issue', requireAdmin, (req, res) => {
  const { email, plan, sites, domain, expires, provider, provider_ref } = req.body || {};

  if (!email || !domain || !expires) {
    return res.status(400).json({ error: 'Missing required fields: email, domain, expires' });
  }

  const licenseId = crypto.randomUUID();
  const normalizedDomain = normalizeDomain(domain);

  const payload = {
    id: licenseId,
    license_id: licenseId,
    plan: plan || 'solo',
    sites: sites ? parseInt(sites, 10) : 1,
    expires: expires,
    domain: normalizedDomain,
    issued_at: new Date().toISOString()
  };

  const signed = signLicense(payload);

  const licenseRecord = db.createLicense({
    id: licenseId,
    email,
    plan: payload.plan,
    sites: payload.sites,
    domain: normalizedDomain,
    expires_at: expires,
    provider: provider || 'manual',
    provider_ref: provider_ref || null,
    status: 'active',
    signed_key: signed.key
  });

  res.json({
    license: licenseRecord,
    key: signed.key
  });
});

// Revoke license via API
app.post('/v1/admin/revoke', requireAdmin, (req, res) => {
  const { id, reason } = req.body || {};
  if (!id) {
    return res.status(400).json({ error: 'Missing license id' });
  }

  const updated = db.updateLicenseStatus(id, 'revoked', reason || 'manual');
  if (!updated) {
    return res.status(404).json({ error: 'License not found' });
  }

  res.json({ ok: true, license: updated });
});

// List licenses / shared licenses
app.get('/v1/admin/licenses', requireAdmin, (req, res) => {
  if (req.query.shared === 'true') {
    const shared = db.getSharedLicenses();
    return res.json({ shared });
  }
  const list = db.listLicenses({ status: req.query.status });
  res.json({ licenses: list });
});

// Publish release via API
app.post('/v1/admin/publish', requireAdmin, (req, res) => {
  const { version, zip_path, requires, tested, requires_php, download_url, changelog } = req.body || {};

  if (!version || !zip_path) {
    return res.status(400).json({ error: 'Missing version or zip_path' });
  }

  if (!fs.existsSync(zip_path)) {
    return res.status(400).json({ error: `File not found: ${zip_path}` });
  }

  const sha256 = crypto.createHash('sha256').update(fs.readFileSync(zip_path)).digest('hex');

  const release = db.createRelease({
    version,
    zip_path: path.resolve(zip_path),
    sha256,
    requires: requires || '6.5',
    tested: tested || '6.8',
    requires_php: requires_php || '8.1',
    download_url: download_url || null,
    changelog: changelog || null,
    published_at: new Date().toISOString()
  });

  res.json({ ok: true, release });
});

// Start server if run directly
if (require.main === module) {
  initKeypair();
  db.getDb(); // initialize database

  app.listen(config.port, config.host, () => {
    console.log(`[server] RGAA Audit License Server running on http://${config.host}:${config.port}`);
    console.log(`[server] Keys directory: ${config.keysDir}`);
    console.log(`[server] Database: ${config.dbPath}`);
  });
}

module.exports = app;
