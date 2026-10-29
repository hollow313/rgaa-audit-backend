const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');

let dbInstance = null;

function getDb(customDbPath = null) {
  if (dbInstance && !customDbPath) {
    return dbInstance;
  }

  const dbPath = customDbPath || config.dbPath;
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  let db;
  try {
    const BetterSqlite3 = require('better-sqlite3');
    db = new BetterSqlite3(dbPath);
  } catch {
    const { DatabaseSync } = require('node:sqlite');
    db = new DatabaseSync(dbPath);
  }

  // WAL mode for SQLite
  try {
    db.exec('PRAGMA journal_mode = WAL;');
  } catch {
    // Ignore if not supported in memory mode
  }
  db.exec('PRAGMA foreign_keys = ON;');

  initSchema(db);

  if (!customDbPath) {
    dbInstance = db;
  }
  return db;
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS licenses (
      id            TEXT PRIMARY KEY,              -- uuid v4, DANS le payload signé
      email         TEXT NOT NULL,
      plan          TEXT NOT NULL,                 -- solo | agence
      sites         INTEGER NOT NULL DEFAULT 1,
      domain        TEXT NOT NULL,                 -- host normalisé, ou '*'
      domain_raw    TEXT,                          -- saisie brute du client
      expires_at    TEXT NOT NULL,                 -- YYYY-MM-DD
      status        TEXT NOT NULL DEFAULT 'active',-- active | revoked | refunded
      provider      TEXT NOT NULL,                 -- polar | paddle | manual
      provider_ref  TEXT,                          -- id d'abonnement / de commande
      auto_renew    INTEGER NOT NULL DEFAULT 1,    -- renouvellement automatique actif
      created_at    TEXT NOT NULL,
      revoked_at    TEXT,
      revoke_reason TEXT,
      signed_key    TEXT,
      emailed_at    TEXT,
      mail_attempts INTEGER NOT NULL DEFAULT 0,
      mail_last_error TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_provider_ref ON licenses(provider, provider_ref);

    CREATE TABLE IF NOT EXISTS activations (
      license_id     TEXT NOT NULL,
      domain         TEXT NOT NULL,                -- host normalisé
      plugin_version TEXT,
      first_seen     TEXT NOT NULL,
      last_seen      TEXT NOT NULL,
      PRIMARY KEY (license_id, domain)
    );

    CREATE TABLE IF NOT EXISTS events (                          -- idempotence des webhooks
      id           TEXT PRIMARY KEY,                             -- id d'événement du MoR
      type         TEXT NOT NULL,
      status       TEXT NOT NULL DEFAULT 'received',             -- 'received', 'processed', 'failed'
      attempts     INTEGER NOT NULL DEFAULT 1,
      last_error   TEXT,
      received_at  TEXT NOT NULL,
      processed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS releases (
      version      TEXT PRIMARY KEY,
      zip_path     TEXT NOT NULL,
      sha256       TEXT NOT NULL,
      requires     TEXT,
      tested       TEXT,
      requires_php TEXT,
      download_url TEXT,
      changelog    TEXT,
      download_count INTEGER NOT NULL DEFAULT 0,
      published_at TEXT NOT NULL
    );
  `);

  // Migration for signed_key and auto_renew columns in case table already existed
  try {
    db.exec('ALTER TABLE licenses ADD COLUMN signed_key TEXT;');
  } catch {}
  try {
    db.exec('ALTER TABLE licenses ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 1;');
  } catch {}
  try {
    db.exec('ALTER TABLE licenses ADD COLUMN emailed_at TEXT;');
  } catch {}
  try {
    db.exec('ALTER TABLE licenses ADD COLUMN mail_attempts INTEGER NOT NULL DEFAULT 0;');
  } catch {}
  try {
    db.exec('ALTER TABLE licenses ADD COLUMN mail_last_error TEXT;');
  } catch {}
  try {
    db.exec('ALTER TABLE licenses ADD COLUMN domain_raw TEXT;');
  } catch {}
  try {
    db.exec("ALTER TABLE events ADD COLUMN status TEXT NOT NULL DEFAULT 'received';");
  } catch {}
  try {
    db.exec('ALTER TABLE releases ADD COLUMN download_count INTEGER NOT NULL DEFAULT 0;');
  } catch {}
  try {
    db.exec("ALTER TABLE events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 1;");
  } catch {}
  try {
    db.exec("ALTER TABLE events ADD COLUMN last_error TEXT;");
  } catch {}
  try {
    db.exec("ALTER TABLE events ADD COLUMN processed_at TEXT;");
  } catch {}

  // Revoke security-test licenses if present (§P0)
  try {
    db.prepare(`
      UPDATE licenses
      SET status = 'revoked', revoke_reason = 'security-test', revoked_at = datetime('now')
      WHERE id IN ('24fcfea8-238f-4f67-8366-f11ffd673f2b', '2b263539-976d-401e-bee1-ee8451ab2f21')
        AND status != 'revoked'
    `).run();
  } catch {
    // Table might not exist yet
  }
}

function createLicense(data, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare(`
    INSERT INTO licenses (
      id, email, plan, sites, domain, domain_raw, expires_at, status, provider, provider_ref, auto_renew, created_at, signed_key, emailed_at, mail_attempts, mail_last_error
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    data.id,
    data.email,
    data.plan || 'solo',
    data.sites || 1,
    data.domain,
    data.domain_raw || null,
    data.expires_at,
    data.status || 'active',
    data.provider || 'manual',
    data.provider_ref || null,
    data.auto_renew !== undefined ? (data.auto_renew ? 1 : 0) : 1,
    data.created_at || new Date().toISOString(),
    data.signed_key || null,
    data.emailed_at || null,
    data.mail_attempts || 0,
    data.mail_last_error || null
  );
  return getLicenseById(data.id, db);
}

function updateLicenseMailStatus(id, { success, error = null }, customDb = null) {
  const db = customDb || getDb();
  const now = new Date().toISOString();
  if (success) {
    const stmt = db.prepare(`
      UPDATE licenses
      SET emailed_at = ?,
          mail_attempts = mail_attempts + 1,
          mail_last_error = NULL
      WHERE id = ?
    `);
    stmt.run(now, id);
  } else {
    const stmt = db.prepare(`
      UPDATE licenses
      SET mail_attempts = mail_attempts + 1,
          mail_last_error = ?
      WHERE id = ?
    `);
    stmt.run(error ? String(error).slice(0, 500) : 'unknown_error', id);
  }
  return getLicenseById(id, db);
}

function getLicenseByEmail(email, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('SELECT * FROM licenses WHERE email = ? ORDER BY created_at DESC LIMIT 1');
  return stmt.get(email);
}

function setAutoRenew(id, autoRenew = 0, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('UPDATE licenses SET auto_renew = ? WHERE id = ?');
  stmt.run(autoRenew ? 1 : 0, id);
  return getLicenseById(id, db);
}

function updateLicenseExpires(id, newExpires, newSignedKey = null, customDb = null) {
  const db = customDb || getDb();
  if (newSignedKey) {
    const stmt = db.prepare('UPDATE licenses SET expires_at = ?, signed_key = ? WHERE id = ?');
    stmt.run(newExpires, newSignedKey, id);
  } else {
    const stmt = db.prepare('UPDATE licenses SET expires_at = ? WHERE id = ?');
    stmt.run(newExpires, id);
  }
  return getLicenseById(id, db);
}

function getLicenseById(id, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('SELECT * FROM licenses WHERE id = ?');
  return stmt.get(id);
}

function getLicenseByProviderRef(provider, provider_ref, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('SELECT * FROM licenses WHERE provider = ? AND provider_ref = ?');
  return stmt.get(provider, provider_ref);
}

function updateLicenseStatus(id, status, reason = null, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare(`
    UPDATE licenses
    SET status = ?, revoked_at = ?, revoke_reason = ?
    WHERE id = ?
  `);
  const now = new Date().toISOString();
  stmt.run(status, status === 'active' ? null : now, reason, id);
  return getLicenseById(id, db);
}

function listLicenses(filters = {}, customDb = null) {
  const db = customDb || getDb();
  if (filters.status) {
    const stmt = db.prepare(`
      SELECT l.*, COUNT(DISTINCT a.domain) as activations_count, GROUP_CONCAT(DISTINCT a.domain) as activated_domains
      FROM licenses l
      LEFT JOIN activations a ON a.license_id = l.id
      WHERE l.status = ?
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `);
    return stmt.all(filters.status);
  }
  const stmt = db.prepare(`
    SELECT l.*, COUNT(DISTINCT a.domain) as activations_count, GROUP_CONCAT(DISTINCT a.domain) as activated_domains
    FROM licenses l
    LEFT JOIN activations a ON a.license_id = l.id
    GROUP BY l.id
    ORDER BY l.created_at DESC
  `);
  return stmt.all();
}

function getLicenseStats(customDb = null) {
  const db = customDb || getDb();
  const total = db.prepare('SELECT COUNT(*) as count FROM licenses').get()?.count || 0;
  const active = db.prepare("SELECT COUNT(*) as count FROM licenses WHERE status = 'active'").get()?.count || 0;
  const revoked = db.prepare("SELECT COUNT(*) as count FROM licenses WHERE status IN ('revoked', 'refunded')").get()?.count || 0;
  const activations = db.prepare('SELECT COUNT(*) as count FROM activations').get()?.count || 0;
  const emails_pending = db.prepare("SELECT COUNT(*) as count FROM licenses WHERE emailed_at IS NULL AND mail_attempts = 0").get()?.count || 0;
  const emails_failed = db.prepare("SELECT COUNT(*) as count FROM licenses WHERE emailed_at IS NULL AND mail_attempts > 0").get()?.count || 0;
  const events_failed = db.prepare("SELECT COUNT(*) as count FROM events WHERE status = 'failed'").get()?.count || 0;
  return { total, active, revoked, activations, emails_pending, emails_failed, events_failed };
}

function deleteLicense(id, customDb = null) {
  const db = customDb || getDb();
  db.prepare('DELETE FROM activations WHERE license_id = ?').run(id);
  const result = db.prepare('DELETE FROM licenses WHERE id = ?').run(id);
  return result.changes > 0;
}

function purgeLicenses(filter = 'test', customDb = null) {
  const db = customDb || getDb();
  let whereClause = '';
  if (filter === 'test') {
    whereClause = "WHERE email LIKE '%@example.com' OR email LIKE '%@test.local' OR provider = 'manual' OR provider_ref IS NULL";
  } else if (filter === 'revoked') {
    whereClause = "WHERE status IN ('revoked', 'refunded')";
  } else if (filter === 'all') {
    whereClause = '';
  } else {
    throw new Error('invalid_filter');
  }

  const rows = db.prepare(`SELECT id FROM licenses ${whereClause}`).all();
  if (rows.length === 0) return 0;

  const ids = rows.map(r => r.id);
  const placeholders = ids.map(() => '?').join(',');
  db.prepare(`DELETE FROM activations WHERE license_id IN (${placeholders})`).run(...ids);
  const delStmt = db.prepare(`DELETE FROM licenses WHERE id IN (${placeholders})`);
  const info = delStmt.run(...ids);
  return typeof info?.changes === 'number' ? info.changes : ids.length;
}

function recordActivation({ license_id, domain, plugin_version }, customDb = null) {
  const db = customDb || getDb();
  const now = new Date().toISOString();
  const stmt = db.prepare(`
    INSERT INTO activations (license_id, domain, plugin_version, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(license_id, domain) DO UPDATE SET
      last_seen = excluded.last_seen,
      plugin_version = COALESCE(excluded.plugin_version, activations.plugin_version)
  `);
  stmt.run(license_id, domain, plugin_version || null, now, now);
}

function getActivations(license_id, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('SELECT * FROM activations WHERE license_id = ? ORDER BY last_seen DESC');
  return stmt.all(license_id);
}

function deleteActivation(license_id, domain, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('DELETE FROM activations WHERE license_id = ? AND domain = ?');
  const result = stmt.run(license_id, domain);
  return result.changes > 0;
}

function getSharedLicenses(customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare(`
    SELECT
      l.id,
      l.email,
      l.plan,
      l.sites,
      l.domain as licensed_domain,
      l.status,
      COUNT(DISTINCT a.domain) as active_domains_count,
      GROUP_CONCAT(a.domain, ', ') as active_domains
    FROM licenses l
    JOIN activations a ON a.license_id = l.id
    GROUP BY l.id
    HAVING COUNT(DISTINCT a.domain) > 1
    ORDER BY active_domains_count DESC
  `);
  return stmt.all();
}

function recordEventStart(id, type, customDb = null) {
  const db = customDb || getDb();
  const now = new Date().toISOString();

  const checkStmt = db.prepare('SELECT id, status, attempts FROM events WHERE id = ?');
  const existing = checkStmt.get(id);

  if (!existing) {
    const insertStmt = db.prepare(
      "INSERT INTO events (id, type, status, attempts, received_at) VALUES (?, ?, 'received', 1, ?)"
    );
    insertStmt.run(id, type, now);
    return { shouldProcess: true, isRetry: false, attempts: 1 };
  }

  // Already processed successfully: do not re-process
  if (existing.status === 'processed') {
    return { shouldProcess: false, status: 'already_processed', attempts: existing.attempts };
  }

  // If status is 'received' (retry while processing) or 'failed': allow retry
  const nextAttempts = (existing.attempts || 1) + 1;
  const updateStmt = db.prepare(
    "UPDATE events SET attempts = ?, type = ?, received_at = ? WHERE id = ?"
  );
  updateStmt.run(nextAttempts, type, now, id);
  return { shouldProcess: true, isRetry: true, attempts: nextAttempts };
}

function markEventProcessed(id, customDb = null) {
  const db = customDb || getDb();
  const now = new Date().toISOString();
  const stmt = db.prepare(
    "UPDATE events SET status = 'processed', processed_at = ?, last_error = NULL WHERE id = ?"
  );
  stmt.run(now, id);
}

function markEventFailed(id, errorMessage, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare(
    "UPDATE events SET status = 'failed', last_error = ? WHERE id = ?"
  );
  stmt.run(errorMessage ? String(errorMessage).slice(0, 500) : 'unknown_error', id);
}

function getEvent(id, customDb = null) {
  const db = customDb || getDb();
  return db.prepare('SELECT * FROM events WHERE id = ?').get(id);
}

function recordEvent(id, type, customDb = null) {
  const res = recordEventStart(id, type, customDb);
  if (res.shouldProcess) {
    markEventProcessed(id, customDb);
    return true;
  }
  return false;
}

function getRevokedLicenses(customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare(`
    SELECT id as license_id, revoked_at, revoke_reason as reason
    FROM licenses
    WHERE status IN ('revoked', 'refunded')
    ORDER BY revoked_at DESC
  `);
  return stmt.all();
}

function createRelease(data, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare(`
    INSERT INTO releases (
      version, zip_path, sha256, requires, tested, requires_php, download_url, changelog, published_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(version) DO UPDATE SET
      zip_path = excluded.zip_path,
      sha256 = excluded.sha256,
      requires = excluded.requires,
      tested = excluded.tested,
      requires_php = excluded.requires_php,
      download_url = excluded.download_url,
      changelog = excluded.changelog,
      published_at = excluded.published_at
  `);
  stmt.run(
    data.version,
    data.zip_path,
    data.sha256,
    data.requires || null,
    data.tested || null,
    data.requires_php || null,
    data.download_url || null,
    data.changelog || null,
    data.published_at || new Date().toISOString()
  );
  return getRelease(data.version, db);
}

function getRelease(version, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('SELECT * FROM releases WHERE version = ?');
  return stmt.get(version);
}

function getLatestRelease(customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('SELECT * FROM releases ORDER BY published_at DESC LIMIT 1');
  return stmt.get();
}

function listReleases(customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('SELECT * FROM releases ORDER BY published_at DESC');
  return stmt.all();
}

function deleteRelease(version, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('DELETE FROM releases WHERE version = ?');
  const info = stmt.run(version);
  return typeof info?.changes === 'number' && info.changes > 0;
}

function incrementReleaseDownloads(version, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare('UPDATE releases SET download_count = download_count + 1 WHERE version = ?');
  stmt.run(version);
}

function purgeOldEvents(days = 90, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare(`DELETE FROM events WHERE datetime(received_at) < datetime('now', '-' || ? || ' days')`);
  const info = stmt.run(days);
  return typeof info?.changes === 'number' ? info.changes : 0;
}

function revokeSecurityTestLicenses(customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare(`
    UPDATE licenses
    SET status = 'revoked', revoke_reason = 'security-test', revoked_at = datetime('now')
    WHERE id IN ('24fcfea8-238f-4f67-8366-f11ffd673f2b', '2b263539-976d-401e-bee1-ee8451ab2f21')
      AND status != 'revoked'
  `);
  const info = stmt.run();
  return typeof info?.changes === 'number' ? info.changes : 0;
}

module.exports = {
  getDb,
  initSchema,
  createLicense,
  getLicenseById,
  getLicenseByEmail,
  getLicenseByProviderRef,
  updateLicenseStatus,
  updateLicenseMailStatus,
  deleteLicense,
  purgeLicenses,
  setAutoRenew,
  updateLicenseExpires,
  listLicenses,
  getLicenseStats,
  recordActivation,
  getActivations,
  deleteActivation,
  getSharedLicenses,
  recordEvent,
  recordEventStart,
  markEventProcessed,
  markEventFailed,
  getEvent,
  purgeOldEvents,
  revokeSecurityTestLicenses,
  getRevokedLicenses,
  createRelease,
  getRelease,
  getLatestRelease,
  listReleases,
  deleteRelease,
  incrementReleaseDownloads
};
