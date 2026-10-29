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
      expires_at    TEXT NOT NULL,                 -- YYYY-MM-DD
      status        TEXT NOT NULL DEFAULT 'active',-- active | revoked | refunded
      provider      TEXT NOT NULL,                 -- polar | paddle | manual
      provider_ref  TEXT,                          -- id d'abonnement / de commande
      created_at    TEXT NOT NULL,
      revoked_at    TEXT,
      revoke_reason TEXT,
      signed_key    TEXT
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
      id          TEXT PRIMARY KEY,                -- id d'événement du MoR
      type        TEXT NOT NULL,
      received_at TEXT NOT NULL
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
      published_at TEXT NOT NULL
    );
  `);

  // Migration for signed_key column in case table already existed
  try {
    db.exec('ALTER TABLE licenses ADD COLUMN signed_key TEXT;');
  } catch {
    // Column already exists
  }
}

function createLicense(data, customDb = null) {
  const db = customDb || getDb();
  const stmt = db.prepare(`
    INSERT INTO licenses (
      id, email, plan, sites, domain, expires_at, status, provider, provider_ref, created_at, signed_key
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    data.id,
    data.email,
    data.plan || 'solo',
    data.sites || 1,
    data.domain,
    data.expires_at,
    data.status || 'active',
    data.provider || 'manual',
    data.provider_ref || null,
    data.created_at || new Date().toISOString(),
    data.signed_key || null
  );
  return getLicenseById(data.id, db);
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
      SELECT l.*, COUNT(a.domain) as activations_count
      FROM licenses l
      LEFT JOIN activations a ON a.license_id = l.id
      WHERE l.status = ?
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `);
    return stmt.all(filters.status);
  }
  const stmt = db.prepare(`
    SELECT l.*, COUNT(a.domain) as activations_count
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
  return { total, active, revoked, activations };
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

function recordEvent(id, type, customDb = null) {
  const db = customDb || getDb();
  const now = new Date().toISOString();
  try {
    const stmt = db.prepare('INSERT INTO events (id, type, received_at) VALUES (?, ?, ?)');
    stmt.run(id, type, now);
    return true; // Successfully recorded new event
  } catch {
    return false; // Already exists (idempotency triggered)
  }
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

module.exports = {
  getDb,
  initSchema,
  createLicense,
  getLicenseById,
  getLicenseByProviderRef,
  updateLicenseStatus,
  listLicenses,
  getLicenseStats,
  recordActivation,
  getActivations,
  getSharedLicenses,
  recordEvent,
  getRevokedLicenses,
  createRelease,
  getRelease,
  getLatestRelease
};
