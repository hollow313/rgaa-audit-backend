#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const config = require('./config');
const db = require('./db');
const {
  normalizeDomain,
  signLicense,
  verifyLicenseKey,
  initKeypair,
  sha256File
} = require('./crypto');

function parseArgs(args) {
  const result = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        result[key] = args[i + 1];
        i++;
      } else {
        result[key] = true;
      }
    } else {
      result._.push(arg);
    }
  }
  return result;
}

function printUsage() {
  console.log(`
RGAA Audit License CLI

Usage:
  node src/cli.js issue --email <email> --plan <solo|agence> --sites <n> --domain <domain> --expires <YYYY-MM-DD>
  node src/cli.js revoke --id <uuid> [--reason <reason>]
  node src/cli.js list [--shared]
  node src/cli.js publish --zip <path> --version <semver> [--requires <ver>] [--tested <ver>] [--requires-php <ver>]
  node src/cli.js verify --key <key>
  node src/cli.js keypair
  node src/cli.js purge-events [--days 90]
  node src/cli.js backup [--out <dir>] [--passphrase <pass>]
  node src/cli.js restore --file <backup.json> [--passphrase <pass>]
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  if (!command) {
    printUsage();
    process.exit(1);
  }

  // Ensure keys & DB are initialized
  initKeypair();
  db.getDb();

  switch (command) {
    case 'issue': {
      const email = args.email;
      const domain = args.domain;
      const expires = args.expires;
      const plan = args.plan || 'solo';
      const sites = args.sites ? parseInt(args.sites, 10) : 1;

      if (!email || !domain || !expires) {
        console.error('Error: --email, --domain and --expires are required');
        process.exit(1);
      }

      const licenseId = crypto.randomUUID();
      const normalizedDomain = normalizeDomain(domain);
      const nowIso = new Date().toISOString();

      // 1. Transactional insertion: INSERT first
      db.createLicense({
        id: licenseId,
        email,
        plan,
        sites,
        domain: normalizedDomain,
        expires_at: expires,
        provider: 'manual',
        status: 'active',
        created_at: nowIso
      });

      // 2. Sign key (with auto-control verification)
      const payload = {
        id: licenseId,
        plan,
        sites,
        expires,
        domain: normalizedDomain,
        issued_at: nowIso
      };
      const signed = signLicense(payload);

      // 3. Store signed_key
      db.getDb().prepare('UPDATE licenses SET signed_key = ? WHERE id = ?').run(signed.key, licenseId);

      console.log('\n--- Licence générée avec succès ---');
      console.log(`ID:      ${licenseId}`);
      console.log(`Email:   ${email}`);
      console.log(`Plan:    ${plan}`);
      console.log(`Sites:   ${sites}`);
      console.log(`Domaine: ${normalizedDomain}`);
      console.log(`Expire:  ${expires}`);
      console.log('\nClé de licence :');
      console.log(signed.key);
      console.log('-----------------------------------\n');
      break;
    }

    case 'revoke': {
      const id = args.id;
      const reason = args.reason || 'manual';

      if (!id) {
        console.error('Error: --id is required');
        process.exit(1);
      }

      const updated = db.updateLicenseStatus(id, 'revoked', reason);
      if (!updated) {
        console.error(`Error: License ${id} not found`);
        process.exit(1);
      }

      console.log(`Licence ${id} révoquée (motif : ${reason})`);
      break;
    }

    case 'list': {
      if (args.shared) {
        const shared = db.getSharedLicenses();
        console.log(`\n--- Clés partagées sur plusieurs domaines (${shared.length}) ---`);
        if (shared.length === 0) {
          console.log('Aucune licence active partagée sur plusieurs domaines.');
        } else {
          for (const item of shared) {
            console.log(`ID: ${item.id} | Email: ${item.email} | Plan: ${item.plan} | Domaines distincts: ${item.active_domains_count} (${item.active_domains})`);
          }
        }
        console.log('-------------------------------------------------------------\n');
      } else {
        const licenses = db.listLicenses();
        console.log(`\n--- Licences enregistrées (${licenses.length}) ---`);
        for (const lic of licenses) {
          console.log(`[${lic.status.toUpperCase()}] ID: ${lic.id} | ${lic.email} | ${lic.plan} | ${lic.domain} | Expire: ${lic.expires_at}`);
        }
        console.log('--------------------------------------------\n');
      }
      break;
    }

    case 'publish': {
      const zipPath = args.zip;
      const version = args.version;
      const requires = args.requires || '6.5';
      const tested = args.tested || '6.8';
      const requiresPhp = args['requires-php'] || '8.1';
      const downloadUrl = args['download-url'] || null;
      const changelog = args.changelog || null;

      if (!zipPath || !version) {
        console.error('Error: --zip and --version are required');
        process.exit(1);
      }

      if (!fs.existsSync(zipPath)) {
        console.error(`Error: File not found: ${zipPath}`);
        process.exit(1);
      }

      const sha256 = sha256File(zipPath);

      const release = db.createRelease({
        version,
        zip_path: path.resolve(zipPath),
        sha256,
        requires,
        tested,
        requires_php: requiresPhp,
        download_url: downloadUrl,
        changelog,
        published_at: new Date().toISOString()
      });

      console.log(`\nRelease ${version} publiée avec succès :`);
      console.log(`SHA256: ${sha256}`);
      console.log(`Fichier: ${release.zip_path}\n`);
      break;
    }

    case 'verify': {
      const key = args.key;
      if (!key) {
        console.error('Error: --key is required');
        process.exit(1);
      }

      const result = verifyLicenseKey(key);
      if (!result.valid) {
        console.error(`Verification FAILED: ${result.error}`);
        process.exit(1);
      }

      console.log('\n--- Signature VALIDE ---');
      console.log(JSON.stringify(result.payload, null, 2));
      console.log('------------------------\n');
      break;
    }

    case 'keypair': {
      console.log(`Paire de clés RSA prête.`);
      console.log(`Clé privée : ${config.keyPath}`);
      console.log(`Clé publique : ${config.publicKeyPath}`);
      break;
    }

    case 'purge-events': {
      const days = args.days ? parseInt(args.days, 10) : 90;
      const count = db.purgeOldEvents(days);
      console.log(`Purge terminée : ${count} événement(s) de plus de ${days} jours supprimé(s).`);
      break;
    }

    case 'backup': {
      const outDir = args.out || path.join(process.cwd(), 'backups');
      if (!fs.existsSync(outDir)) {
        fs.mkdirSync(outDir, { recursive: true });
      }

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const tempSqlite = path.join(outDir, `licenses-snap-${timestamp}.sqlite`);

      // Consistent live DB snapshot via SQLite VACUUM INTO
      const database = db.getDb();
      database.prepare(`VACUUM INTO ?`).run(tempSqlite);

      const bundle = {
        timestamp: new Date().toISOString(),
        database: fs.readFileSync(tempSqlite).toString('base64'),
        privateKey: fs.readFileSync(config.keyPath, 'utf8'),
        publicKey: fs.readFileSync(config.publicKeyPath, 'utf8')
      };

      try {
        fs.unlinkSync(tempSqlite);
      } catch {}

      const jsonStr = JSON.stringify(bundle);
      const passphrase = args.passphrase || process.env.BACKUP_PASSPHRASE;

      if (passphrase) {
        const salt = crypto.randomBytes(16);
        const iv = crypto.randomBytes(12);
        const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(Buffer.from(jsonStr, 'utf8')), cipher.final()]);
        const tag = cipher.getAuthTag();

        const encryptedBundle = {
          encrypted: true,
          salt: salt.toString('base64'),
          iv: iv.toString('base64'),
          tag: tag.toString('base64'),
          data: encrypted.toString('base64')
        };
        const finalFile = path.join(outDir, `backup-rgaa-${timestamp}.enc.json`);
        fs.writeFileSync(finalFile, JSON.stringify(encryptedBundle, null, 2), { mode: 0o600 });
        console.log(`Sauvegarde chiffrée créée avec succès : ${finalFile}`);
      } else {
        const finalFile = path.join(outDir, `backup-rgaa-${timestamp}.json`);
        fs.writeFileSync(finalFile, jsonStr, { mode: 0o600 });
        console.log(`Sauvegarde créée avec succès : ${finalFile}`);
      }
      break;
    }

    case 'restore': {
      const file = args.file;
      if (!file || !fs.existsSync(file)) {
        console.error('Error: --file <path> is required and must exist');
        process.exit(1);
      }

      const content = fs.readFileSync(file, 'utf8');
      const parsed = JSON.parse(content);
      let bundle;

      if (parsed.encrypted) {
        const passphrase = args.passphrase || process.env.BACKUP_PASSPHRASE;
        if (!passphrase) {
          console.error('Error: Backup is encrypted. Please provide --passphrase');
          process.exit(1);
        }
        const salt = Buffer.from(parsed.salt, 'base64');
        const iv = Buffer.from(parsed.iv, 'base64');
        const tag = Buffer.from(parsed.tag, 'base64');
        const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(Buffer.from(parsed.data, 'base64')), decipher.final()]);
        bundle = JSON.parse(decrypted.toString('utf8'));
      } else {
        bundle = parsed;
      }

      if (!bundle.privateKey || !bundle.publicKey || !bundle.database) {
        console.error('Error: Invalid backup archive format');
        process.exit(1);
      }

      fs.writeFileSync(config.keyPath, bundle.privateKey, { mode: 0o600 });
      fs.writeFileSync(config.publicKeyPath, bundle.publicKey, { mode: 0o644 });
      fs.writeFileSync(config.dbPath, Buffer.from(bundle.database, 'base64'));

      console.log(`Restauration terminée dans ${config.keysDir}`);
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      printUsage();
      process.exit(1);
  }
}

main().catch(err => {
  console.error('Fatal CLI error:', err);
  process.exit(1);
});
