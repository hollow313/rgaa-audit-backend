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

      const payload = {
        id: licenseId,
        license_id: licenseId,
        plan,
        sites,
        expires,
        domain: normalizedDomain,
        issued_at: new Date().toISOString()
      };

      const signed = signLicense(payload);

      db.createLicense({
        id: licenseId,
        email,
        plan,
        sites,
        domain: normalizedDomain,
        expires_at: expires,
        provider: 'manual',
        status: 'active',
        signed_key: signed.key
      });

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
