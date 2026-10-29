const path = require('node:path');
const fs = require('node:fs');
require('dotenv').config();

function resolveKeysDir() {
  if (process.env.KEYS_DIR) {
    return path.resolve(process.env.KEYS_DIR);
  }
  // If running in docker with /keys mounted
  if (fs.existsSync('/keys')) {
    return '/keys';
  }
  return path.resolve(process.cwd(), 'keys');
}

const keysDir = resolveKeysDir();

const config = {
  port: parseInt(process.env.PORT || '30019', 10),
  host: process.env.HOST || '0.0.0.0',
  keysDir: keysDir,
  keyPath: process.env.KEY_PATH || path.join(keysDir, 'private.pem'),
  publicKeyPath: process.env.PUBLIC_KEY_PATH || path.join(keysDir, 'public.pem'),
  dbPath: process.env.DB_PATH || path.join(keysDir, 'licenses.sqlite'),
  autoGenerateKeys: process.env.AUTO_GENERATE_KEYS !== 'false',
  adminApiKey: process.env.ADMIN_API_KEY || '',
  polarWebhookSecret: process.env.POLAR_WEBHOOK_SECRET || '',
  paddleWebhookSecret: process.env.PADDLE_WEBHOOK_SECRET || '',
  smtpUrl: process.env.SMTP_URL || '',
  smtpFrom: process.env.SMTP_FROM || 'licenses@exemple.fr',
  crlValidityHours: parseInt(process.env.CRL_VALIDITY_HOURS || '24', 10),
  releasesDir: process.env.RELEASES_DIR || path.join(keysDir, 'releases')
};

module.exports = config;
