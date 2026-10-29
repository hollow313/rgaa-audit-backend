const nodemailer = require('nodemailer');
const config = require('./config');

let transporter = null;
let lastMailStatus = null; // null = never tried, true = succeeded, false = failed
let lastMailError = null;

function getTransporter() {
  if (transporter) {
    return transporter;
  }
  if (!config.smtpUrl) {
    return null;
  }
  transporter = nodemailer.createTransport(config.smtpUrl);
  return transporter;
}

function setMockTransporter(mock) {
  transporter = mock;
  if (mock) {
    lastMailStatus = true;
    lastMailError = null;
  } else {
    lastMailStatus = null;
    lastMailError = null;
  }
}

function getMailHealth() {
  if (!transporter && (!config.smtpUrl || !config.smtpFrom)) {
    return false;
  }
  if (lastMailStatus === false) {
    return false;
  }
  return true;
}

function getLastMailError() {
  return lastMailError;
}

async function sendLicenseEmail({ to, plan, domain, expires, key, downloadUrl = null, isRenewal = false }) {
  const mailer = getTransporter();
  if (!mailer) {
    const msg = 'SMTP_URL or SMTP_FROM not configured';
    console.log(`[mailer] ${msg}. Skipping email to ${to.replace(/(?<=.{2}).(?=.*@)/g, '*')}`);
    return { success: false, ok: false, error: 'smtp_not_configured' };
  }

  const base = config.publicBaseUrl || 'https://updates.rgaa-audit.eu';
  const dlLink = downloadUrl || `${base}/v1/download/0.2.0.zip?key=${encodeURIComponent(key)}`;
  const subject = isRenewal ? 'Renouvellement de votre licence RGAA Audit' : 'Votre clé de licence RGAA Audit';
  const intro = isRenewal
    ? 'Votre abonnement a été renouvelé avec succès ! Voici votre nouvelle clé de licence mise à jour :'
    : 'Merci pour votre commande !\n\nVoici votre clé de licence pour RGAA Audit :';

  const text = `Bonjour,

${intro}
${key}

Détails de la licence :
- Plan : ${plan}
- Domaine associé : ${domain}
- Date d'expiration : ${expires}

Téléchargement de l'extension :
${dlLink}

Pour l'activer, rendez-vous dans l'administration WordPress de votre site :
RGAA Audit > Réglages > Clé de licence.

Bien cordialement,
L'équipe RGAA Audit
`;

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #f8fafc; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 30px;">
    <h2 style="color: #0f172a; margin-top: 0;">RGAA Audit</h2>
    <p>Bonjour,</p>
    <p>${isRenewal ? 'Votre abonnement a été renouvelé avec succès ! Voici votre nouvelle clé de licence mise à jour :' : 'Merci pour votre commande ! Voici votre clé de licence pour l\'extension RGAA Audit :'}</p>
    
    <div style="background: #f1f5f9; padding: 14px 18px; border-radius: 6px; font-family: monospace; font-size: 13px; word-break: break-all; margin: 20px 0; border: 1px solid #cbd5e1; color: #0f172a;">
      <strong>${key}</strong>
    </div>

    <h3 style="color: #334155; font-size: 16px;">Détails de la licence :</h3>
    <ul style="color: #475569; padding-left: 20px;">
      <li><strong>Plan :</strong> ${plan}</li>
      <li><strong>Domaine :</strong> ${domain}</li>
      <li><strong>Date d'expiration :</strong> ${expires}</li>
    </ul>

    <h3 style="color: #334155; font-size: 16px;">Téléchargement de l'extension :</h3>
    <p style="margin: 20px 0;">
      <a href="${dlLink}" style="display: inline-block; background: #2563eb; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 6px; font-weight: 600;">Télécharger le plugin (.zip)</a>
    </p>
    <p style="font-size: 12px; color: #64748b; word-break: break-all;">
      Lien direct : <a href="${dlLink}" style="color: #2563eb;">${dlLink}</a>
    </p>

    <p style="margin-top: 25px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 14px; color: #64748b;">
      Pour l'activer, rendez-vous dans l'administration WordPress de votre site :<br>
      <strong>RGAA Audit &gt; Réglages &gt; Clé de licence</strong>.
    </p>

    <p style="font-size: 14px; color: #64748b; margin-bottom: 0;">
      Bien cordialement,<br>
      <strong>L'équipe RGAA Audit</strong>
    </p>
  </div>
</body>
</html>`;

  try {
    await mailer.sendMail({
      from: config.smtpFrom,
      to,
      subject,
      text,
      html
    });
    lastMailStatus = true;
    lastMailError = null;
    console.log(`[mailer] ${isRenewal ? 'Renewal' : 'License'} email sent successfully to ${to.replace(/(?<=.{2}).(?=.*@)/g, '*')}`);
    return { success: true, ok: true };
  } catch (err) {
    lastMailStatus = false;
    lastMailError = err.message;
    console.error(`[mailer] Failed to send email: ${err.message}`);
    return { success: false, ok: false, error: err.message };
  }
}

async function sendLicenseRenewalEmail(opts) {
  return sendLicenseEmail({ ...opts, isRenewal: true });
}

module.exports = {
  sendLicenseEmail,
  sendLicenseRenewalEmail,
  getMailHealth,
  getLastMailError,
  setMockTransporter
};
