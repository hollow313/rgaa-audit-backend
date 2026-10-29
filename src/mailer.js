const nodemailer = require('nodemailer');
const config = require('./config');

let transporter = null;

function getTransporter() {
  if (!config.smtpUrl) {
    return null;
  }
  if (!transporter) {
    transporter = nodemailer.createTransport(config.smtpUrl);
  }
  return transporter;
}

async function sendLicenseEmail({ to, plan, domain, expires, key, downloadUrl = null, isRenewal = false }) {
  const mailer = getTransporter();
  if (!mailer) {
    console.log(`[mailer] SMTP_URL not configured. Skipping email to ${to.replace(/(?<=.{2}).(?=.*@)/g, '*')}`);
    return false;
  }

  const dlLink = downloadUrl || `https://updates.rgaa-audit.eu/v1/updates/rgaa-audit?key=${encodeURIComponent(key)}`;
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

  try {
    await mailer.sendMail({
      from: config.smtpFrom,
      to,
      subject,
      text
    });
    console.log(`[mailer] ${isRenewal ? 'Renewal' : 'License'} email sent successfully to ${to.replace(/(?<=.{2}).(?=.*@)/g, '*')}`);
    return true;
  } catch (err) {
    console.error(`[mailer] Failed to send email: ${err.message}`);
    return false;
  }
}

async function sendLicenseRenewalEmail(opts) {
  return sendLicenseEmail({ ...opts, isRenewal: true });
}

module.exports = {
  sendLicenseEmail,
  sendLicenseRenewalEmail
};
