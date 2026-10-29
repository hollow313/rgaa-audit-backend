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

async function sendLicenseEmail({ to, plan, domain, expires, key, downloadUrl = null }) {
  const mailer = getTransporter();
  if (!mailer) {
    console.log(`[mailer] SMTP_URL not configured. Skipping email to ${to.replace(/(?<=.{2}).(?=.*@)/g, '*')}`);
    return false;
  }

  const dlLink = downloadUrl || `https://updates.rgaa-audit.eu/v1/updates/rgaa-audit?key=${encodeURIComponent(key)}`;
  const subject = 'Votre clé de licence RGAA Audit';
  const text = `Bonjour,

Merci pour votre commande !

Voici votre clé de licence pour RGAA Audit :
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
    console.log(`[mailer] License email sent successfully to ${to.replace(/(?<=.{2}).(?=.*@)/g, '*')}`);
    return true;
  } catch (err) {
    console.error(`[mailer] Failed to send email: ${err.message}`);
    return false;
  }
}

module.exports = {
  sendLicenseEmail
};
