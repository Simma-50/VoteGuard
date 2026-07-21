const nodemailer = require('nodemailer');
const { SMTP_USER, SMTP_PASS } = require('../config');

let transporter = null;

function getTransporter() {
  if (!SMTP_USER || !SMTP_PASS) return null;
  if (!transporter) {
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
  }
  return transporter;
}

function otpEmailHtml(code) {
  return `
  <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 440px; margin: auto; padding: 8px;">
    <h2 style="color:#0b1f3f; margin-bottom: 4px;">VoteGuard Security</h2>
    <p style="color:#374151;">Use the verification code below to complete your sign-in. This code expires in <strong>60 seconds</strong>.</p>
    <div style="font-size: 32px; font-weight: 700; letter-spacing: 8px; background: #f4f6fb; padding: 18px 24px; border-radius: 10px; text-align: center; color: #0b1f3f;">
      ${code}
    </div>
    <p style="color:#6b7280; font-size: 13px; margin-top: 18px;">
      If you did not request this code, no action is required — someone may have mistyped their email address.
    </p>
  </div>`;
}

/**
 * Sends a one-time verification code by email via Gmail SMTP.
 * If SMTP credentials are not configured (GMAIL_USER / GMAIL_APP_PASSWORD),
 * or the send fails, the code is only logged server-side as a fallback so
 * the application remains usable in a local/dev environment. It is never
 * returned to the browser in either case.
 */
async function sendOtpEmail(to, code) {
  const t = getTransporter();
  if (!t) {
    console.warn(`[Mailer] SMTP not configured (set GMAIL_USER / GMAIL_APP_PASSWORD in .env). OTP for ${to}: ${code}`);
    return { sent: false, reason: 'smtp_not_configured' };
  }
  try {
    await t.sendMail({
      from: `"VoteGuard Security" <${SMTP_USER}>`,
      to,
      subject: 'Your VoteGuard verification code',
      text: `Your VoteGuard verification code is ${code}. It expires in 60 seconds.`,
      html: otpEmailHtml(code)
    });
    return { sent: true };
  } catch (err) {
    console.error('[Mailer] Failed to send OTP email:', err.message);
    console.warn(`[Mailer] Falling back to console for this OTP: ${code}`);
    return { sent: false, reason: 'send_failed', error: err.message };
  }
}

function credentialsEmailHtml({ heading, intro, username, tempPassword }) {
  return `
  <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 480px; margin: auto; padding: 8px;">
    <h2 style="color:#0b1f3f; margin-bottom: 4px;">${heading}</h2>
    <p style="color:#374151;">${intro}</p>
    <table style="width:100%; border-collapse: collapse; margin: 18px 0;">
      <tr>
        <td style="padding:10px 14px; background:#f4f6fb; border-radius:8px 8px 0 0; color:#6b7280; font-size:12px; text-transform:uppercase;">Username</td>
      </tr>
      <tr>
        <td style="padding:6px 14px 16px; background:#f4f6fb; font-weight:700; font-size:16px; color:#0b1f3f;">${username}</td>
      </tr>
      <tr>
        <td style="padding:10px 14px; background:#f4f6fb; color:#6b7280; font-size:12px; text-transform:uppercase;">Temporary Password</td>
      </tr>
      <tr>
        <td style="padding:6px 14px 16px; background:#f4f6fb; border-radius:0 0 8px 8px; font-weight:700; font-size:16px; letter-spacing:1px; color:#0b1f3f;">${tempPassword}</td>
      </tr>
    </table>
    <p style="color:#374151;">You will be required to set a new password the first time you sign in, before completing multi-factor verification.</p>
    <p style="color:#6b7280; font-size: 13px; margin-top: 18px;">
      If you were not expecting this email, please contact your Election Official immediately.
    </p>
  </div>`;
}

/**
 * Emails a newly created director their username and temporary password.
 */
async function sendDirectorCredentialsEmail(to, username, tempPassword) {
  const t = getTransporter();
  if (!t) {
    console.warn(`[Mailer] SMTP not configured. Credentials for ${username} <${to}>: password = ${tempPassword}`);
    return { sent: false, reason: 'smtp_not_configured' };
  }
  try {
    await t.sendMail({
      from: `"VoteGuard Security" <${SMTP_USER}>`,
      to,
      subject: 'Your VoteGuard board director account has been created',
      text: `Username: ${username}\nTemporary password: ${tempPassword}\n\nYou will be required to set a new password on first sign-in.`,
      html: credentialsEmailHtml({
        heading: 'Welcome to VoteGuard',
        intro: 'An Election Official has created your board director account. Use the credentials below to sign in for the first time.',
        username,
        tempPassword
      })
    });
    return { sent: true };
  } catch (err) {
    console.error('[Mailer] Failed to send credentials email:', err.message);
    console.warn(`[Mailer] Falling back to console for ${username}: password = ${tempPassword}`);
    return { sent: false, reason: 'send_failed', error: err.message };
  }
}

/**
 * Emails a director a newly reset temporary password.
 */
async function sendPasswordResetEmail(to, username, tempPassword) {
  const t = getTransporter();
  if (!t) {
    console.warn(`[Mailer] SMTP not configured. Reset password for ${username} <${to}>: ${tempPassword}`);
    return { sent: false, reason: 'smtp_not_configured' };
  }
  try {
    await t.sendMail({
      from: `"VoteGuard Security" <${SMTP_USER}>`,
      to,
      subject: 'Your VoteGuard password has been reset',
      text: `Username: ${username}\nNew temporary password: ${tempPassword}\n\nYou will be required to set a new password on your next sign-in.`,
      html: credentialsEmailHtml({
        heading: 'Password Reset',
        intro: 'An Election Official has reset your VoteGuard password. Use the temporary password below to sign in.',
        username,
        tempPassword
      })
    });
    return { sent: true };
  } catch (err) {
    console.error('[Mailer] Failed to send reset email:', err.message);
    console.warn(`[Mailer] Falling back to console for ${username}: password = ${tempPassword}`);
    return { sent: false, reason: 'send_failed', error: err.message };
  }
}

function isConfigured() {
  return Boolean(SMTP_USER && SMTP_PASS);
}

function maskEmail(email) {
  const parts = String(email || '').split('@');
  if (parts.length !== 2) return email;
  const [user, domain] = parts;
  const visible = user.slice(0, Math.min(2, user.length));
  return `${visible}${'*'.repeat(Math.max(user.length - visible.length, 1))}@${domain}`;
}

module.exports = { sendOtpEmail, sendDirectorCredentialsEmail, sendPasswordResetEmail, isConfigured, maskEmail };
