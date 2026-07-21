const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const store = require('../db/store');
const certService = require('../pki/certService');
const otp = require('../utils/otp');
const mailer = require('../utils/mailer');
const auditLog = require('../utils/logger');
const { JWT_SECRET, JWT_EXPIRES_IN } = require('../config');

const router = express.Router();

// NOTE: Public self-registration has been removed. Directors are onboarded
// exclusively by an Election Official/Admin (see POST /api/admin/directors),
// which generates the account, issues the X.509 certificate, and emails the
// director their username and a temporary password. The certificate-issuance
// logic itself (pki/certService.js) is unchanged from the original design —
// only *who* is allowed to trigger it has moved from "anyone" to "an
// authenticated Admin."

async function dispatchOtp(user, res, { resend } = {}) {
  const code = otp.generateOtp(user.username);
  auditLog.log(resend ? 'OTP_RESENT' : 'OTP_ISSUED', user.username, {});

  const sendResult = await mailer.sendOtpEmail(user.email, code);
  const maskedEmail = mailer.maskEmail(user.email);

  return res.json({
    message: sendResult.sent
      ? `A${resend ? ' new' : ''} verification code was emailed to ${maskedEmail}.`
      : `A${resend ? ' new' : ''} verification code was generated, but email delivery is not configured on this server (see server console).`,
    mfaRequired: true,
    maskedEmail,
    emailSent: sendResult.sent
  });
}

// ---------------- STEP 1: AUTHENTICATION - password check + OTP dispatch ----------------
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const users = store.load('users');
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password || '', user.passwordHash)) {
    auditLog.log('LOGIN_FAILED', username || 'unknown', { reason: 'bad credentials' });
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  if (user.disabled) {
    auditLog.log('LOGIN_BLOCKED_DISABLED', username, {});
    return res.status(403).json({ error: 'This account has been disabled. Contact your Election Official.' });
  }

  // Directors created by an Admin must set their own password before MFA
  // proceeds. No OTP is issued until this step is complete.
  if (user.mustChangePassword) {
    auditLog.log('PASSWORD_CHANGE_REQUIRED', username, {});
    return res.json({
      mustChangePassword: true,
      message: 'A password change is required before you can continue.'
    });
  }

  const certs = store.load('certificates');
  const cert = certs.find(c => c.serial === user.certSerial);
  const certCheck = certService.verifyCertificate(cert.certPem);
  if (!certCheck.valid) {
    auditLog.log('LOGIN_BLOCKED_CERT_INVALID', username, { reason: certCheck.reason });
    return res.status(403).json({ error: `Certificate invalid: ${certCheck.reason}` });
  }

  return dispatchOtp(user, res);
});

// ---------------- STEP 1b: Forced first-login password change ----------------
router.post('/force-change-password', async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  const users = store.load('users');
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(oldPassword || '', user.passwordHash)) {
    auditLog.log('PASSWORD_CHANGE_FAILED', username || 'unknown', { reason: 'bad current credentials' });
    return res.status(401).json({ error: 'Current username or password is incorrect' });
  }
  if (user.disabled) {
    return res.status(403).json({ error: 'This account has been disabled. Contact your Election Official.' });
  }
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  if (newPassword === oldPassword) {
    return res.status(400).json({ error: 'New password must be different from the temporary password' });
  }

  store.withCollection('users', (list) => {
    const u = list.find(x => x.id === user.id);
    u.passwordHash = bcrypt.hashSync(newPassword, 10);
    u.mustChangePassword = false;
  });
  auditLog.log('PASSWORD_CHANGED', username, {});

  const certs = store.load('certificates');
  const cert = certs.find(c => c.serial === user.certSerial);
  const certCheck = certService.verifyCertificate(cert.certPem);
  if (!certCheck.valid) {
    auditLog.log('LOGIN_BLOCKED_CERT_INVALID', username, { reason: certCheck.reason });
    return res.status(403).json({ error: `Certificate invalid: ${certCheck.reason}` });
  }

  return dispatchOtp(user, res);
});

// ---------------- STEP 2a-bis: Resend OTP email ----------------
router.post('/resend-otp', async (req, res) => {
  const { username } = req.body;
  const users = store.load('users');
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const check = otp.canResend(username);
  if (!check.allowed) {
    return res.status(429).json({ error: `Please wait ${check.retryAfterSeconds}s before requesting another code.` });
  }

  return dispatchOtp(user, res, { resend: true });
});

// ---------------- STEP 2b: AUTHENTICATION - MFA verification -> session token ----------------
router.post('/verify-otp', (req, res) => {
  const { username, code } = req.body;
  const result = otp.verifyOtp(username, code);
  if (!result.valid) {
    auditLog.log('OTP_FAILED', username, { reason: result.reason });
    return res.status(401).json({ error: result.reason });
  }

  const users = store.load('users');
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.disabled) {
    return res.status(403).json({ error: 'This account has been disabled. Contact your Election Official.' });
  }

  const token = jwt.sign(
    { sub: user.id, username: user.username, role: user.role, certSerial: user.certSerial },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  auditLog.log('LOGIN_SUCCESS', username, { role: user.role });

  return res.json({
    message: 'MFA verified. Session established.',
    token,
    role: user.role,
    hasVoted: user.hasVoted
  });
});

module.exports = router;
