const { OTP_TTL_MS, OTP_RESEND_COOLDOWN_MS } = require('../config');

// In-memory store: username -> { code, expiresAt, attempts, lastSentAt }
const otpStore = new Map();

function generateOtp(username) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  otpStore.set(username, { code, expiresAt: Date.now() + OTP_TTL_MS, attempts: 0, lastSentAt: Date.now() });
  return code;
}

function canResend(username) {
  const entry = otpStore.get(username);
  if (!entry) return { allowed: true };
  const elapsed = Date.now() - entry.lastSentAt;
  if (elapsed < OTP_RESEND_COOLDOWN_MS) {
    return { allowed: false, retryAfterSeconds: Math.ceil((OTP_RESEND_COOLDOWN_MS - elapsed) / 1000) };
  }
  return { allowed: true };
}

function verifyOtp(username, code) {
  const entry = otpStore.get(username);
  if (!entry) return { valid: false, reason: 'No OTP requested or already used' };
  if (Date.now() > entry.expiresAt) {
    otpStore.delete(username);
    return { valid: false, reason: 'OTP expired' };
  }
  entry.attempts += 1;
  if (entry.attempts > 5) {
    otpStore.delete(username);
    return { valid: false, reason: 'Too many attempts' };
  }
  if (entry.code !== code) {
    return { valid: false, reason: 'Incorrect OTP' };
  }
  otpStore.delete(username);
  return { valid: true };
}

module.exports = { generateOtp, verifyOtp, canResend };
