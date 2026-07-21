const path = require('path');
require('dotenv').config();

module.exports = {
  PORT: process.env.PORT || 4000,
  JWT_SECRET: process.env.JWT_SECRET || 'voteguard-demo-secret-CHANGE-IN-PRODUCTION',
  JWT_EXPIRES_IN: '20m',
  OTP_TTL_MS: 60 * 1000, // 60 seconds, per spec
  OTP_RESEND_COOLDOWN_MS: 20 * 1000, // minimum time between resend requests
  DATA_DIR: path.join(__dirname, 'data'),
  PKI_DIR: path.join(__dirname, 'data', 'pki'),
  STORE_DIR: path.join(__dirname, 'data', 'store'),
  CERT_VALIDITY_YEARS: 1,
  CA_VALIDITY_YEARS: 5,
  // Email OTP delivery (Gmail SMTP via Nodemailer)
  SMTP_USER: process.env.GMAIL_USER || '',
  SMTP_PASS: process.env.GMAIL_APP_PASSWORD || ''
};
