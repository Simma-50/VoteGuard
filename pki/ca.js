const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const { PKI_DIR, CA_VALIDITY_YEARS } = require('../config');

const CA_CERT_PATH = path.join(PKI_DIR, 'ca-cert.pem');
const CA_KEY_PATH = path.join(PKI_DIR, 'ca-key.pem');
const CRL_PATH = path.join(PKI_DIR, 'crl.json'); // list of revoked serial numbers

if (!fs.existsSync(PKI_DIR)) fs.mkdirSync(PKI_DIR, { recursive: true });

function generateCA() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + CA_VALIDITY_YEARS);

  const attrs = [
    { name: 'commonName', value: 'VoteGuard Root Certificate Authority' },
    { name: 'organizationName', value: 'VoteGuard Election Commission' },
    { shortName: 'OU', value: 'Trust Layer / PKI Infrastructure' }
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs); // self-signed
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true }
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  fs.writeFileSync(CA_CERT_PATH, forge.pki.certificateToPem(cert));
  fs.writeFileSync(CA_KEY_PATH, forge.pki.privateKeyToPem(keys.privateKey));
  if (!fs.existsSync(CRL_PATH)) fs.writeFileSync(CRL_PATH, JSON.stringify([], null, 2));

  console.log('[CA] New Root Certificate Authority generated at', PKI_DIR);
}

function ensureCA() {
  if (!fs.existsSync(CA_CERT_PATH) || !fs.existsSync(CA_KEY_PATH)) {
    generateCA();
  }
  if (!fs.existsSync(CRL_PATH)) fs.writeFileSync(CRL_PATH, JSON.stringify([], null, 2));
}

function getCACert() {
  return forge.pki.certificateFromPem(fs.readFileSync(CA_CERT_PATH, 'utf-8'), true);
}

function getCAKey() {
  return forge.pki.privateKeyFromPem(fs.readFileSync(CA_KEY_PATH, 'utf-8'));
}

function getCACertPem() {
  return fs.readFileSync(CA_CERT_PATH, 'utf-8');
}

function getCRL() {
  return JSON.parse(fs.readFileSync(CRL_PATH, 'utf-8'));
}

function revokeSerial(serial) {
  const crl = getCRL();
  if (!crl.includes(serial)) {
    crl.push(serial);
    fs.writeFileSync(CRL_PATH, JSON.stringify(crl, null, 2));
  }
}

function isRevoked(serial) {
  return getCRL().includes(serial);
}

module.exports = { ensureCA, getCACert, getCAKey, getCACertPem, getCRL, revokeSerial, isRevoked };
