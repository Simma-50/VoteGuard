const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const { PKI_DIR } = require('../config');

const ELECTION_KEY_PATH = path.join(PKI_DIR, 'election-aes.key');

function ensureElectionKey() {
  if (!fs.existsSync(ELECTION_KEY_PATH)) {
    const key = crypto.randomBytes(32); // AES-256
    fs.writeFileSync(ELECTION_KEY_PATH, key.toString('hex'));
    console.log('[Crypto] New AES-256 ballot encryption key generated.');
  }
}

function getElectionKey() {
  ensureElectionKey();
  return Buffer.from(fs.readFileSync(ELECTION_KEY_PATH, 'utf-8'), 'hex');
}

// ---- Ballot encryption (AES-256-GCM) ----
function encryptBallot(plaintextObj) {
  const key = getElectionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(plaintextObj), 'utf-8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

function decryptBallot({ ciphertext, iv, authTag }) {
  const key = getElectionKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'hex')),
    decipher.final()
  ]);
  return JSON.parse(plaintext.toString('utf-8'));
}

// ---- SHA-256 hashing ----
function sha256Hex(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

// ---- RSA-PSS digital signatures (using node-forge, matches X.509 keys) ----
function signHashWithPrivateKey(privateKeyPem, hashHex) {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const md = forge.md.sha256.create();
  md.update(forge.util.hexToBytes(hashHex));
  const pss = forge.pss.create({
    md: forge.md.sha256.create(),
    mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
    saltLength: 32
  });
  const signature = privateKey.sign(md, pss);
  return forge.util.bytesToHex(signature);
}

function verifySignatureWithPublicKeyPem(publicKeyPem, hashHex, signatureHex) {
  try {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const md = forge.md.sha256.create();
    md.update(forge.util.hexToBytes(hashHex));
    const pss = forge.pss.create({
      md: forge.md.sha256.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
      saltLength: 32
    });
    const signatureBytes = forge.util.hexToBytes(signatureHex);
    return publicKey.verify(md.digest().getBytes(), signatureBytes, pss);
  } catch (err) {
    return false;
  }
}

function verifySignatureWithCertPem(certPem, hashHex, signatureHex) {
  const cert = forge.pki.certificateFromPem(certPem);
  const publicKeyPem = forge.pki.publicKeyToPem(cert.publicKey);
  return verifySignatureWithPublicKeyPem(publicKeyPem, hashHex, signatureHex);
}

module.exports = {
  encryptBallot,
  decryptBallot,
  sha256Hex,
  signHashWithPrivateKey,
  verifySignatureWithPublicKeyPem,
  verifySignatureWithCertPem
};
