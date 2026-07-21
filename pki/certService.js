const forge = require('node-forge');
const ca = require('./ca');
const { CERT_VALIDITY_YEARS } = require('../config');

let serialCounter = 1000;

function nextSerial() {
  serialCounter += 1;
  let hex = serialCounter.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex; // DER integers must be whole bytes
  // Only prefix a 00 byte if the high bit of the first byte is set (would
  // otherwise be misread as a negative number). Avoid any *extra* leading
  // zero bytes beyond that - node-forge's DER integer round-trip does not
  // tolerate superfluous zero-padding and will silently produce a
  // certificate whose stored signature no longer verifies against the
  // reloaded TBSCertificate bytes.
  if (parseInt(hex[0], 16) >= 8) hex = '00' + hex;
  return hex;
}

/**
 * Issues a new voter certificate.
 * NOTE (production consideration): in a real deployment the key pair would be
 * generated client-side (browser WebCrypto / hardware token) and only a CSR
 * (Certificate Signing Request) would be sent to the CA — the private key
 * would never leave the voter's device. Here, for demo simplicity, keys are
 * generated server-side, but the private key is still returned only once,
 * at enrollment time, exactly like a smart-card issuance ceremony.
 */
function issueVoterCertificate({ commonName, email, role }) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  const caCert = ca.getCACert();
  const caKey = ca.getCAKey();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = nextSerial();
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + CERT_VALIDITY_YEARS);

  const subjectAttrs = [
    { name: 'commonName', value: commonName },
    { name: 'emailAddress', value: email },
    { shortName: 'OU', value: role || 'voter' }
  ];
  const issuerAttrs = [
    { name: 'commonName', value: 'VoteGuard Root Certificate Authority' },
    { name: 'organizationName', value: 'VoteGuard Election Commission' },
    { shortName: 'OU', value: 'Trust Layer / PKI Infrastructure' }
  ];

  cert.setSubject(subjectAttrs);
  cert.setIssuer(issuerAttrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, nonRepudiation: true },
    { name: 'extKeyUsage', clientAuth: true }
  ]);

  cert.sign(caKey, forge.md.sha256.create());

  return {
    serial: cert.serialNumber,
    certPem: forge.pki.certificateToPem(cert),
    publicKeyPem: forge.pki.publicKeyToPem(keys.publicKey),
    privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
    issuedAt: cert.validity.notBefore.toISOString(),
    expiresAt: cert.validity.notAfter.toISOString()
  };
}

/**
 * Validates a certificate: signature chain to CA root, validity window, and CRL/OCSP revocation check.
 */
function verifyCertificate(certPem) {
  try {
    const cert = forge.pki.certificateFromPem(certPem, true);
    const caCert = ca.getCACert();

    const now = new Date();
    if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
      return { valid: false, reason: 'Certificate expired or not yet valid' };
    }

    const chainOk = caCert.verify(cert);
    if (!chainOk) {
      return { valid: false, reason: 'Certificate was not signed by trusted VoteGuard CA' };
    }

    if (ca.isRevoked(cert.serialNumber)) {
      return { valid: false, reason: 'Certificate has been revoked (found on CRL)' };
    }

    return { valid: true, serial: cert.serialNumber, subject: cert.subject.getField('CN').value };
  } catch (err) {
    return { valid: false, reason: 'Malformed certificate: ' + err.message };
  }
}

module.exports = { issueVoterCertificate, verifyCertificate };
