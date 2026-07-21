const express = require('express');
const { v4: uuidv4 } = require('uuid');
const store = require('../db/store');
const certService = require('../pki/certService');
const cryptoService = require('../pki/cryptoService');
const { requireAuth, requireRole } = require('../middleware/auth');
const auditLog = require('../utils/logger');

const router = express.Router();

// ---- View Candidates ----
router.get('/candidates', requireAuth, (req, res) => {
  const candidates = store.load('candidates');
  const election = store.load('election');
  res.json({ election, candidates: candidates.map(c => ({ id: c.id, name: c.name, party: c.party })) });
});

// ---- Check my voter status ----
router.get('/status', requireAuth, requireRole('voter'), (req, res) => {
  const users = store.load('users');
  const user = users.find(u => u.username === req.user.username);
  const certs = store.load('certificates');
  const cert = certs.find(c => c.serial === user.certSerial);
  const certCheck = certService.verifyCertificate(cert.certPem);
  res.json({
    username: user.username,
    hasVoted: user.hasVoted,
    certSerial: user.certSerial,
    certificateValid: certCheck.valid,
    certificateStatus: certCheck.valid ? 'valid' : certCheck.reason
  });
});

// ---- View my own certificate (Certificate page) ----
// Per the Certificate Workflow requirement: certificates/keys are never shown
// at account-creation time. A director may only view their certificate here,
// after authenticating, and only the public certificate — never the private
// signing key, which remains server-side only.
router.get('/certificate', requireAuth, requireRole('voter'), (req, res) => {
  const users = store.load('users');
  const user = users.find(u => u.username === req.user.username);
  if (!user) return res.status(404).json({ error: 'Director not found' });

  const certs = store.load('certificates');
  const cert = certs.find(c => c.serial === user.certSerial);
  if (!cert) return res.status(404).json({ error: 'Certificate not found' });

  const certCheck = certService.verifyCertificate(cert.certPem);
  res.json({
    serial: cert.serial,
    owner: cert.owner,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt,
    revoked: cert.revoked,
    certificateValid: certCheck.valid,
    certificateStatus: certCheck.valid ? 'valid' : certCheck.reason,
    certPem: cert.certPem
  });
});

// ---- Cast Vote (Ballot Module) ----
router.post('/vote', requireAuth, requireRole('voter'), (req, res) => {
  const { candidateId } = req.body;
  const election = store.load('election');
  if (election.status !== 'open') {
    return res.status(403).json({ error: 'Voting is currently closed for this election' });
  }

  const users = store.load('users');
  const user = users.find(u => u.username === req.user.username);
  if (!user) return res.status(404).json({ error: 'Voter not found' });
  if (user.hasVoted) {
    auditLog.log('DUPLICATE_VOTE_BLOCKED', user.username, {});
    return res.status(409).json({ error: 'This voter has already cast a ballot. One vote per voter is enforced.' });
  }

  const candidates = store.load('candidates');
  const candidate = candidates.find(c => c.id === candidateId);
  if (!candidate) return res.status(400).json({ error: 'Invalid candidate selected' });

  const certs = store.load('certificates');
  const cert = certs.find(c => c.serial === user.certSerial);
  const certCheck = certService.verifyCertificate(cert.certPem);
  if (!certCheck.valid) {
    auditLog.log('VOTE_BLOCKED_CERT_INVALID', user.username, { reason: certCheck.reason });
    return res.status(403).json({ error: `Cannot cast vote: certificate ${certCheck.reason}` });
  }

  // 1. Encrypt the ballot (AES-256-GCM) - candidate choice is confidential
  const timestamp = new Date().toISOString(); // simulated trusted timestamp (OpenTSA)
  const ballotPlaintext = { candidateId, voterCertSerial: user.certSerial, timestamp, nonce: uuidv4() };
  const encrypted = cryptoService.encryptBallot(ballotPlaintext);

  // 2. Hash the ciphertext, then sign the hash with the voter's private key (RSA-PSS / SHA-256)
  const ciphertextHash = cryptoService.sha256Hex(encrypted.ciphertext + encrypted.iv + encrypted.authTag);
  const signature = cryptoService.signHashWithPrivateKey(cert.privateKeyPemDemoOnly, ciphertextHash);

  const voteId = uuidv4();
  const receipt = cryptoService.sha256Hex(voteId + ciphertextHash + signature);

  store.withCollection('votes', (list) => {
    list.push({
      id: voteId,
      certSerial: user.certSerial,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      ciphertextHash,
      signature,
      timestamp,
      receipt
    });
  });

  store.withCollection('users', (list) => {
    const u = list.find(x => x.id === user.id);
    u.hasVoted = true;
  });

  auditLog.log('VOTE_CAST', user.username, { voteId, receipt });

  res.status(201).json({
    message: 'Vote encrypted, digitally signed, and recorded successfully.',
    receipt,
    voteId,
    note: 'Keep this receipt to independently verify your vote was recorded and untampered, without revealing your choice.'
  });
});

// ---- Verify Vote Receipt (integrity check without revealing the vote content) ----
router.post('/verify-receipt', requireAuth, (req, res) => {
  const { receipt } = req.body;
  const votes = store.load('votes');
  const vote = votes.find(v => v.receipt === receipt);
  if (!vote) return res.status(404).json({ error: 'No vote found matching this receipt' });

  const certs = store.load('certificates');
  const cert = certs.find(c => c.serial === vote.certSerial);
  const certCheck = certService.verifyCertificate(cert.certPem);

  const signatureValid = cryptoService.verifySignatureWithCertPem(cert.certPem, vote.ciphertextHash, vote.signature);
  const recomputedHash = cryptoService.sha256Hex(vote.ciphertext + vote.iv + vote.authTag);
  const hashIntact = recomputedHash === vote.ciphertextHash;

  auditLog.log('VOTE_VERIFIED', req.user.username, { receipt, signatureValid, hashIntact, certValid: certCheck.valid });

  res.json({
    receipt,
    timestamp: vote.timestamp,
    signatureValid,
    hashIntact,
    certificateValid: certCheck.valid,
    certificateStatus: certCheck.valid ? 'valid' : certCheck.reason,
    integrityConfirmed: signatureValid && hashIntact && certCheck.valid
  });
});

module.exports = router;
