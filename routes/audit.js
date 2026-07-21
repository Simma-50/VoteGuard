const express = require('express');
const store = require('../db/store');
const cryptoService = require('../pki/cryptoService');
const certService = require('../pki/certService');
const { requireAuth, requireRole } = require('../middleware/auth');
const auditLog = require('../utils/logger');
const ca = require('../pki/ca');

const router = express.Router();

// ---- Results Module: tally votes, verify integrity of every ballot before counting ----
router.get('/results', requireAuth, requireRole('election_official', 'auditor'), (req, res) => {
  const election = store.load('election');
  const votes = store.load('votes');
  const certs = store.load('certificates');
  const candidates = store.load('candidates');

  const tally = {};
  candidates.forEach(c => { tally[c.id] = 0; });

  let validVotes = 0;
  let invalidVotes = 0;
  const issues = [];

  votes.forEach(vote => {
    const cert = certs.find(c => c.serial === vote.certSerial);
    const certCheck = cert ? certService.verifyCertificate(cert.certPem) : { valid: false, reason: 'cert missing' };
    const recomputedHash = cryptoService.sha256Hex(vote.ciphertext + vote.iv + vote.authTag);
    const hashIntact = recomputedHash === vote.ciphertextHash;
    const sigValid = cert ? cryptoService.verifySignatureWithCertPem(cert.certPem, vote.ciphertextHash, vote.signature) : false;

    if (hashIntact && sigValid && certCheck.valid) {
      const decrypted = cryptoService.decryptBallot(vote);
      if (tally[decrypted.candidateId] !== undefined) {
        tally[decrypted.candidateId] += 1;
        validVotes += 1;
      } else {
        invalidVotes += 1;
        issues.push({ voteId: vote.id, reason: 'candidate id not found (possibly removed after voting)' });
      }
    } else {
      invalidVotes += 1;
      issues.push({
        voteId: vote.id,
        reason: !hashIntact ? 'ciphertext hash mismatch - possible tampering'
          : !sigValid ? 'digital signature invalid'
          : certCheck.reason
      });
    }
  });

  const results = candidates.map(c => ({ id: c.id, name: c.name, party: c.party, votes: tally[c.id] || 0 }));

  auditLog.log('RESULTS_TALLIED', req.user.username, { validVotes, invalidVotes });

  res.json({
    election,
    totalBallotsCast: votes.length,
    validVotesCounted: validVotes,
    invalidOrTamperedVotes: invalidVotes,
    integrityIssues: issues,
    results
  });
});

// ---- Audit & Reports Module ----
router.get('/logs', requireAuth, requireRole('auditor', 'election_official'), (req, res) => {
  res.json(auditLog.getAll());
});

router.get('/verify-chain', requireAuth, requireRole('auditor', 'election_official'), (req, res) => {
  res.json(auditLog.verifyChain());
});

router.get('/crl', requireAuth, requireRole('auditor', 'election_official'), (req, res) => {
  res.json({ revokedSerials: ca.getCRL() });
});

router.get('/certificates', requireAuth, requireRole('auditor', 'election_official'), (req, res) => {
  const certs = store.load('certificates');
  res.json(certs.map(c => ({
    serial: c.serial, owner: c.owner, role: c.role, issuedAt: c.issuedAt,
    expiresAt: c.expiresAt, revoked: c.revoked
  })));
});

router.get('/ca-certificate', requireAuth, (req, res) => {
  res.type('text/plain').send(ca.getCACertPem());
});

module.exports = router;
