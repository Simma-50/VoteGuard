const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const store = require('../db/store');
const ca = require('../pki/ca');
const certService = require('../pki/certService');
const mailer = require('../utils/mailer');
const { requireAuth, requireRole } = require('../middleware/auth');
const auditLog = require('../utils/logger');

const router = express.Router();

router.use(requireAuth, requireRole('election_official'));

function generateTempPassword() {
  // 12-character temporary password: readable but strong (mixed case + digits)
  return crypto.randomBytes(9).toString('base64').replace(/[+/=]/g, '').slice(0, 12) + 'X1';
}

// ---------------- Manage Directors ----------------

// Rich director list for the Manage Directors admin page (adds status/lifecycle
// fields on top of the original /voters response; that original endpoint is
// left completely unchanged below for backward compatibility).
router.get('/directors', (req, res) => {
  const users = store.load('users').filter(u => u.role === 'voter');
  const certs = store.load('certificates');
  res.json(users.map(u => {
    const cert = certs.find(c => c.serial === u.certSerial);
    return {
      username: u.username,
      email: u.email,
      certSerial: u.certSerial,
      hasVoted: u.hasVoted,
      disabled: Boolean(u.disabled),
      mustChangePassword: Boolean(u.mustChangePassword),
      certRevoked: cert ? Boolean(cert.revoked) : null,
      certExpiresAt: cert ? cert.expiresAt : null,
      createdAt: u.createdAt
    };
  }));
});

// Original, unmodified list endpoint (kept exactly as-is for compatibility).
router.get('/voters', (req, res) => {
  const users = store.load('users').filter(u => u.role === 'voter');
  res.json(users.map(u => ({
    username: u.username, email: u.email, certSerial: u.certSerial, hasVoted: u.hasVoted
  })));
});

// Create a Director: generates a temporary password + X.509 certificate and
// emails login instructions. Certificates/keys/passwords are never returned
// in this response — only a confirmation message, per the Certificate
// Workflow requirement.
router.post('/directors', async (req, res) => {
  const { username, email } = req.body;
  if (!username || !email) {
    return res.status(400).json({ error: 'username and email are required' });
  }

  const users = store.load('users');
  if (users.find(u => u.username === username)) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  const tempPassword = generateTempPassword();
  const cert = certService.issueVoterCertificate({ commonName: username, email, role: 'voter' });

  store.withCollection('users', (list) => {
    list.push({
      id: uuidv4(),
      username,
      email,
      passwordHash: bcrypt.hashSync(tempPassword, 10),
      role: 'voter',
      certSerial: cert.serial,
      hasVoted: false,
      disabled: false,
      mustChangePassword: true,
      createdAt: new Date().toISOString()
    });
  });

  store.withCollection('certificates', (list) => {
    list.push({
      serial: cert.serial,
      owner: username,
      email,
      role: 'voter',
      certPem: cert.certPem,
      publicKeyPem: cert.publicKeyPem,
      privateKeyPemDemoOnly: cert.privateKeyPem,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt,
      revoked: false
    });
  });

  const sendResult = await mailer.sendDirectorCredentialsEmail(email, username, tempPassword);
  auditLog.log('DIRECTOR_CREATED', req.user.username, { username, email, certSerial: cert.serial, emailSent: sendResult.sent });

  res.status(201).json({
    message: sendResult.sent
      ? `Director account created. Login instructions were emailed to ${email}.`
      : `Director account created. Email delivery is not configured on this server — credentials were logged to the server console instead.`,
    username,
    certSerial: cert.serial,
    emailSent: sendResult.sent
  });
});

// Disable / enable a director's account (blocks login without touching their certificate).
router.post('/directors/:username/disable', (req, res) => {
  const { username } = req.params;
  let found = false;
  store.withCollection('users', (list) => {
    const u = list.find(x => x.username === username && x.role === 'voter');
    if (u) { u.disabled = true; found = true; }
  });
  if (!found) return res.status(404).json({ error: 'Director not found' });
  auditLog.log('DIRECTOR_DISABLED', req.user.username, { username });
  res.json({ message: `${username} has been disabled.` });
});

router.post('/directors/:username/enable', (req, res) => {
  const { username } = req.params;
  let found = false;
  store.withCollection('users', (list) => {
    const u = list.find(x => x.username === username && x.role === 'voter');
    if (u) { u.disabled = false; found = true; }
  });
  if (!found) return res.status(404).json({ error: 'Director not found' });
  auditLog.log('DIRECTOR_ENABLED', req.user.username, { username });
  res.json({ message: `${username} has been re-enabled.` });
});

// Reset a director's password: generates a new temporary password, forces a
// change on next login, and emails it. Never returned in the API response.
router.post('/directors/:username/reset-password', async (req, res) => {
  const { username } = req.params;
  const users = store.load('users');
  const user = users.find(u => u.username === username && u.role === 'voter');
  if (!user) return res.status(404).json({ error: 'Director not found' });

  const tempPassword = generateTempPassword();
  store.withCollection('users', (list) => {
    const u = list.find(x => x.username === username);
    u.passwordHash = bcrypt.hashSync(tempPassword, 10);
    u.mustChangePassword = true;
  });

  const sendResult = await mailer.sendPasswordResetEmail(user.email, username, tempPassword);
  auditLog.log('DIRECTOR_PASSWORD_RESET', req.user.username, { username, emailSent: sendResult.sent });

  res.json({
    message: sendResult.sent
      ? `A new temporary password was emailed to ${user.email}.`
      : `Email delivery is not configured on this server — the new temporary password was logged to the server console instead.`,
    emailSent: sendResult.sent
  });
});

// Renew a director's certificate: issues a fresh X.509 certificate (new
// serial, new validity window), revokes the previous one, and updates the
// director's record to point at the new certificate.
router.post('/directors/:username/renew-certificate', (req, res) => {
  const { username } = req.params;
  const users = store.load('users');
  const user = users.find(u => u.username === username && u.role === 'voter');
  if (!user) return res.status(404).json({ error: 'Director not found' });

  const oldSerial = user.certSerial;
  const cert = certService.issueVoterCertificate({ commonName: username, email: user.email, role: 'voter' });

  store.withCollection('certificates', (list) => {
    list.push({
      serial: cert.serial,
      owner: username,
      email: user.email,
      role: 'voter',
      certPem: cert.certPem,
      publicKeyPem: cert.publicKeyPem,
      privateKeyPemDemoOnly: cert.privateKeyPem,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt,
      revoked: false
    });
    const old = list.find(c => c.serial === oldSerial);
    if (old) { old.revoked = true; old.revokedAt = new Date().toISOString(); old.revokeReason = 'renewed'; }
  });

  if (oldSerial) ca.revokeSerial(oldSerial);

  store.withCollection('users', (list) => {
    const u = list.find(x => x.username === username);
    u.certSerial = cert.serial;
  });

  auditLog.log('CERTIFICATE_RENEWED', req.user.username, { username, oldSerial, newSerial: cert.serial });
  res.json({ message: `Certificate renewed for ${username}.`, newSerial: cert.serial });
});

// ---------------- Candidates ----------------
// Candidate editing is locked once the election is open, per the Candidate
// Management requirement.
function assertElectionNotOpen(res) {
  const election = store.load('election');
  if (election.status === 'open') {
    res.status(403).json({ error: 'Candidates cannot be modified while the election is open. Close the election first.' });
    return false;
  }
  return true;
}

router.post('/candidates', (req, res) => {
  if (!assertElectionNotOpen(res)) return;
  const { name, party } = req.body;
  if (!name) return res.status(400).json({ error: 'Candidate name is required' });
  const candidate = { id: uuidv4(), name, party: party || 'Independent' };
  store.withCollection('candidates', (list) => list.push(candidate));
  auditLog.log('CANDIDATE_ADDED', req.user.username, candidate);
  res.status(201).json(candidate);
});

router.delete('/candidates/:id', (req, res) => {
  if (!assertElectionNotOpen(res)) return;
  store.withCollection('candidates', (list) => {
    const idx = list.findIndex(c => c.id === req.params.id);
    if (idx !== -1) list.splice(idx, 1);
  });
  auditLog.log('CANDIDATE_REMOVED', req.user.username, { id: req.params.id });
  res.json({ message: 'Candidate removed' });
});

// ---------------- Election control ----------------
router.post('/election/open', (req, res) => {
  store.save('election', { ...store.load('election'), status: 'open' });
  auditLog.log('ELECTION_OPENED', req.user.username, {});
  res.json({ message: 'Election is now open for voting' });
});

router.post('/election/close', (req, res) => {
  store.save('election', { ...store.load('election'), status: 'closed' });
  auditLog.log('ELECTION_CLOSED', req.user.username, {});
  res.json({ message: 'Election is now closed' });
});

// ---------------- Certificate revocation ----------------
router.post('/revoke-certificate', (req, res) => {
  const { certSerial, reason } = req.body;
  const certs = store.load('certificates');
  const cert = certs.find(c => c.serial === certSerial);
  if (!cert) return res.status(404).json({ error: 'Certificate not found' });

  ca.revokeSerial(certSerial);
  store.withCollection('certificates', (list) => {
    const c = list.find(x => x.serial === certSerial);
    c.revoked = true;
    c.revokedAt = new Date().toISOString();
    c.revokeReason = reason || 'unspecified';
  });

  auditLog.log('CERTIFICATE_REVOKED', req.user.username, { certSerial, reason });
  res.json({ message: `Certificate ${certSerial} revoked and added to CRL` });
});

module.exports = router;
