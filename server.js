const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const { PORT } = require('./config');
const ca = require('./pki/ca');
const cryptoService = require('./pki/cryptoService');
const certService = require('./pki/certService');
const store = require('./db/store');
const auditLog = require('./utils/logger');

const authRoutes = require('./routes/auth');
const voterRoutes = require('./routes/voter');
const adminRoutes = require('./routes/admin');
const auditRoutes = require('./routes/audit');

// ---- Bootstrap PKI infrastructure ----
ca.ensureCA();
cryptoService.encryptBallot; // ensures module loaded; key file created lazily on first use
require('./pki/cryptoService'); // noop require to trigger key file presence check below
(function ensureElectionKeyEager() {
  // Force creation of the AES election key at startup for a clean first run
  const fs = require('fs');
  const path2 = require('path');
  const { PKI_DIR } = require('./config');
  const keyPath = path2.join(PKI_DIR, 'election-aes.key');
  if (!fs.existsSync(keyPath)) {
    const crypto = require('crypto');
    fs.writeFileSync(keyPath, crypto.randomBytes(32).toString('hex'));
    console.log('[Crypto] AES-256 election ballot key generated.');
  }
})();

// ---- Seed default accounts, election, candidates on first run ----
function seed() {
  const users = store.load('users');

  function seedRoleAccount(username, email, password, role) {
    if (users.find(u => u.username === username)) return;
    const cert = certService.issueVoterCertificate({ commonName: username, email, role });
    store.withCollection('users', (list) => {
      list.push({
        id: uuidv4(),
        username,
        email,
        passwordHash: bcrypt.hashSync(password, 10),
        role,
        certSerial: cert.serial,
        hasVoted: false,
        disabled: false,
        mustChangePassword: false,
        createdAt: new Date().toISOString()
      });
    });
    store.withCollection('certificates', (list) => {
      list.push({
        serial: cert.serial,
        owner: username,
        email,
        role,
        certPem: cert.certPem,
        publicKeyPem: cert.publicKeyPem,
        privateKeyPemDemoOnly: cert.privateKeyPem,
        issuedAt: cert.issuedAt,
        expiresAt: cert.expiresAt,
        revoked: false
      });
    });
    console.log(`[Seed] Created ${role} account -> username: ${username} / password: ${password}`);
  }

  // Default administrator account (Election Official role). Directors are no
  // longer self-registered — they are onboarded exclusively by this account
  // via the Manage Directors admin page.
  seedRoleAccount('admin', 'admin@voteguard.demo', 'Admin@123', 'election_official');
  seedRoleAccount('auditor1', 'auditor1@voteguard.demo', 'Auditor@123', 'auditor');

  const candidates = store.load('candidates');
  if (candidates.length === 0) {
    store.save('candidates', [
      { id: uuidv4(), name: 'Sushma Rai', party: 'Board Director — Finance' },
      { id: uuidv4(), name: 'Hari Basnet', party: 'Board Director — Operations' },
      { id: uuidv4(), name: 'Jaya Thapa', party: 'Board Director — Human Resources' },
      { id: uuidv4(), name: 'Kiran Singh', party: 'Board Director — Technology' }
    ]);
    console.log('[Seed] Default board director candidates added.');
  }

  if (store.load('auditLogs').length === 0) {
    auditLog.log('SYSTEM_INITIALIZED', 'system', { message: 'VoteGuard PKI infrastructure and audit chain initialized' });
  }
}
seed();

// ---- Express app ----
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/auth', authRoutes);
app.use('/api/voter', voterRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/audit', auditRoutes);

app.get('/api/health', (req, res) => res.json({ status: 'ok', service: 'VoteGuard PKI Corporate Board Election API' }));

// Public, unauthenticated status summary for the landing page widgets.
// Deliberately exposes only safe, aggregate booleans/counts — no PII, no
// certificate owners, no log contents. Everything below is derived from
// data already served (in fuller form) by existing authenticated endpoints.
app.get('/api/public/status', (req, res) => {
  try {
    const election = store.load('election');
    const certs = store.load('certificates');
    const activeCerts = certs.filter(c => !c.revoked).length;
    const chain = auditLog.verifyChain();

    res.json({
      systemStatus: 'operational',
      election: { status: election.status, title: election.title },
      caStatus: 'operational',
      certificateRepository: { total: certs.length, active: activeCerts, revoked: certs.length - activeCerts },
      auditLog: { intact: chain.intact, totalEntries: chain.totalEntries }
    });
  } catch (err) {
    res.status(500).json({ systemStatus: 'degraded', error: 'Unable to compute status' });
  }
});

app.listen(PORT, () => {
  console.log('==========================================================');
  console.log(' VoteGuard - PKI-Based Corporate Board of Directors Election System');
  console.log(` Running at: http://localhost:${PORT}`);
  console.log(' Default accounts:');
  console.log('   Admin (Election Official) -> admin / Admin@123');
  console.log('   Auditor                   -> auditor1 / Auditor@123');
  console.log(' Directors are onboarded by the Admin from Manage Directors — there is no public registration.');
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    console.log(' NOTE: Gmail SMTP not configured — OTP codes will be printed here instead of emailed.');
    console.log('       Set GMAIL_USER / GMAIL_APP_PASSWORD in a .env file to enable real email delivery.');
  }
  console.log('==========================================================');
});
