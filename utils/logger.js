const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const store = require('../db/store');

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function log(action, actor, details = {}) {
  return store.withCollection('auditLogs', (logs) => {
    const prevHash = logs.length > 0 ? logs[logs.length - 1].hash : '0'.repeat(64);
    const entry = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      action,
      actor,
      details,
      prevHash
    };
    entry.hash = sha256(prevHash + JSON.stringify({ id: entry.id, timestamp: entry.timestamp, action, actor, details }));
    logs.push(entry);
    return entry;
  });
}

function getAll() {
  return store.load('auditLogs');
}

// Recompute the chain to detect any tampering with the log file
function verifyChain() {
  const logs = store.load('auditLogs');
  let expectedPrev = '0'.repeat(64);
  const breaks = [];
  for (let i = 0; i < logs.length; i++) {
    const e = logs[i];
    if (e.prevHash !== expectedPrev) {
      breaks.push({ index: i, id: e.id, reason: 'prevHash mismatch' });
    }
    const recomputed = sha256(e.prevHash + JSON.stringify({ id: e.id, timestamp: e.timestamp, action: e.action, actor: e.actor, details: e.details }));
    if (recomputed !== e.hash) {
      breaks.push({ index: i, id: e.id, reason: 'hash mismatch - entry may have been altered' });
    }
    expectedPrev = e.hash;
  }
  return { intact: breaks.length === 0, totalEntries: logs.length, breaks };
}

module.exports = { log, getAll, verifyChain, sha256 };
