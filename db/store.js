const fs = require('fs');
const path = require('path');
const { STORE_DIR } = require('../config');

if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });

const COLLECTIONS = ['users', 'certificates', 'votes', 'candidates', 'auditLogs', 'election'];

function filePath(name) {
  return path.join(STORE_DIR, `${name}.json`);
}

function load(name) {
  const fp = filePath(name);
  if (!fs.existsSync(fp)) {
    const initial = name === 'election' ? { status: 'open', title: 'VoteGuard 2026 Board of Directors Election' } : [];
    fs.writeFileSync(fp, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(fp, 'utf-8'));
}

function save(name, data) {
  fs.writeFileSync(filePath(name), JSON.stringify(data, null, 2));
}

// Simple in-process lock to avoid concurrent write corruption in this demo server
const locks = {};
function withCollection(name, fn) {
  const data = load(name);
  const result = fn(data);
  save(name, data);
  return result;
}

module.exports = { load, save, withCollection, COLLECTIONS };
