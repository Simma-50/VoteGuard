const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');
const store = require('../db/store');

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);

    // Re-check the account is still active on every request. This lets an
    // Admin immediately cut off access for a disabled director even if a
    // valid session token was already issued — without changing anything
    // about how the JWT itself is created, signed, or verified.
    const user = store.load('users').find(u => u.username === payload.username);
    if (!user || user.disabled) {
      return res.status(403).json({ error: 'This account has been disabled. Contact your Election Official.' });
    }

    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: `Access denied. Requires role: ${roles.join(' or ')}` });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole };
