const crypto = require('crypto');

const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const DIGITS = '23456789';
const SYMBOLS = '!@#$%&*';

function pick(charset) {
  return charset[crypto.randomInt(charset.length)];
}

/**
 * Generates a random temporary password that satisfies typical complexity
 * rules (upper, lower, digit, symbol) without ambiguous characters (0/O, 1/l/I).
 */
function generateTempPassword(length = 12) {
  const all = UPPER + LOWER + DIGITS + SYMBOLS;
  const required = [pick(UPPER), pick(LOWER), pick(DIGITS), pick(SYMBOLS)];
  const rest = Array.from({ length: length - required.length }, () => pick(all));
  const chars = [...required, ...rest];
  // Shuffle (Fisher-Yates) so the required characters aren't always in the same position
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

module.exports = { generateTempPassword };
