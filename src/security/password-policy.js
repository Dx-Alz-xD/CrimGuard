'use strict';

// What a new password must satisfy, following NIST SP 800-63B: a real minimum length,
// a generous maximum, no composition rules, and a check against passwords attackers try first.

const MIN_LENGTH = 12;
const MAX_LENGTH = 256;

// Common passwords that are long enough to pass the length rule. Shorter ones are already rejected.
const COMMON = new Set([
  '123456789012', '1234567890123', '12345678901234', '123123123123', '111111111111', '000000000000',
  'password1234', 'password12345', 'password123456', 'passwordpassword', 'password1234!', 'p@ssw0rd1234',
  'qwertyuiop12', 'qwertyuiopasdf', 'qwerty123456', 'qwertyqwerty', '1q2w3e4r5t6y', 'asdfghjkl123',
  'iloveyou1234', 'letmein12345', 'welcome12345', 'welcome123456', 'changeme1234', 'administrator',
  'admin1234567', 'adminadmin12', 'football1234', 'baseball1234', 'superman1234', 'trustno11234',
  'abcdefghijkl', 'abc123abc123', 'monkey123456', 'dragon123456', 'sunshine1234', 'princess1234',
  'masterkey123', 'zaq12wsxcde3', '1qaz2wsx3edc', 'correcthorsebatterystaple',
]);

const SEQUENCES = ['0123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiopasdfghjklzxcvbnm'];

function isSequential(value) {
  return SEQUENCES.some((sequence) => sequence.includes(value) || [...sequence].reverse().join('').includes(value));
}

// Returns an error message, or null when the password is acceptable.
function checkPassword(password, { email = '', name = '' } = {}) {
  if (typeof password !== 'string') return `Password must be ${MIN_LENGTH} to ${MAX_LENGTH} characters.`;
  const length = [...password].length;
  if (length < MIN_LENGTH || length > MAX_LENGTH) return `Password must be ${MIN_LENGTH} to ${MAX_LENGTH} characters.`;

  const lower = password.toLowerCase();
  if (COMMON.has(lower) || new Set(lower).size <= 2 || isSequential(lower)) {
    return 'That password is too easy to guess. Try a longer phrase of unrelated words.';
  }

  const localPart = String(email).toLowerCase().split('@')[0];
  const compact = lower.replace(/[^\p{L}\p{N}]/gu, '');
  const nameCompact = String(name).toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
  if ((localPart.length >= 4 && lower.includes(localPart)) || (nameCompact.length >= 4 && compact === nameCompact)) {
    return "Your password can't be based on your name or email.";
  }
  return null;
}

module.exports = { MIN_LENGTH, MAX_LENGTH, checkPassword };
