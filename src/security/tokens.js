'use strict';

const crypto = require('node:crypto');

// 256 bits from the OS CSPRNG.
const newToken = () => crypto.randomBytes(32).toString('base64url');

// Only a SHA-256 of each session token is stored, so a leaked database can't be replayed as live
// sessions. A plain hash is enough here (unlike passwords) because the token is 256 random bits.
const hashToken = (token) => crypto.createHash('sha256').update(String(token)).digest('hex');

// A random password for the first admin in local development, instead of a well-known default.
const newPassword = () => crypto.randomBytes(18).toString('base64url');

module.exports = { newToken, hashToken, newPassword };
