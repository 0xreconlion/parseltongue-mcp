'use strict';

/**
 * Encoding helpers and canonical serialisation.
 *
 * The canonical form matters more than it looks. Both the AEAD associated data and the Ed25519
 * signature are computed over a serialised header, so sender and recipient must produce byte
 * identical output from the same logical object or every capsule fails to verify. JSON.stringify
 * does not guarantee key order across engines, so keys are sorted explicitly and recursively.
 */

const { sha256 } = require('@noble/hashes/sha2.js');

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') return utf8.encode(value);
  throw new TypeError('expected a string or Uint8Array');
}

function fromUtf8(bytes) {
  return utf8Decoder.decode(bytes);
}

/** base64url without padding — safe in URLs, filenames, and QR codes. */
function b64u(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64u(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error('not valid base64url');
  }
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

/**
 * Deterministic JSON: object keys sorted recursively, no whitespace. Used for anything that gets
 * signed or bound as associated data.
 */
function canonical(value) {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value === null || typeof value !== 'object') return value;
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] === undefined) continue;
    out[key] = sortDeep(value[key]);
  }
  return out;
}

function canonicalBytes(value) {
  return utf8.encode(canonical(value));
}

/**
 * Human-comparable fingerprint of a public key: the first 8 bytes of SHA-256, hex, in groups of
 * four. Short enough to read aloud or compare by eye, which is the point — it exists so two people
 * can confirm out of band that they imported the right key.
 */
function fingerprint(publicKeyBytes) {
  const digest = sha256(toBytes(publicKeyBytes));
  const hex = Buffer.from(digest.slice(0, 8)).toString('hex');
  return hex.match(/.{4}/g).join('-');
}

/** Full-strength content digest, for "has this changed since sealing?" */
function digestHex(bytes) {
  return Buffer.from(sha256(toBytes(bytes))).toString('hex');
}

/**
 * A constant-time `equalBytes` used to live here. It was removed in security review: it was
 * exported but never called, because every secret-dependent comparison in this package happens
 * inside the AEAD tag check in @noble/ciphers. Shipping an unused constant-time helper in a
 * crypto package implies a guarantee nothing actually relies on, and invites a future caller to
 * assume some comparison elsewhere is already hardened. If a secret comparison is ever genuinely
 * needed, add it back at that call site.
 */

/**
 * Overwrite a byte array in place.
 *
 * Honest limitation: this is not a guarantee. V8 may have copied the bytes during GC, and Node
 * offers no way to pin or reliably scrub memory. It shortens the window in which a secret sits in
 * a live buffer and nothing more. It is not a substitute for not holding secrets in the first
 * place, which is why unlocked vault material is kept for the duration of one operation.
 */
function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

module.exports = {
  b64u,
  canonical,
  canonicalBytes,
  digestHex,
  fingerprint,
  fromUtf8,
  sortDeep,
  toBytes,
  unb64u,
  wipe,
};
