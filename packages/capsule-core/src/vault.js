'use strict';

/**
 * Passphrase-protected local vault for private key material.
 *
 * Design notes that are load-bearing:
 *
 *  - Argon2id for the passphrase, not PBKDF2 or a bare hash. A vault passphrase is the one secret
 *    a human chooses, so it is the weakest link and the only place a memory-hard KDF genuinely
 *    pays for itself. Measured on this Pi: m=64MiB t=3 costs ~1.9s, which is acceptable for a
 *    once-per-session unlock and expensive for an offline attacker.
 *
 *  - KDF PARAMETERS ARE BOUND AS ASSOCIATED DATA. They are stored in cleartext so future versions
 *    can raise them without breaking old vaults — but storing them in cleartext without binding
 *    them would let an attacker who can write the file rewrite m=65536 to m=8, then brute-force
 *    cheaply against the weakened parameters. Binding the header into the AEAD makes any such
 *    edit fail to decrypt instead.
 *
 *  - THERE IS NO RECOVERY. No escrow, no reset, no backdoor. Lose the passphrase and every
 *    capsule ever sealed to this identity is permanently unreadable. That is the intended
 *    property, and it is why exportBackup/importBackup exist and are a shipping gate rather than
 *    a nicety: on an SD card, "no recovery" otherwise means guaranteed eventual loss.
 *
 *  - Unlocked secrets are returned to the caller for the duration of one operation and not cached
 *    here. There is no "stay unlocked" state in this module for anything to leak.
 */

const { xchacha20poly1305 } = require('@noble/ciphers/chacha.js');
const { argon2id } = require('@noble/hashes/argon2.js');
const { randomBytes } = require('node:crypto');

const { b64u, canonicalBytes, fromUtf8, unb64u, wipe } = require('./codec');
const { derivePublic } = require('./identity');

const VAULT_VERSION = 1;
const NONCE_BYTES = 24; // XChaCha20 extended nonce
const SALT_BYTES = 16;
const KEY_BYTES = 32;

// OWASP's floor is m=19456 t=2 p=1. Raised deliberately: unlock happens once per session, so the
// extra ~1.5s buys real offline-cracking resistance for free from the user's point of view.
const DEFAULT_KDF = { alg: 'argon2id', m: 65536, t: 3, p: 1 };

const MIN_PASSPHRASE_LENGTH = 10;

class VaultError extends Error {}

function assertPassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new VaultError(
      `passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters. There is no recovery if ` +
        'it is lost, and no rate limit on an attacker who copies this file - length is the only ' +
        'defence that matters here.'
    );
  }
}

function deriveKey(passphrase, salt, kdf) {
  if (kdf.alg !== 'argon2id') {
    throw new VaultError(`unsupported KDF "${kdf.alg}"`);
  }
  // Reject implausibly weak stored parameters outright. Binding them as AAD already prevents
  // tampering, but a vault written by a buggy future version should not silently be trusted.
  if (!(kdf.m >= 8192 && kdf.t >= 1 && kdf.p >= 1)) {
    throw new VaultError(
      `stored KDF parameters are too weak to trust (m=${kdf.m} t=${kdf.t} p=${kdf.p})`
    );
  }
  return argon2id(passphrase, salt, { m: kdf.m, t: kdf.t, p: kdf.p, dkLen: KEY_BYTES });
}

/** The cleartext part of a vault, and exactly what gets bound as associated data. */
function vaultHeader(record) {
  return {
    v: record.v,
    kdf: record.kdf,
    salt: record.salt,
    nonce: record.nonce,
    created: record.created,
    updated: record.updated,
    identity: record.identity, // public keys only - see assertions in create()
  };
}

/**
 * Create a vault record holding one identity's secret material.
 *
 * Returns a plain object the caller serialises to disk. This module does no file I/O, which keeps
 * it testable and keeps path handling (a place to get traversal wrong) out of the crypto.
 */
function create({ identity, passphrase, kdf = DEFAULT_KDF }) {
  assertPassphrase(passphrase);
  if (!identity || !identity.secret || !identity.public) {
    throw new VaultError('expected an identity with both public and secret parts');
  }

  const salt = new Uint8Array(randomBytes(SALT_BYTES));
  const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
  const now = new Date().toISOString();

  const record = {
    v: VAULT_VERSION,
    kdf: { ...kdf },
    salt: b64u(salt),
    nonce: b64u(nonce),
    created: now,
    updated: now,
    // Public keys are stored in cleartext so the vault can be identified without unlocking it.
    identity: {
      id: identity.public.id,
      label: identity.public.label || '',
      sign: identity.public.sign,
      encrypt: identity.public.encrypt,
      signFingerprint: identity.public.signFingerprint,
      encryptFingerprint: identity.public.encryptFingerprint,
      created: identity.public.created,
    },
    ct: null,
  };

  const key = deriveKey(passphrase, salt, record.kdf);
  try {
    const aead = xchacha20poly1305(key, nonce, canonicalBytes(vaultHeader(record)));
    record.ct = b64u(aead.encrypt(canonicalBytes(identity.secret)));
  } finally {
    wipe(key);
  }

  assertNoSecretInHeader(record);
  return record;
}

/**
 * Unlock a vault. Returns the secret material plus the public identity re-derived FROM the secret
 * keys rather than read back from the cleartext header — so a tampered header cannot make the
 * vault report keys it does not actually hold.
 */
function unlock(record, passphrase) {
  if (!record || record.v !== VAULT_VERSION) {
    throw new VaultError(`unsupported vault version ${record && record.v}`);
  }
  assertPassphrase(passphrase);

  const salt = unb64u(record.salt);
  const nonce = unb64u(record.nonce);
  const key = deriveKey(passphrase, salt, record.kdf);

  let plaintext;
  try {
    const aead = xchacha20poly1305(key, nonce, canonicalBytes(vaultHeader(record)));
    plaintext = aead.decrypt(unb64u(record.ct));
  } catch {
    // One message for both causes. Distinguishing "wrong passphrase" from "tampered file" would
    // tell an attacker which of the two they achieved.
    throw new VaultError(
      'could not unlock the vault: wrong passphrase, or the vault file has been altered. ' +
        'There is no recovery for a lost passphrase.'
    );
  } finally {
    wipe(key);
  }

  let secret;
  try {
    secret = JSON.parse(fromUtf8(plaintext));
  } finally {
    wipe(plaintext);
  }

  const publicIdentity = derivePublic(secret, {
    label: record.identity ? record.identity.label : '',
    created: record.identity ? record.identity.created : null,
  });

  // If the cleartext header disagrees with what the secret keys actually derive to, the file was
  // edited. Fail rather than serve a misleading identity.
  if (record.identity && record.identity.sign && record.identity.sign !== publicIdentity.sign) {
    throw new VaultError(
      'vault header does not match the key material it contains; the file has been altered'
    );
  }

  return { secret, public: publicIdentity };
}

/** Re-encrypt under a new passphrase, or under stronger KDF parameters. */
function changePassphrase(record, oldPassphrase, newPassphrase, kdf = DEFAULT_KDF) {
  const { secret, public: publicIdentity } = unlock(record, oldPassphrase);
  return create({ identity: { public: publicIdentity, secret }, passphrase: newPassphrase, kdf });
}

/**
 * Belt-and-braces check that no private material landed in the cleartext part of a vault record.
 * Cheap, and the failure it guards against is unrecoverable.
 */
function assertNoSecretInHeader(record) {
  const header = JSON.stringify(vaultHeader(record));
  for (const banned of ['secret', 'private', 'seed', 'passphrase', 'mnemonic']) {
    if (header.includes(`"${banned}"`)) {
      throw new VaultError(`vault header would contain a "${banned}" field; refusing to produce it`);
    }
  }
}

module.exports = {
  DEFAULT_KDF,
  MIN_PASSPHRASE_LENGTH,
  VAULT_VERSION,
  VaultError,
  changePassphrase,
  create,
  unlock,
  vaultHeader,
};
