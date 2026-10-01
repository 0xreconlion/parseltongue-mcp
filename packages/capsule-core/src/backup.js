'use strict';

/**
 * Identity backup and restore.
 *
 * This is the one place in the whole package that deliberately emits private key material, and it
 * is a SHIPPING GATE rather than a convenience. "No account recovery" is the intended security
 * property, but on a Raspberry Pi running off an SD card it otherwise means guaranteed eventual
 * loss of every capsule ever sealed to an identity. A tested restore path is what makes the
 * no-recovery design survivable instead of merely strict.
 *
 * The backup is independently passphrase-wrapped with its own salt and its own KDF parameters, so
 * it is not tied to the vault it came from and can use a different (longer, written-down)
 * passphrase than the day-to-day one.
 *
 * It is still a file containing your private keys. Anyone who gets both it and its passphrase
 * becomes you.
 */

const { xchacha20poly1305 } = require('@noble/ciphers/chacha.js');
const { argon2id } = require('@noble/hashes/argon2.js');
const { randomBytes } = require('node:crypto');

const { b64u, canonicalBytes, digestHex, fromUtf8, unb64u, wipe } = require('./codec');
const { derivePublic } = require('./identity');

const BACKUP_VERSION = 1;
const BACKUP_HEADER = '----- PARSELTONGUE IDENTITY BACKUP v1 -----';
const BACKUP_FOOTER = '----- END PARSELTONGUE IDENTITY BACKUP -----';
const NONCE_BYTES = 24;
const SALT_BYTES = 16;
const KEY_BYTES = 32;

// Heavier than the vault's: a backup is a long-lived artifact that may sit on other media, so it
// gets a bigger offline-cracking cost. Unlock happens approximately never.
const BACKUP_KDF = { alg: 'argon2id', m: 131072, t: 4, p: 1 };

const MIN_BACKUP_PASSPHRASE = 16;

class BackupError extends Error {}

function deriveKey(passphrase, salt, kdf) {
  if (kdf.alg !== 'argon2id') throw new BackupError(`unsupported KDF "${kdf.alg}"`);
  if (!(kdf.m >= 8192 && kdf.t >= 1 && kdf.p >= 1)) {
    throw new BackupError(`backup KDF parameters are too weak to trust (m=${kdf.m} t=${kdf.t})`);
  }
  return argon2id(passphrase, salt, { m: kdf.m, t: kdf.t, p: kdf.p, dkLen: KEY_BYTES });
}

function backupHeader(record) {
  return {
    v: record.v,
    kdf: record.kdf,
    salt: record.salt,
    nonce: record.nonce,
    created: record.created,
    identity: record.identity,
  };
}

/**
 * Produce a passphrase-wrapped backup of one identity's secret material.
 *
 * Returns the record, a pasteable text block, and the fingerprints a human should check against
 * the live identity before trusting the backup.
 */
/**
 * `kdf` exists so the test suite can run at a cost that does not discourage running it. Callers
 * in production must leave it alone - BACKUP_KDF is deliberately heavier than the vault's,
 * because a backup is a long-lived artifact that may sit on other media and is unlocked
 * approximately never. The parameters travel inside the record and are bound as associated data,
 * so a backup written with weaker settings stays readable but cannot be silently downgraded.
 */
function exportBackup({ secret, publicIdentity, passphrase, contacts = null, kdf = BACKUP_KDF }) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_BACKUP_PASSPHRASE) {
    throw new BackupError(
      `a backup passphrase must be at least ${MIN_BACKUP_PASSPHRASE} characters. This file ` +
        'contains your private keys and may outlive the machine that made it - it should be ' +
        'longer than your day-to-day vault passphrase, and written down somewhere physical.'
    );
  }
  if (!secret || !secret.sign || !secret.encrypt) {
    throw new BackupError('expected unlocked secret material with sign and encrypt keys');
  }

  const resolvedPublic = publicIdentity || derivePublic(secret);
  const salt = new Uint8Array(randomBytes(SALT_BYTES));
  const nonce = new Uint8Array(randomBytes(NONCE_BYTES));

  const record = {
    v: BACKUP_VERSION,
    kdf: { ...kdf },
    salt: b64u(salt),
    nonce: b64u(nonce),
    created: new Date().toISOString(),
    // Public identification in cleartext, so a human can tell which identity a backup holds
    // without decrypting it. No private material here - asserted below.
    identity: {
      id: resolvedPublic.id,
      label: resolvedPublic.label || '',
      signFingerprint: resolvedPublic.signFingerprint,
      encryptFingerprint: resolvedPublic.encryptFingerprint,
    },
    ct: null,
  };

  // The contact book rides inside the ENCRYPTED payload when supplied.
  //
  // Without it, a restore recovers the identity but loses every imported contact - and the
  // visible symptom is that sender verification silently degrades from "matches your contact
  // alice" to "unconfirmed", which is exactly the check a user is most likely to stop doing if
  // it stops working. Contacts are public keys, so this adds no secret to the file; it does put
  // the social graph in there, which is a reason to encrypt the backup and not a reason to omit
  // them.
  const payload = contacts ? { ...secret, contacts } : secret;

  const key = deriveKey(passphrase, salt, record.kdf);
  try {
    const aead = xchacha20poly1305(key, nonce, canonicalBytes(backupHeader(record)));
    record.ct = b64u(aead.encrypt(canonicalBytes(payload)));
  } finally {
    wipe(key);
  }

  const header = JSON.stringify(backupHeader(record));
  for (const banned of ['secret', 'private', 'seed', 'passphrase', 'mnemonic']) {
    if (header.includes(`"${banned}"`)) {
      throw new BackupError(`backup header would contain a "${banned}" field; refusing to produce it`);
    }
  }

  return {
    record,
    text: toText(record),
    identity: record.identity,
    checksum: digestHex(record.ct).slice(0, 16),
    warning:
      'This file plus its passphrase IS your identity. Anyone holding both can read every ' +
      'capsule ever sealed to you and can seal capsules as you. Store it offline. Never commit ' +
      'it, never email it to yourself, never put it in a notes app that syncs.',
  };
}

/** Restore secret material from a backup. */
function importBackup({ backup, passphrase }) {
  const record = typeof backup === 'string' ? fromText(backup) : backup;
  if (!record || record.v !== BACKUP_VERSION) {
    throw new BackupError(`unsupported backup version ${record && record.v}`);
  }

  const key = deriveKey(passphrase, unb64u(record.salt), record.kdf);
  let plaintext;
  try {
    const aead = xchacha20poly1305(key, unb64u(record.nonce), canonicalBytes(backupHeader(record)));
    plaintext = aead.decrypt(unb64u(record.ct));
  } catch {
    throw new BackupError(
      'could not decrypt the backup: wrong passphrase, or the file has been altered. There is no ' +
        'recovery for a lost backup passphrase.'
    );
  } finally {
    wipe(key);
  }

  let payload;
  try {
    payload = JSON.parse(fromUtf8(plaintext));
  } finally {
    wipe(plaintext);
  }

  // Split the contact book back out; keep `secret` to exactly the key material so nothing
  // downstream has to guess what is sensitive in it.
  const { contacts = null, ...secret } = payload;
  const publicIdentity = derivePublic(secret, { label: record.identity ? record.identity.label : '' });

  // The cleartext fingerprints are a convenience, not a source of truth. If they disagree with
  // what the keys actually derive to, the file was edited.
  if (
    record.identity &&
    record.identity.signFingerprint &&
    record.identity.signFingerprint !== publicIdentity.signFingerprint
  ) {
    throw new BackupError(
      'backup header fingerprint does not match the key material it contains; the file has been ' +
        'altered. Do not use it.'
    );
  }

  return { secret, public: publicIdentity, contacts };
}

function toText(record) {
  const encoded = b64u(canonicalBytes(record));
  const lines = encoded.match(/.{1,76}/g) || [''];
  return [
    BACKUP_HEADER,
    `identity: ${record.identity.label || '(unnamed)'}`,
    `signing fingerprint:    ${record.identity.signFingerprint}`,
    `encryption fingerprint: ${record.identity.encryptFingerprint}`,
    `created: ${record.created}`,
    '',
    '# PRIVATE KEY MATERIAL, passphrase-wrapped. Keep offline.',
    '',
    ...lines,
    BACKUP_FOOTER,
  ].join('\n');
}

function fromText(text) {
  if (typeof text !== 'string') throw new BackupError('expected backup text');
  const trimmed = text.trim();

  if (trimmed.startsWith('{')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      throw new BackupError('looks like JSON but does not parse');
    }
  }
  if (!trimmed.includes(BACKUP_HEADER)) throw new BackupError('not a Parseltongue identity backup');

  const start = trimmed.indexOf(BACKUP_HEADER) + BACKUP_HEADER.length;
  const end = trimmed.indexOf(BACKUP_FOOTER);
  if (end === -1) throw new BackupError('backup has no terminator; it may be truncated');

  const body = trimmed
    .slice(start, end)
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#') && !line.includes(':'))
    .join('');

  if (!body) throw new BackupError('backup body is empty');

  try {
    return JSON.parse(fromUtf8(unb64u(body)));
  } catch {
    throw new BackupError('backup body did not decode; the file may be corrupted or truncated');
  }
}

module.exports = {
  BACKUP_FOOTER,
  BACKUP_HEADER,
  BACKUP_KDF,
  BACKUP_VERSION,
  BackupError,
  MIN_BACKUP_PASSPHRASE,
  exportBackup,
  importBackup,
};
