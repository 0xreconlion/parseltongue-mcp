'use strict';

/**
 * @reconlion/capsule-core - Apache-2.0
 *
 * Local secure message capsules. Create an identity, exchange public contact cards, seal a
 * message to someone, send it through any channel you already use, open and verify it locally.
 *
 * No network, no relay, no accounts, no hosted anything. This package does no file I/O either -
 * it returns records for a caller to persist, which keeps path handling out of the crypto.
 *
 * DESIGN CONSTRAINTS
 *
 *  - This package must never import from @reconlion/parseltongue-bridge or any P4RS3LT0NGV3
 *    source. Parseltongue transforms are *representation*, not confidentiality. Keeping them out
 *    keeps this package Apache-2.0 and separately reusable, and keeps the security boundary
 *    legible. Enforced by scripts/check-license-seam.js.
 *
 *  - Established primitives only, no custom cryptography: X25519 + Ed25519 (@noble/curves),
 *    XChaCha20-Poly1305 (@noble/ciphers), HKDF-SHA256 and Argon2id (@noble/hashes).
 *
 *  - The full visible capsule header is bound into the AEAD as associated data and covered by the
 *    signature, so tampering with *visible metadata* breaks both decryption and verification.
 *
 *  - No private key material may appear in a return value destined for an MCP response, a log
 *    line, or a contact card. Only exportBackup returns key material, and only
 *    passphrase-wrapped. Asserted by test, not by inspection.
 *
 *  - There is no account recovery. exportBackup/importBackup are therefore a shipping gate.
 */

const capsule = require('./capsule');
const codec = require('./codec');
const identity = require('./identity');
const vault = require('./vault');
const backup = require('./backup');
const sealed = require('./sealed');

module.exports = {
  CAPSULE_FORMAT_VERSION: capsule.CAPSULE_VERSION,
  VAULT_VERSION: vault.VAULT_VERSION,
  BACKUP_VERSION: backup.BACKUP_VERSION,

  CapsuleError: capsule.CapsuleError,
  IdentityError: identity.IdentityError,
  VaultError: vault.VaultError,
  BackupError: backup.BackupError,

  // Identity and contacts
  createIdentity: identity.createIdentity,
  derivePublic: identity.derivePublic,
  exportContactCard: identity.exportContactCard,
  importContactCard: identity.importContactCard,

  // Vault
  createVault: vault.create,
  unlockVault: vault.unlock,
  changeVaultPassphrase: vault.changePassphrase,
  MIN_PASSPHRASE_LENGTH: vault.MIN_PASSPHRASE_LENGTH,

  // Capsules
  sealCapsule: capsule.sealCapsule,
  openCapsule: capsule.openCapsule,
  inspectCapsule: capsule.inspectCapsule,
  toEnvelope: capsule.toEnvelope,
  fromEnvelope: capsule.fromEnvelope,
  MAX_PAYLOAD_BYTES: capsule.MAX_PAYLOAD_BYTES,

  // Recovery - a shipping gate, see above
  exportIdentityBackup: backup.exportBackup,
  importIdentityBackup: backup.importBackup,
  MIN_BACKUP_PASSPHRASE: backup.MIN_BACKUP_PASSPHRASE,

  // Sealed notes - symmetric "decrypt code" encryption, no identities required
  SEALED_VERSION: sealed.SEALED_VERSION,
  SealedError: sealed.SealedError,
  sealNote: sealed.sealNote,
  openNote: sealed.openNote,
  inspectNote: sealed.inspectNote,
  noteToEnvelope: sealed.toEnvelope,
  noteFromEnvelope: sealed.fromEnvelope,
  generateCode: sealed.generateCode,
  assertCodeStrength: sealed.assertCodeStrength,
  estimateCodeEntropyBits: sealed.estimateCodeEntropyBits,
  guessableReason: sealed.guessableReason,
  codeEntropyBits: sealed.codeEntropyBits,
  MIN_CODE_ENTROPY_BITS: sealed.MIN_CODE_ENTROPY_BITS,

  // Utilities worth exposing
  fingerprint: codec.fingerprint,
};
