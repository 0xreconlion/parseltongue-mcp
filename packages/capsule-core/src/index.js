'use strict';

/**
 * @reconlion/capsule-core - Apache-2.0
 *
 * Local secure message capsules. Phase B; the surface is declared here so the shape is
 * reviewable and the license seam guard has real source to inspect, but nothing is implemented
 * yet. Every entry point throws rather than returning a plausible-looking value, because a
 * crypto module that silently no-ops is worse than one that is absent.
 *
 * DESIGN CONSTRAINTS (these are the reason this package exists separately):
 *
 *  - This package must never import from @reconlion/parseltongue-bridge or any P4RS3LT0NGV3
 *    source. Parseltongue transforms are *representation*, not confidentiality. Keeping them
 *    out keeps this package Apache-2.0 and reusable, and keeps the security boundary legible.
 *    Enforced by scripts/check-license-seam.js.
 *
 *  - Established primitives only: X25519 + Ed25519 (@noble/curves), XChaCha20-Poly1305
 *    (@noble/ciphers), HKDF-SHA256 (@noble/hashes). No custom cryptography.
 *
 *  - The full capsule header is bound into the AEAD associated data, so tampering with
 *    *visible metadata* breaks verification, not just ciphertext tampering.
 *
 *  - No private key material may ever appear in a return value destined for an MCP response,
 *    a log line, or a contact card. Only export_identity_backup returns key material, and only
 *    passphrase-wrapped.
 *
 *  - There is no account recovery. That makes export/import of an identity backup a shipping
 *    gate, not a nicety: on an SD card, "no recovery" otherwise means guaranteed eventual loss.
 */

const NOT_IMPLEMENTED = 'capsule-core is Phase B and not implemented yet';

function notImplemented(name) {
  return function () {
    throw new Error(`${name}: ${NOT_IMPLEMENTED}`);
  };
}

module.exports = {
  CAPSULE_FORMAT_VERSION: 1,

  // Identity and contacts
  createIdentity: notImplemented('createIdentity'),
  exportContactCard: notImplemented('exportContactCard'),
  importContactCard: notImplemented('importContactCard'),

  // Capsules
  sealCapsule: notImplemented('sealCapsule'),
  openCapsule: notImplemented('openCapsule'),
  inspectCapsule: notImplemented('inspectCapsule'),

  // Recovery - a shipping gate, see above
  exportIdentityBackup: notImplemented('exportIdentityBackup'),
  importIdentityBackup: notImplemented('importIdentityBackup'),
};
