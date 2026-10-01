'use strict';

/**
 * Identities and contact cards.
 *
 * An identity is two keypairs:
 *
 *   Ed25519  - signing. Proves who sealed a capsule.
 *   X25519   - key agreement. Lets others encrypt TO you.
 *
 * They are separate because they do separate jobs, and because reusing one key for both is a
 * well-known way to create cross-protocol attacks. Nothing here ever needs the sender's static
 * X25519 private key: senders use a fresh ephemeral X25519 keypair per capsule (see capsule.js),
 * so the static X25519 key only ever decrypts.
 *
 * A contact card carries PUBLIC keys only. The guarantee that no private material reaches a
 * contact card is enforced by test, not by reading the code.
 */

const { ed25519, x25519 } = require('@noble/curves/ed25519.js');

const { b64u, canonical, digestHex, fingerprint, unb64u } = require('./codec');

const IDENTITY_VERSION = 1;
const CARD_VERSION = 1;
const CARD_HEADER = '----- PARSELTONGUE CONTACT CARD v1 -----';
const CARD_FOOTER = '----- END PARSELTONGUE CONTACT CARD -----';

class IdentityError extends Error {}

/**
 * Generate a new identity. Returns both halves; the caller is responsible for putting `secret`
 * into a vault and never letting it out again.
 */
function createIdentity({ label = '' } = {}) {
  if (typeof label !== 'string' || label.length > 200) {
    throw new IdentityError('label must be a string of at most 200 characters');
  }

  const signSecret = ed25519.utils.randomSecretKey();
  const signPublic = ed25519.getPublicKey(signSecret);
  const encryptSecret = x25519.utils.randomSecretKey();
  const encryptPublic = x25519.getPublicKey(encryptSecret);

  const publicPart = {
    v: IDENTITY_VERSION,
    label,
    sign: b64u(signPublic),
    encrypt: b64u(encryptPublic),
    created: new Date().toISOString(),
  };

  return {
    public: {
      ...publicPart,
      signFingerprint: fingerprint(signPublic),
      encryptFingerprint: fingerprint(encryptPublic),
      id: identityId(publicPart),
    },
    // Private material. Never serialise this anywhere but an encrypted vault or backup.
    secret: {
      v: IDENTITY_VERSION,
      sign: b64u(signSecret),
      encrypt: b64u(encryptSecret),
    },
  };
}

/** Stable identity id: a digest over the public keys, so it cannot be chosen or spoofed. */
function identityId(publicPart) {
  return digestHex(canonical({ sign: publicPart.sign, encrypt: publicPart.encrypt })).slice(0, 16);
}

/** Recover public keys from stored secret material, so a vault need not trust its own copy. */
function derivePublic(secret, { label = '', created = null } = {}) {
  const signPublic = ed25519.getPublicKey(unb64u(secret.sign));
  const encryptPublic = x25519.getPublicKey(unb64u(secret.encrypt));
  const publicPart = {
    v: IDENTITY_VERSION,
    label,
    sign: b64u(signPublic),
    encrypt: b64u(encryptPublic),
    created: created || new Date().toISOString(),
  };
  return {
    ...publicPart,
    signFingerprint: fingerprint(signPublic),
    encryptFingerprint: fingerprint(encryptPublic),
    id: identityId(publicPart),
  };
}

/**
 * Render a contact card for sharing. Public keys only.
 *
 * Deliberately a text block rather than a file format: it has to survive being pasted into chat,
 * email, or a commit message, which is the whole point of the design.
 */
function exportContactCard(publicIdentity) {
  assertPublicOnly(publicIdentity);

  const body = {
    v: CARD_VERSION,
    label: publicIdentity.label || '',
    sign: publicIdentity.sign,
    encrypt: publicIdentity.encrypt,
    created: publicIdentity.created,
  };
  const checksum = digestHex(canonical(body)).slice(0, 16);

  const card = [
    CARD_HEADER,
    `label:    ${body.label || '(unnamed)'}`,
    `sign:     ${body.sign}`,
    `encrypt:  ${body.encrypt}`,
    `created:  ${body.created}`,
    `checksum: ${checksum}`,
    '',
    `# Verify out of band before trusting this card.`,
    `# signing fingerprint:    ${publicIdentity.signFingerprint}`,
    `# encryption fingerprint: ${publicIdentity.encryptFingerprint}`,
    '# Public keys only. Anyone may hold this. It cannot decrypt anything.',
    CARD_FOOTER,
  ].join('\n');

  return { card, checksum, fingerprints: {
    sign: publicIdentity.signFingerprint,
    encrypt: publicIdentity.encryptFingerprint,
  } };
}

/**
 * Parse a contact card. Rejects anything carrying private-looking fields rather than quietly
 * ignoring them — a card that tries to ship a secret is either a bug or an attack, and in both
 * cases the right move is to refuse it loudly.
 */
function importContactCard(text) {
  if (typeof text !== 'string' || !text.includes(CARD_HEADER)) {
    throw new IdentityError('not a Parseltongue contact card');
  }

  const fields = {};
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-----')) continue;
    const match = /^([a-z]+):\s*(.*)$/.exec(trimmed);
    if (match) fields[match[1]] = match[2].trim();
  }

  for (const forbidden of ['secret', 'private', 'seed', 'passphrase', 'mnemonic']) {
    if (forbidden in fields) {
      throw new IdentityError(
        `contact card contains a "${forbidden}" field. Contact cards carry public keys only; ` +
          'refusing to import. Whoever produced this card may have leaked their private key.'
      );
    }
  }

  if (!fields.sign || !fields.encrypt) {
    throw new IdentityError('contact card is missing the sign or encrypt key');
  }

  const signPublic = unb64u(fields.sign);
  const encryptPublic = unb64u(fields.encrypt);
  if (signPublic.length !== 32) throw new IdentityError('sign key is not a 32-byte Ed25519 public key');
  if (encryptPublic.length !== 32) throw new IdentityError('encrypt key is not a 32-byte X25519 public key');

  const label = fields.label === '(unnamed)' ? '' : fields.label || '';
  const body = {
    v: CARD_VERSION,
    label,
    sign: fields.sign,
    encrypt: fields.encrypt,
    created: fields.created,
  };
  const expected = digestHex(canonical(body)).slice(0, 16);

  // A checksum mismatch means the card was altered in transit or retyped wrong. It is NOT a
  // signature and proves nothing about authenticity — hence the wording.
  const checksumOk = !fields.checksum || fields.checksum === expected;

  const publicPart = {
    v: IDENTITY_VERSION,
    label,
    sign: fields.sign,
    encrypt: fields.encrypt,
    created: fields.created || null,
  };

  return {
    contact: {
      ...publicPart,
      signFingerprint: fingerprint(signPublic),
      encryptFingerprint: fingerprint(encryptPublic),
      id: identityId(publicPart),
    },
    checksumOk,
    checksumExpected: expected,
    checksumFound: fields.checksum || null,
    warnings: checksumOk
      ? []
      : [
          'Checksum does not match. The card was altered or mistyped. A checksum only detects ' +
            'accidental corruption - it is not a signature and cannot prove who wrote the card. ' +
            'Confirm the fingerprints with the sender over a channel you already trust.',
        ],
  };
}

/**
 * Guard against handing private material to anything that serialises for sharing. This exists
 * because "we only pass the public object here" is an assumption that rots.
 */
function assertPublicOnly(candidate) {
  if (!candidate || typeof candidate !== 'object') {
    throw new IdentityError('expected a public identity object');
  }
  for (const banned of ['secret', 'private', 'seed', 'passphrase']) {
    if (banned in candidate) {
      throw new IdentityError(
        `refusing to export: object carries a "${banned}" field. Pass identity.public, not the ` +
          'whole identity.'
      );
    }
  }
  if (!candidate.sign || !candidate.encrypt) {
    throw new IdentityError('public identity is missing the sign or encrypt key');
  }
}

module.exports = {
  CARD_FOOTER,
  CARD_HEADER,
  CARD_VERSION,
  IDENTITY_VERSION,
  IdentityError,
  assertPublicOnly,
  createIdentity,
  derivePublic,
  exportContactCard,
  identityId,
  importContactCard,
};
