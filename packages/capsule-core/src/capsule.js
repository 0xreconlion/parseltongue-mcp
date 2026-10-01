'use strict';

/**
 * Sealing, opening and inspecting capsules.
 *
 * FORMAT v1
 *
 *   visible (anyone holding the capsule reads this):
 *     v          format version
 *     id         capsule id, derived from the ciphertext - not chooseable
 *     created    ISO-8601 timestamp, set by the sender's clock (so: a claim, not a fact)
 *     sender     { sign, signFingerprint }   who sealed it
 *     recipient  { encryptFingerprint }     which key can open it
 *     epk        ephemeral X25519 public key, fresh per capsule
 *     meta       arbitrary sender-supplied metadata - VISIBLE, NOT SECRET
 *     nonce      XChaCha20 nonce
 *   encrypted:
 *     ct         XChaCha20-Poly1305 ciphertext of the payload
 *   integrity:
 *     sig        Ed25519 signature over canonical(header) || ct
 *
 * WHY AN EPHEMERAL SENDER KEY
 * Each capsule generates a throwaway X25519 keypair; the shared secret comes from the sender's
 * ephemeral private key and the recipient's static public key. Consequences, all good:
 *   - a sender needs no X25519 key of their own to send, only Ed25519 to sign
 *   - compromising the sender's long-term keys later does not decrypt past capsules
 *   - two capsules with identical content produce different ciphertext
 * This is the same shape as age and HPKE, and it is why identity.js notes the static X25519 key
 * only ever decrypts.
 *
 * WHY THE HEADER IS BOUND AS ASSOCIATED DATA
 * The whole visible header is passed as AEAD associated data AND covered by the signature. So
 * editing any visible field - including the metadata and the claimed sender - breaks decryption
 * *and* breaks verification. Without this, someone could rewrite a sealed capsule's subject line
 * and it would still open cleanly.
 *
 * WHAT THE SIGNATURE DOES AND DOES NOT PROVE
 * It is computed over the header and ciphertext, not the plaintext. So it proves the holder of
 * the sender's Ed25519 private key produced *this exact capsule*, and it is verifiable WITHOUT
 * decrypting - which is what lets inspectCapsule check authenticity without unlocking a vault.
 * It does not independently prove the sender read the plaintext. For point-to-point use, where
 * the sender is the encryptor, that distinction does not bite; it is recorded here so nobody has
 * to re-derive it.
 *
 * WHAT LEAKS, ALWAYS
 * Sender key, recipient fingerprint, timestamp, metadata, and payload length are all visible.
 * A capsule hides content, not the fact of correspondence. inspectCapsule says so in writing.
 */

const { ed25519, x25519 } = require('@noble/curves/ed25519.js');
const { xchacha20poly1305 } = require('@noble/ciphers/chacha.js');
const { hkdf } = require('@noble/hashes/hkdf.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const { randomBytes } = require('node:crypto');

const {
  b64u,
  canonicalBytes,
  digestHex,
  fingerprint,
  fromUtf8,
  toBytes,
  unb64u,
  wipe,
} = require('./codec');

const CAPSULE_VERSION = 1;
const NONCE_BYTES = 24;
const KEY_BYTES = 32;
const HKDF_INFO = 'parseltongue-capsule-v1';
const MAX_PAYLOAD_BYTES = 1024 * 1024; // 1 MiB; this is a message tool, not a file transport
const MAX_META_BYTES = 4096;

const ENVELOPE_HEADER = '----- PARSELTONGUE CAPSULE v1 -----';
const ENVELOPE_FOOTER = '----- END PARSELTONGUE CAPSULE -----';

class CapsuleError extends Error {}

/**
 * Derive the content key.
 *
 * Both identities are bound into the HKDF info, so a key derived for one (sender, recipient) pair
 * is useless in any other context even if the same shared secret somehow recurred.
 */
function deriveContentKey(sharedSecret, { senderSign, recipientEncrypt, epk }) {
  const info = toBytes(`${HKDF_INFO}|${senderSign}|${recipientEncrypt}|${epk}`);
  return hkdf(sha256, sharedSecret, new Uint8Array(32), info, KEY_BYTES);
}

function headerOf(capsule) {
  return {
    v: capsule.v,
    created: capsule.created,
    sender: capsule.sender,
    recipient: capsule.recipient,
    epk: capsule.epk,
    meta: capsule.meta,
    nonce: capsule.nonce,
  };
}

function signedBytes(header, ciphertextB64) {
  return toBytes(`${Buffer.from(canonicalBytes(header)).toString('utf8')}.${ciphertextB64}`);
}

/**
 * Seal a message to a recipient's contact.
 *
 * `senderSecret` is the unlocked secret bundle from the vault. `recipientContact` is a public
 * contact imported from a card.
 */
function sealCapsule({ senderSecret, senderPublic, recipientContact, payload, meta = {} }) {
  if (!senderSecret || !senderSecret.sign) throw new CapsuleError('sender secret is missing a signing key');
  if (!recipientContact || !recipientContact.encrypt) {
    throw new CapsuleError('recipient contact is missing an encryption key');
  }

  const payloadBytes = toBytes(payload == null ? '' : payload);
  if (payloadBytes.length === 0) throw new CapsuleError('refusing to seal an empty payload');
  if (payloadBytes.length > MAX_PAYLOAD_BYTES) {
    throw new CapsuleError(
      `payload is ${payloadBytes.length} bytes; the limit is ${MAX_PAYLOAD_BYTES}. Capsules are ` +
        'for messages, not file transport.'
    );
  }

  if (meta === null || typeof meta !== 'object' || Array.isArray(meta)) {
    throw new CapsuleError('meta must be a plain object');
  }
  const metaBytes = canonicalBytes(meta);
  if (metaBytes.length > MAX_META_BYTES) {
    throw new CapsuleError(`meta is ${metaBytes.length} bytes; the limit is ${MAX_META_BYTES}`);
  }
  // Metadata is visible. Refuse anything that looks like the caller mistook it for a secret field.
  for (const key of Object.keys(meta)) {
    if (/pass|secret|private|token|seed|key$/i.test(key)) {
      throw new CapsuleError(
        `meta field "${key}" looks like a secret. Capsule metadata is VISIBLE to anyone holding ` +
          'the capsule. Put it in the payload instead.'
      );
    }
  }

  const recipientEncrypt = unb64u(recipientContact.encrypt);
  if (recipientEncrypt.length !== 32) throw new CapsuleError('recipient encryption key is malformed');

  const ephemeralSecret = x25519.utils.randomSecretKey();
  const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);
  const nonce = new Uint8Array(randomBytes(NONCE_BYTES));

  const senderSignPublic = senderPublic
    ? senderPublic.sign
    : b64u(ed25519.getPublicKey(unb64u(senderSecret.sign)));

  const capsule = {
    v: CAPSULE_VERSION,
    id: null,
    created: new Date().toISOString(),
    sender: {
      sign: senderSignPublic,
      signFingerprint: fingerprint(unb64u(senderSignPublic)),
      label: (senderPublic && senderPublic.label) || '',
    },
    recipient: {
      encryptFingerprint: fingerprint(recipientEncrypt),
      label: recipientContact.label || '',
    },
    epk: b64u(ephemeralPublic),
    meta,
    nonce: b64u(nonce),
    ct: null,
    sig: null,
  };

  let shared;
  let contentKey;
  try {
    shared = x25519.getSharedSecret(ephemeralSecret, recipientEncrypt);
    contentKey = deriveContentKey(shared, {
      senderSign: capsule.sender.sign,
      recipientEncrypt: recipientContact.encrypt,
      epk: capsule.epk,
    });

    const header = headerOf(capsule);
    const aead = xchacha20poly1305(contentKey, nonce, canonicalBytes(header));
    capsule.ct = b64u(aead.encrypt(payloadBytes));
    capsule.id = digestHex(capsule.ct).slice(0, 16);
    capsule.sig = b64u(ed25519.sign(signedBytes(header, capsule.ct), unb64u(senderSecret.sign)));
  } finally {
    wipe(ephemeralSecret);
    if (shared) wipe(shared);
    if (contentKey) wipe(contentKey);
  }

  return {
    capsule,
    envelope: toEnvelope(capsule),
    visible: describeVisible(capsule),
    warning:
      'The header above is NOT secret: sender, recipient fingerprint, timestamp, metadata and ' +
      'payload size are readable by anyone holding this capsule. Only the payload is encrypted.',
  };
}

/**
 * Open a capsule with the recipient's unlocked secret.
 *
 * Verifies the signature first so a tampered capsule is rejected before any decryption is
 * attempted, then relies on the AEAD to catch anything the signature could not.
 */
function openCapsule({ capsule, recipientSecret, expectedSenderContact = null }) {
  const parsed = typeof capsule === 'string' ? fromEnvelope(capsule) : capsule;
  assertShape(parsed);

  if (!recipientSecret || !recipientSecret.encrypt) {
    throw new CapsuleError('recipient secret is missing an encryption key');
  }

  const recipientEncryptSecret = unb64u(recipientSecret.encrypt);
  const recipientEncryptPublic = x25519.getPublicKey(recipientEncryptSecret);
  const recipientFingerprint = fingerprint(recipientEncryptPublic);

  if (parsed.recipient.encryptFingerprint !== recipientFingerprint) {
    throw new CapsuleError(
      `this capsule is addressed to ${parsed.recipient.encryptFingerprint}, but this identity is ` +
        `${recipientFingerprint}. It was not sealed to you and cannot be opened with this key.`
    );
  }

  const header = headerOf(parsed);
  const senderSign = unb64u(parsed.sender.sign);
  const signatureOk = ed25519.verify(
    unb64u(parsed.sig),
    signedBytes(header, parsed.ct),
    senderSign
  );
  if (!signatureOk) {
    throw new CapsuleError(
      'signature does not verify. The capsule was altered after sealing, or it was not sealed by ' +
        'the key it claims. Do not trust its contents.'
    );
  }

  let shared;
  let contentKey;
  let plaintext;
  try {
    shared = x25519.getSharedSecret(recipientEncryptSecret, unb64u(parsed.epk));
    contentKey = deriveContentKey(shared, {
      senderSign: parsed.sender.sign,
      recipientEncrypt: b64u(recipientEncryptPublic),
      epk: parsed.epk,
    });
    const aead = xchacha20poly1305(contentKey, unb64u(parsed.nonce), canonicalBytes(header));
    plaintext = aead.decrypt(unb64u(parsed.ct));
  } catch (err) {
    if (err instanceof CapsuleError) throw err;
    throw new CapsuleError(
      'decryption failed even though the signature verified. The visible header was probably ' +
        'altered - it is bound into the encryption, so editing it breaks decryption too.'
    );
  } finally {
    if (shared) wipe(shared);
    if (contentKey) wipe(contentKey);
  }

  let payload;
  try {
    payload = fromUtf8(plaintext);
  } catch {
    throw new CapsuleError('payload decrypted but is not valid UTF-8 text');
  } finally {
    wipe(plaintext);
  }

  // Sender identity is cryptographically proven, but "proven to be key X" only means something
  // if you independently know key X belongs to the person you think it does.
  let senderTrust = {
    verified: true,
    fingerprint: parsed.sender.signFingerprint,
    matchesExpected: null,
    note:
      'The signature proves this capsule was sealed by the holder of the private key matching ' +
      `fingerprint ${parsed.sender.signFingerprint}. It does not prove who that person is unless ` +
      'you verified that fingerprint with them out of band.',
  };
  if (expectedSenderContact && expectedSenderContact.sign) {
    const matches = expectedSenderContact.sign === parsed.sender.sign;
    senderTrust = {
      ...senderTrust,
      matchesExpected: matches,
      note: matches
        ? `Signature matches the contact you expected (${expectedSenderContact.label || 'unnamed'}).`
        : 'WARNING: the signing key does NOT match the contact you expected. Treat this capsule ' +
          'as being from an unknown party.',
    };
    if (!matches) senderTrust.verified = true; // signature is valid; the *identity* is wrong
  }

  return {
    payload,
    capsuleId: parsed.id,
    created: parsed.created,
    meta: parsed.meta,
    sender: senderTrust,
    visible: describeVisible(parsed),
  };
}

/**
 * Inspect a capsule without any private key.
 *
 * Reports structure, what is visible, and whether the signature verifies. Deliberately does NOT
 * attempt decryption, so this is safe to run on a capsule that is not addressed to you.
 */
function inspectCapsule(capsule) {
  let parsed;
  let envelopeNote = null;
  try {
    parsed = typeof capsule === 'string' ? fromEnvelope(capsule) : capsule;
  } catch (err) {
    return {
      wellFormed: false,
      error: err.message,
      findings: [{ severity: 'high', detail: `not a readable capsule: ${err.message}` }],
    };
  }

  const findings = [];
  let wellFormed = true;
  try {
    assertShape(parsed);
  } catch (err) {
    wellFormed = false;
    findings.push({ severity: 'high', detail: err.message });
  }

  let signatureVerifies = null;
  if (wellFormed) {
    try {
      signatureVerifies = require('@noble/curves/ed25519.js').ed25519.verify(
        unb64u(parsed.sig),
        signedBytes(headerOf(parsed), parsed.ct),
        unb64u(parsed.sender.sign)
      );
    } catch {
      signatureVerifies = false;
    }
    if (signatureVerifies) {
      findings.push({
        severity: 'info',
        detail:
          `Signature verifies against ${parsed.sender.signFingerprint}. Nothing visible or ` +
          'encrypted has changed since sealing.',
      });
    } else {
      findings.push({
        severity: 'high',
        detail:
          'Signature does NOT verify. The capsule was altered after sealing, or was not sealed ' +
          'by the key it claims. Do not trust it.',
      });
    }

    const idExpected = digestHex(parsed.ct).slice(0, 16);
    if (parsed.id !== idExpected) {
      findings.push({
        severity: 'medium',
        detail: `capsule id does not match its ciphertext (claims ${parsed.id}, computes ${idExpected})`,
      });
    }
  }

  const ciphertextBytes = wellFormed ? unb64u(parsed.ct).length : 0;

  return {
    wellFormed,
    version: parsed && parsed.v,
    capsuleId: parsed && parsed.id,
    signatureVerifies,
    visible: wellFormed ? describeVisible(parsed) : null,
    encrypted: {
      payload: true,
      ciphertextBytes,
      // Length is not hidden. For short messages this is a real leak.
      approximatePlaintextBytes: Math.max(0, ciphertextBytes - 16),
    },
    findings,
    notes: [
      'No decryption was attempted. This is safe to run on a capsule not addressed to you.',
      'A capsule hides its PAYLOAD only. Sender, recipient fingerprint, timestamp, metadata and ' +
        'approximate message length are all visible to anyone holding it.',
      'Encoding or concealment applied on top of a capsule adds NO confidentiality. If this ' +
        'capsule arrived wrapped in base64, zero-width characters or any other transform, that ' +
        'wrapper is decoration - the capsule crypto is what protects the payload.',
    ],
  };
}

function describeVisible(capsule) {
  return {
    version: capsule.v,
    capsuleId: capsule.id,
    created: capsule.created,
    createdIsAClaim: 'timestamp is set by the sender and is not independently verifiable',
    senderSigningKey: capsule.sender.sign,
    senderFingerprint: capsule.sender.signFingerprint,
    senderLabel: capsule.sender.label || '',
    recipientFingerprint: capsule.recipient.encryptFingerprint,
    recipientLabel: capsule.recipient.label || '',
    metadata: capsule.meta,
  };
}

/** Wrap a capsule in a pasteable text envelope. */
function toEnvelope(capsule) {
  const json = Buffer.from(canonicalBytes(capsule)).toString('utf8');
  const encoded = b64u(toBytes(json));
  const lines = encoded.match(/.{1,76}/g) || [''];
  return [
    ENVELOPE_HEADER,
    `id: ${capsule.id}`,
    `to: ${capsule.recipient.encryptFingerprint}`,
    `from: ${capsule.sender.signFingerprint}`,
    '',
    ...lines,
    ENVELOPE_FOOTER,
  ].join('\n');
}

function fromEnvelope(text) {
  if (typeof text !== 'string') throw new CapsuleError('expected capsule text');

  // Accept a bare JSON capsule too - people will paste both.
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      throw new CapsuleError('looks like JSON but does not parse');
    }
  }

  if (!trimmed.includes(ENVELOPE_HEADER)) {
    throw new CapsuleError('not a Parseltongue capsule envelope');
  }

  const start = trimmed.indexOf(ENVELOPE_HEADER) + ENVELOPE_HEADER.length;
  const end = trimmed.indexOf(ENVELOPE_FOOTER);
  if (end === -1) throw new CapsuleError('capsule envelope has no terminator; it may be truncated');

  const body = trimmed
    .slice(start, end)
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !/^(id|to|from):/.test(line))
    .join('');

  if (!body) throw new CapsuleError('capsule envelope is empty');

  let json;
  try {
    json = fromUtf8(unb64u(body));
  } catch {
    throw new CapsuleError(
      'capsule body is not valid base64url. It was probably corrupted in transit - some chat ' +
        'clients rewrite long strings or strip line breaks.'
    );
  }

  try {
    return JSON.parse(json);
  } catch {
    throw new CapsuleError('capsule body decoded but is not valid JSON');
  }
}

function assertShape(capsule) {
  if (!capsule || typeof capsule !== 'object') throw new CapsuleError('capsule is not an object');
  if (capsule.v !== CAPSULE_VERSION) {
    throw new CapsuleError(`unsupported capsule version ${capsule.v}; this build understands v${CAPSULE_VERSION}`);
  }
  for (const field of ['id', 'created', 'epk', 'nonce', 'ct', 'sig']) {
    if (typeof capsule[field] !== 'string' || !capsule[field]) {
      throw new CapsuleError(`capsule is missing "${field}"`);
    }
  }
  if (!capsule.sender || typeof capsule.sender.sign !== 'string') {
    throw new CapsuleError('capsule is missing sender.sign');
  }
  if (!capsule.recipient || typeof capsule.recipient.encryptFingerprint !== 'string') {
    throw new CapsuleError('capsule is missing recipient.encryptFingerprint');
  }
  if (capsule.meta === null || typeof capsule.meta !== 'object' || Array.isArray(capsule.meta)) {
    throw new CapsuleError('capsule meta must be an object');
  }
  if (unb64u(capsule.epk).length !== 32) throw new CapsuleError('ephemeral key is malformed');
  if (unb64u(capsule.nonce).length !== NONCE_BYTES) throw new CapsuleError('nonce is malformed');
  if (unb64u(capsule.sig).length !== 64) throw new CapsuleError('signature is malformed');
  if (unb64u(capsule.ct).length > MAX_PAYLOAD_BYTES + 1024) {
    throw new CapsuleError('ciphertext exceeds the supported size');
  }
}

module.exports = {
  CAPSULE_VERSION,
  CapsuleError,
  ENVELOPE_FOOTER,
  ENVELOPE_HEADER,
  MAX_META_BYTES,
  MAX_PAYLOAD_BYTES,
  fromEnvelope,
  inspectCapsule,
  openCapsule,
  sealCapsule,
  toEnvelope,
};
