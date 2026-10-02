'use strict';

/**
 * Sealed notes — symmetric, "decrypt code" encryption.
 *
 * This is the format for: person A seals a note under a code, sends the note one way and the code
 * another, person B opens it with the code. No identities, no key exchange, no contact cards.
 *
 * WHY THIS EXISTS ALONGSIDE capsule.js
 *
 * `capsule.js` is public-key: it proves *who* sealed a message, and requires the recipient to have
 * published a contact card and had their fingerprint verified before a first message is possible.
 * That is the right shape when authorship matters. It is the wrong shape when two people just want
 * to share a secret and can agree a code.
 *
 * WHAT YOU GIVE UP: a shared code proves only that the sealer knew the code. It cannot distinguish
 * person A from anyone else who knows it. There is no signature here and no way to add one that
 * would mean anything. If you need to prove authorship, use a capsule.
 *
 * WHAT YOU GET: no setup. One call, one code, send it.
 *
 * THE SECURITY OF THE WHOLE SCHEME IS THE CODE AND ITS SEPARATION FROM THE NOTE. An attacker
 * holding the note can grind candidate codes offline with no rate limit and no lockout. Argon2id
 * makes each guess cost real memory and time; it cannot rescue a weak code, and nothing can rescue
 * a code that travelled in the same message as the note.
 *
 * FORMAT v1
 *
 *   visible:    v, id, created, kdf{alg,m,t,p}, salt, nonce
 *   encrypted:  ct   (XChaCha20-Poly1305 over the payload)
 *
 * The entire visible header is bound as AEAD associated data, so editing the KDF parameters, the
 * timestamp or the salt breaks decryption rather than silently weakening it. Same construction as
 * capsule.js, same reasoning.
 */

const { xchacha20poly1305 } = require('@noble/ciphers/chacha.js');
const { argon2id } = require('@noble/hashes/argon2.js');
const { randomBytes, randomInt } = require('node:crypto');

const { b64u, canonicalBytes, digestHex, fromUtf8, toBytes, unb64u, wipe } = require('./codec');
const { WORDLIST } = require('./wordlist');

const SEALED_VERSION = 1;
const NONCE_BYTES = 24;
const SALT_BYTES = 16;
const KEY_BYTES = 32;

// Matches the vault's cost. ~1.9s per derivation on a Raspberry Pi, which is tolerable once per
// message and expensive per guess for anyone grinding offline.
const DEFAULT_KDF = { alg: 'argon2id', m: 65536, t: 3, p: 1 };

const MAX_PAYLOAD_BYTES = 256 * 1024;

// Generated codes: 6 words plus a 4-digit number. Measured against the live wordlist rather than
// assumed — see codeEntropyBits.
const CODE_WORDS = 6;
const CODE_NUMBER_MIN = 1000;
const CODE_NUMBER_MAX = 9999;

/**
 * Minimum entropy for a user-supplied code.
 *
 * Set against what Argon2id at DEFAULT_KDF actually costs an attacker, not a round number. At
 * 64 MiB and t=3 a well-funded adversary might manage ~10^4 guesses/second; 50 bits is then on the
 * order of a thousand years. The floor sits a little above that so the margin survives better
 * hardware. A generated code clears it by ~17 bits.
 */
const MIN_CODE_ENTROPY_BITS = 50;

const SEALED_HEADER = '----- PARSELTONGUE SEALED NOTE v1 -----';
const SEALED_FOOTER = '----- END PARSELTONGUE SEALED NOTE -----';

class SealedError extends Error {}

// ---------------------------------------------------------------- codes

/** Bits of entropy in a generated code, computed from the live wordlist. */
function codeEntropyBits() {
  return CODE_WORDS * Math.log2(WORDLIST.length) + Math.log2(CODE_NUMBER_MAX - CODE_NUMBER_MIN + 1);
}

/**
 * Generate a decrypt code.
 *
 * Word-based on purpose. The code has to survive being read down a phone line or typed from a
 * sticky note onto another device — that is the entire mechanism that keeps it separate from the
 * note. A base64 blob gets mis-typed, and a frustrated human then pastes it into the same chat
 * window as the note, which removes all protection. Words are longer to look at and far harder
 * to get wrong.
 *
 * `randomInt` is rejection-sampled by Node, so there is no modulo bias.
 */
function generateCode() {
  const words = [];
  for (let i = 0; i < CODE_WORDS; i += 1) words.push(WORDLIST[randomInt(WORDLIST.length)]);
  const number = randomInt(CODE_NUMBER_MIN, CODE_NUMBER_MAX + 1);
  // Number in the middle rather than at the end: it breaks up the run of words, which makes the
  // code easier to read back in two halves without losing your place.
  const middle = Math.ceil(CODE_WORDS / 2);
  return [...words.slice(0, middle), String(number), ...words.slice(middle)].join('-');
}

/**
 * Codes that are guessable regardless of how much "entropy" a character-class model assigns them.
 *
 * FOUND IN TESTING: the character-class estimator alone scored `password123` at 57 bits and
 * accepted it. That number is arithmetically defensible and operationally worthless — the string
 * is in every cracking dictionary ever assembled, so its real strength against an offline attack
 * is close to zero. `Tr0ub4dor&3` has the same problem for the same reason.
 *
 * An entropy estimate measures how long a code is, not how *obvious* it is. Those are different
 * properties and need separate gates, so patterns are rejected before any arithmetic happens.
 * This list is not exhaustive and cannot be; it catches the shapes people actually reach for when
 * asked to invent a password, which is the realistic case.
 */
const GUESSABLE_EXACT = new Set([
  'password', 'passw0rd', 'password1', 'password123', 'p@ssword', 'p@ssw0rd',
  'letmein', 'welcome', 'welcome1', 'admin', 'administrator', 'root', 'toor',
  'qwerty', 'qwertyuiop', 'asdfgh', 'zxcvbn', '1q2w3e4r', 'qazwsx',
  'iloveyou', 'monkey', 'dragon', 'sunshine', 'princess', 'football', 'baseball',
  'trustno1', 'hunter', 'hunter2', 'master', 'shadow', 'superman', 'batman',
  'secret', 'secrets', 'changeme', 'default', 'test', 'test123', 'temp', 'guest',
  'abc123', '123456', '1234567', '12345678', '123456789', '1234567890', '111111',
  'correcthorsebatterystaple', 'troubador', 'tr0ub4dor',
]);

const GUESSABLE_PATTERNS = [
  { test: /^(.)\1*$/, why: 'it is a single repeated character' },
  { test: /^(..?.?)\1+$/, why: 'it is a short pattern repeated' },
  { test: /^(?:0?1?2?3?4?5?6?7?8?9?)+$/, why: 'it is a run of digits' },
  { test: /^[a-z]+\d{1,4}$/i, why: 'it is one word followed by digits, the first thing any cracker tries' },
  { test: /^\d{1,4}[a-z]+$/i, why: 'it is digits followed by one word' },
  { test: /qwert|asdfg|zxcvb|yuiop|hjkl/i, why: 'it contains a keyboard run' },
  { test: /^(?:19|20)\d{2}$/, why: 'it is a year' },
];

/** Strip leet substitutions so `p@ssw0rd` is recognised as `password`. */
function deleet(text) {
  return text
    .toLowerCase()
    .replace(/[@4]/g, 'a')
    .replace(/[3€]/g, 'e')
    .replace(/[1!|]/g, 'i')
    .replace(/0/g, 'o')
    .replace(/[5$]/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b');
}

/**
 * Is this code guessable by shape or by being a known favourite? Returns a reason, or null.
 *
 * Checked BEFORE entropy, because no amount of length rescues a dictionary hit.
 */
function guessableReason(code) {
  const text = String(code).trim();
  const bare = text.replace(/[-_\s.]/g, '');
  const candidates = [text.toLowerCase(), bare.toLowerCase(), deleet(bare)];

  for (const candidate of candidates) {
    if (GUESSABLE_EXACT.has(candidate)) {
      return 'it is one of the most commonly used passwords in existence';
    }
  }
  for (const { test, why } of GUESSABLE_PATTERNS) {
    if (test.test(bare)) return why;
  }
  // A single dictionary word, with or without decoration, is one guess against the wordlist.
  if (/^[a-z]+$/i.test(bare) && bare.length <= 12) {
    return 'it is a single word, which is one guess for an attacker with a dictionary';
  }
  return null;
}

/**
 * Estimate the entropy of a code the user supplied.
 *
 * Deliberately conservative. If every token is a wordlist word or a plain number, it is scored as
 * a generated-style code. Otherwise it falls back to a per-character estimate over the character
 * classes actually present — the standard rough model, which rates `hunter2` as hopeless and, on
 * its own, badly overrates `password123`. That is what `guessableReason` is for; this function
 * measures length and variety only, and is never the sole gate.
 */
function estimateCodeEntropyBits(code) {
  const text = String(code);
  const tokens = text.split(/[-_\s.]+/).filter(Boolean);

  const wordSet = new Set(WORDLIST);
  const allKnown = tokens.length >= 3 && tokens.every((t) => wordSet.has(t.toLowerCase()) || /^\d+$/.test(t));
  if (allKnown) {
    return tokens.reduce(
      (sum, t) => sum + (/^\d+$/.test(t) ? Math.log2(10 ** t.length) : Math.log2(WORDLIST.length)),
      0
    );
  }

  let alphabet = 0;
  if (/[a-z]/.test(text)) alphabet += 26;
  if (/[A-Z]/.test(text)) alphabet += 26;
  if (/\d/.test(text)) alphabet += 10;
  if (/[^A-Za-z0-9]/.test(text)) alphabet += 20;
  if (alphabet === 0) return 0;

  // Penalise a code built from a small number of distinct characters ("aaaaaaaaaa").
  const distinct = new Set(text).size;
  const effectiveLength = Math.min(text.length, distinct * 3);
  return effectiveLength * Math.log2(alphabet);
}

/**
 * Is this code derived from the message it is protecting?
 *
 * FOUND IN A NAIVE-USER RUN: a message reading "meet me at the north gate at 9pm" was accepted
 * with the code `northgate9pm`. Sixty-two bits by the character-class model, and worthless —
 * anyone who intercepts both the artifact and the cover text can guess it in a handful of tries,
 * and the cover text travels *with* the artifact by design.
 *
 * This is the shape people naturally reach for, because a code tied to the message is easier to
 * remember. It is also the one kind of weak code the generic gates cannot see, since it depends
 * on context they are not given. Checked by token overlap: any word of four or more characters
 * shared between the code and the protected content is disqualifying.
 */
function derivedFromContent(code, ...content) {
  const normalise = (text) =>
    String(text || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ' ')
      .split(' ')
      .filter((w) => w.length >= 4);

  // Also split a run-together code like "northgate9pm" against the content's words, since the
  // user removed the separators that token comparison would otherwise rely on.
  const bare = String(code).toLowerCase().replace(/[^a-z0-9]+/g, '');
  const codeTokens = new Set(normalise(code));

  for (const piece of content) {
    for (const word of normalise(piece)) {
      if (codeTokens.has(word)) return word;
      if (bare.includes(word)) return word;
    }
  }
  return null;
}

/**
 * Throw unless the code clears every gate, naming the reason.
 *
 * `context` is the message and cover text when available, so a code lifted from the content can be
 * refused. Optional: the gate degrades to the generic checks when context is not supplied.
 */
function assertCodeStrength(code, context = []) {
  if (typeof code !== 'string' || !code.trim()) {
    throw new SealedError('a decrypt code is required');
  }

  const borrowed = derivedFromContent(code, ...context);
  if (borrowed) {
    throw new SealedError(
      `that code will not do: it reuses "${borrowed}" from the message or its cover text. The ` +
        'cover text travels WITH the artifact, so anyone who intercepts it can guess a code built ' +
        'from the same words in a few tries. Leave the code out and one will be generated for you ' +
        `at about ${codeEntropyBits().toFixed(0)} bits.`
    );
  }

  // Guessability first: a dictionary hit is unaffected by how long the string is.
  const guessable = guessableReason(code);
  if (guessable) {
    throw new SealedError(
      `that code will not do: ${guessable}. Anyone who gets the note can try codes offline as ` +
        'fast as their hardware allows, starting with exactly this kind. Leave the code out and ' +
        `one will be generated for you at about ${codeEntropyBits().toFixed(0)} bits.`
    );
  }

  const bits = estimateCodeEntropyBits(code);
  if (bits < MIN_CODE_ENTROPY_BITS) {
    throw new SealedError(
      `that code is too weak: roughly ${bits.toFixed(0)} bits of entropy, and ${MIN_CODE_ENTROPY_BITS} ` +
        'is the floor. Anyone who gets the note can try codes offline as fast as their hardware ' +
        'allows - there is no server to rate-limit them and no lockout. Leave the code out and one ' +
        `will be generated for you at about ${codeEntropyBits().toFixed(0)} bits.`
    );
  }
  return bits;
}

// ---------------------------------------------------------------- crypto

function deriveKey(code, salt, kdf) {
  if (kdf.alg !== 'argon2id') throw new SealedError(`unsupported KDF "${kdf.alg}"`);
  if (!(kdf.m >= 8192 && kdf.t >= 1 && kdf.p >= 1)) {
    throw new SealedError(`stored KDF parameters are too weak to trust (m=${kdf.m} t=${kdf.t} p=${kdf.p})`);
  }
  return argon2id(code, salt, { m: kdf.m, t: kdf.t, p: kdf.p, dkLen: KEY_BYTES });
}

/** The cleartext part, and exactly what is bound as associated data. */
function sealedHeader(note) {
  return { v: note.v, created: note.created, kdf: note.kdf, salt: note.salt, nonce: note.nonce };
}

/**
 * Seal a note under a code.
 *
 * Returns the note, a pasteable envelope, and the code — the caller needs the code in hand to
 * transmit it, so it is returned rather than hidden. Whoever calls this is responsible for
 * getting it to the recipient by a *different* route than the note.
 */
function sealNote({ payload, code = null, kdf = DEFAULT_KDF, context = [] }) {
  const payloadBytes = toBytes(payload == null ? '' : payload);
  if (payloadBytes.length === 0) throw new SealedError('refusing to seal an empty message');
  if (payloadBytes.length > MAX_PAYLOAD_BYTES) {
    throw new SealedError(`message is ${payloadBytes.length} bytes; the limit is ${MAX_PAYLOAD_BYTES}`);
  }

  const generated = code === null || code === undefined;
  const resolvedCode = generated ? generateCode() : String(code);
  // The payload itself is always part of the context: a code lifted from the message is
  // guessable by anyone who later obtains the message.
  const entropyBits = generated
    ? codeEntropyBits()
    : assertCodeStrength(resolvedCode, [payload, ...context]);

  const salt = new Uint8Array(randomBytes(SALT_BYTES));
  const nonce = new Uint8Array(randomBytes(NONCE_BYTES));

  const note = {
    v: SEALED_VERSION,
    id: null,
    created: new Date().toISOString(),
    kdf: { ...kdf },
    salt: b64u(salt),
    nonce: b64u(nonce),
    ct: null,
  };

  const key = deriveKey(resolvedCode, salt, note.kdf);
  try {
    const aead = xchacha20poly1305(key, nonce, canonicalBytes(sealedHeader(note)));
    note.ct = b64u(aead.encrypt(payloadBytes));
  } finally {
    wipe(key);
  }
  note.id = digestHex(note.ct).slice(0, 16);

  return {
    note,
    envelope: toEnvelope(note),
    code: resolvedCode,
    codeGenerated: generated,
    codeEntropyBits: Math.round(entropyBits),
    warning:
      'Send the code by a DIFFERENT route than this note. If both travel the same way, anyone ' +
      'who reads that channel reads the message - the encryption buys you nothing. Speak it, or ' +
      'use a different app than the one carrying the note.',
  };
}

/**
 * Open a note with a code.
 *
 * A wrong code and a tampered note produce the same error, deliberately: distinguishing them tells
 * an attacker which of the two they achieved.
 */
function openNote({ note, code }) {
  const parsed = typeof note === 'string' ? fromEnvelope(note) : note;
  assertShape(parsed);

  if (typeof code !== 'string' || !code) throw new SealedError('a decrypt code is required');

  const key = deriveKey(code, unb64u(parsed.salt), parsed.kdf);
  let plaintext;
  try {
    const aead = xchacha20poly1305(key, unb64u(parsed.nonce), canonicalBytes(sealedHeader(parsed)));
    plaintext = aead.decrypt(unb64u(parsed.ct));
  } catch {
    throw new SealedError(
      'could not open this note: wrong code, or the note was altered after sealing. Those two ' +
        'look identical from here on purpose. Check the code for typos - words are hyphen ' +
        'separated and case does not matter.'
    );
  } finally {
    wipe(key);
  }

  let text;
  try {
    text = fromUtf8(plaintext);
  } catch {
    throw new SealedError('the note decrypted but is not valid UTF-8 text');
  } finally {
    wipe(plaintext);
  }

  return {
    payload: text,
    noteId: parsed.id,
    created: parsed.created,
    visible: {
      version: parsed.v,
      noteId: parsed.id,
      created: parsed.created,
      createdIsAClaim: 'timestamp is set by the sender and is not independently verifiable',
      kdf: parsed.kdf,
    },
    authorship:
      'A code proves whoever sealed this knew the code. It cannot prove who that was - anyone ' +
      'holding the code could have sealed it. Use a capsule if you need to prove authorship.',
  };
}

/** Structure and signature-free integrity report, without the code. */
function inspectNote(note) {
  let parsed;
  try {
    parsed = typeof note === 'string' ? fromEnvelope(note) : note;
    assertShape(parsed);
  } catch (err) {
    return {
      wellFormed: false,
      error: err.message,
      findings: [{ severity: 'high', detail: err.message }],
    };
  }

  const ciphertextBytes = unb64u(parsed.ct).length;
  const idExpected = digestHex(parsed.ct).slice(0, 16);
  const findings = [];
  if (parsed.id !== idExpected) {
    findings.push({
      severity: 'medium',
      detail: `note id does not match its ciphertext (claims ${parsed.id}, computes ${idExpected})`,
    });
  }

  return {
    wellFormed: true,
    version: parsed.v,
    noteId: parsed.id,
    visible: {
      created: parsed.created,
      kdf: parsed.kdf,
    },
    encrypted: {
      ciphertextBytes,
      approximatePlaintextBytes: Math.max(0, ciphertextBytes - 16),
    },
    findings,
    notes: [
      'No code was supplied, so nothing was decrypted. This is safe to run on a note you cannot open.',
      'A sealed note carries NO sender identity and NO signature. There is nothing here to tell ' +
        'you who sealed it; only the code does that, and only by implication.',
      'The timestamp and KDF parameters are visible but bound into the encryption - editing them ' +
        'breaks decryption rather than weakening it.',
    ],
  };
}

// ---------------------------------------------------------------- envelope

function toEnvelope(note) {
  const encoded = b64u(canonicalBytes(note));
  const lines = encoded.match(/.{1,76}/g) || [''];
  return [SEALED_HEADER, `id: ${note.id}`, '', ...lines, SEALED_FOOTER].join('\n');
}

/**
 * Parse an envelope.
 *
 * Damage-tolerant by design: it recovers the body as the longest run of base64url characters
 * between the markers rather than filtering by line, so a note survives being pasted through a
 * client that strips newlines, re-wraps, or indents it. `capsule.js` learned this the hard way —
 * 4 of 5 realistic channel-damage modes destroyed its envelope, and the one that broke most often
 * reported "envelope is empty", which told the user nothing useful.
 */
function fromEnvelope(text) {
  if (typeof text !== 'string') throw new SealedError('expected sealed note text');
  const trimmed = text.trim();
  if (!trimmed) throw new SealedError('nothing to read');

  if (trimmed.startsWith('{')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      throw new SealedError('looks like JSON but does not parse');
    }
  }

  // Normalise characters that "smart" editors substitute, so the markers still match.
  const normalised = trimmed
    .replace(/[‐-―−]/g, '-')
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[​-‏﻿]/g, '')
    .replace(/=\r?\n/g, ''); // quoted-printable soft breaks

  if (!normalised.includes('PARSELTONGUE SEALED NOTE')) {
    throw new SealedError(
      'this is not a Parseltongue sealed note. Paste the whole block including the ----- lines.'
    );
  }

  const endMarker = normalised.search(/-{3,}\s*END\s+PARSELTONGUE\s+SEALED\s+NOTE/i);

  // Slice from the END of the opening marker, so the marker's own words are never part of the body.
  const openMarker = normalised.match(/-{3,}\s*PARSELTONGUE\s+SEALED\s+NOTE[^-]*?-{3,}/i);
  if (!openMarker) {
    throw new SealedError(
      'the opening marker line is damaged beyond recognition. Paste the whole block, or ask for ' +
        'the note as a file attachment.'
    );
  }
  const region = normalised.slice(
    openMarker.index + openMarker[0].length,
    endMarker === -1 ? undefined : endMarker
  );

  // Strip the known metadata, then keep every remaining base64url character in order.
  //
  // TWO EARLIER ATTEMPTS WERE WRONG, both caught by tests rather than review:
  //
  //  1. "longest single base64url run" returned one wrapped line out of five, because the body is
  //     emitted at 76 characters per line.
  //  2. "every run of 32+ characters, joined" silently DROPPED the final line whenever the body
  //     length mod 76 fell below 32 - roughly two messages in five. A payload containing smart
  //     quotes happened to land there, which made it look like a character-encoding problem when
  //     it was arithmetic.
  //
  // Keeping every base64url character has no length threshold to get wrong, and it is what makes
  // the parser damage-tolerant: re-flowing, indenting or un-wrapping the text changes nothing it
  // looks at. It is safe because the region excludes both markers, and the only other furniture
  // is the `id:` line, whose value is always exactly 16 lowercase hex characters.
  const body = region
    .replace(/id\s*:\s*[0-9a-f]{16}/gi, '')
    .replace(/[^A-Za-z0-9_-]/g, '');

  if (!body) {
    throw new SealedError(
      endMarker === -1
        ? 'the note has no terminator and no readable body - it was probably truncated in transit. ' +
          'Ask for it again, or send it as a file attachment.'
        : 'the note has no readable body. It may have been truncated, or re-encoded by whatever ' +
          'carried it. Ask for it as a file attachment.'
    );
  }

  let json;
  try {
    json = fromUtf8(unb64u(body));
  } catch {
    throw new SealedError(
      'the note body did not decode. Something in transit rewrote it - some chat clients and mail ' +
        'gateways alter long strings. Try sending it as a file attachment instead of pasted text.'
    );
  }

  try {
    return JSON.parse(json);
  } catch {
    throw new SealedError('the note body decoded but is not valid JSON; it is probably incomplete');
  }
}

function assertShape(note) {
  if (!note || typeof note !== 'object') throw new SealedError('sealed note is not an object');
  if (note.v !== SEALED_VERSION) {
    throw new SealedError(`unsupported sealed note version ${note.v}; this build understands v${SEALED_VERSION}`);
  }
  for (const field of ['id', 'created', 'salt', 'nonce', 'ct']) {
    if (typeof note[field] !== 'string' || !note[field]) {
      throw new SealedError(`sealed note is missing "${field}"`);
    }
  }
  if (!note.kdf || typeof note.kdf !== 'object') throw new SealedError('sealed note is missing its KDF parameters');
  if (unb64u(note.salt).length !== SALT_BYTES) throw new SealedError('salt is malformed');
  if (unb64u(note.nonce).length !== NONCE_BYTES) throw new SealedError('nonce is malformed');
  if (unb64u(note.ct).length > MAX_PAYLOAD_BYTES + 1024) {
    throw new SealedError('ciphertext exceeds the supported size');
  }
}

module.exports = {
  DEFAULT_KDF,
  guessableReason,
  derivedFromContent,
  MAX_PAYLOAD_BYTES,
  MIN_CODE_ENTROPY_BITS,
  SEALED_FOOTER,
  SEALED_HEADER,
  SEALED_VERSION,
  SealedError,
  assertCodeStrength,
  codeEntropyBits,
  estimateCodeEntropyBits,
  fromEnvelope,
  generateCode,
  inspectNote,
  openNote,
  sealNote,
  toEnvelope,
};
