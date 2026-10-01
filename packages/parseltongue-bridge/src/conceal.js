'use strict';

/**
 * The concealment layer: turn a sealed note into something that looks like an ordinary message.
 *
 * This is the AGPL side of the seam — it reaches into the P4RS3LT0NGV3 transform catalog. The
 * cryptography lives in @reconlion/capsule-core (Apache-2.0) and knows nothing about this file.
 *
 * WHAT CONCEALMENT IS AND IS NOT
 *
 * It is NOT what keeps the message secret. The sealed note underneath does that. Concealment buys
 * *low observability* — a casual reader sees a normal message instead of an obvious blob of
 * ciphertext. That is a real property and a different one from confidentiality, and the two get
 * confused constantly, so every function here reports which it is providing.
 *
 * Concealment is also not invisibility to inspection: `inspectText` finds these carriers
 * immediately. What it defeats is a human skim, not an analyst.
 *
 * THE STYLES ARE NOT INTERCHANGEABLE
 *
 * Measured against the live catalog, not assumed. The cover-text column is the one that decides
 * the user experience, and `emoji` differs from the others in a way that cannot be worked around:
 * its decoder consumes every emoji in the input, so any emoji in a cover message corrupts the
 * payload.
 */

const { runTransform } = require('./run');
const { inspectText } = require('./inspect');

class ConcealError extends Error {}

/**
 * Carrier styles, keyed by the name users see.
 *
 * `ratio` is carrier characters per payload character, measured 2026-10-01 against a real sealed
 * note. `coverText` records whether visible text may accompany the payload.
 */
const STYLES = {
  invisible: {
    transform: 'invisible_text',
    coverText: true,
    ratio: 1,
    label: 'Invisible (Unicode tag characters)',
    sees: 'only your cover message — the payload renders as nothing at all',
    bestFor: 'a message that should look completely ordinary. The default.',
    caveats: [
      'Some platforms strip Unicode tag characters. If a recipient gets your cover message with ' +
        'nothing hidden in it, try the zerowidth style instead.',
    ],
  },
  zerowidth: {
    transform: 'zerowidth_steganography',
    coverText: true,
    ratio: 4,
    label: 'Zero-width',
    sees: 'only your cover message — the payload renders as nothing at all',
    bestFor: 'a fallback when tag characters get stripped. Four times larger than invisible.',
    caveats: [
      'Four characters of carrier per character of payload, so the artifact gets large quickly.',
    ],
  },
  emoji: {
    transform: 'emoji_encoding',
    coverText: false,
    ratio: 1,
    label: 'Emoji',
    sees: 'a string of emoji, and nothing else',
    bestFor: 'contexts where an emoji-only message is unremarkable.',
    caveats: [
      'CANNOT be combined with cover text. The decoder reads every emoji in the input, so any ' +
        'emoji in a covering message corrupts the payload — verified: text before or after ' +
        'yields nothing, and an emoji in the cover yields garbage.',
      'The message is visibly a wall of emoji. That is conspicuous in most conversations.',
    ],
  },
};

const STYLE_NAMES = Object.freeze(Object.keys(STYLES));

function styleOrThrow(name) {
  const style = STYLES[name];
  if (!style) {
    throw new ConcealError(
      `unknown style "${name}". Available: ${STYLE_NAMES.join(', ')}. Call conceal_options for ` +
        'what each one looks like.'
    );
  }
  return style;
}

/**
 * The offerings: what each style would do with this particular payload.
 *
 * Returned before the user commits to one, so an impossible combination (emoji plus cover text)
 * is refused at the point of choosing rather than discovered at the far end.
 */
function describeStyles({ payloadLength = 0, hasCoverText = false } = {}) {
  return STYLE_NAMES.map((name) => {
    const style = STYLES[name];
    const carrierChars = payloadLength ? payloadLength * style.ratio : null;
    const compatible = !hasCoverText || style.coverText;
    return {
      style: name,
      label: style.label,
      coverTextSupported: style.coverText,
      compatibleWithYourRequest: compatible,
      incompatibleReason: compatible
        ? null
        : 'you supplied cover text, and this style cannot carry any',
      recipientSees: style.sees,
      bestFor: style.bestFor,
      charactersPerPayloadChar: style.ratio,
      estimatedCarrierChars: carrierChars,
      caveats: style.caveats,
    };
  });
}

/**
 * Does this payload actually look like something encrypted by this project?
 *
 * FOUND IN REVIEW: `conceal` originally took a `payloadIsEncrypted` boolean that DEFAULTED TO
 * TRUE, so a caller who handed it plaintext got back a confidentiality statement saying "the
 * payload was encrypted before concealment". That is a false assurance produced by the safe-
 * sounding default, which is the worst kind. Detecting beats trusting a flag: the two formats this
 * project produces are recognisable, and anything else is treated as not-encrypted.
 */
function detectEncryptedPayload(payload) {
  const text = String(payload);
  if (/PARSELTONGUE SEALED NOTE/.test(text)) return 'sealed note';
  if (/PARSELTONGUE CAPSULE/.test(text)) return 'capsule';
  // A bare JSON record from either format.
  if (/"ct"\s*:\s*"[A-Za-z0-9_-]{20,}"/.test(text) && /"nonce"\s*:/.test(text)) return 'raw record';
  return null;
}

/**
 * Hide an already-encrypted payload inside a carrier.
 *
 * This function does not encrypt and will not pretend to. Whether the payload is actually
 * encrypted is **detected**, not declared by the caller — see `detectEncryptedPayload`. If it is
 * not, `confidentiality` says so in as many words and `encrypted` is false.
 */
function conceal({ payload, style, coverText = '' }) {
  const chosen = styleOrThrow(style);

  if (typeof payload !== 'string' || !payload) {
    throw new ConcealError('nothing to conceal');
  }

  const cover = typeof coverText === 'string' ? coverText : '';
  if (cover && !chosen.coverText) {
    throw new ConcealError(
      `the "${style}" style cannot carry cover text. ${chosen.caveats[0]} ` +
        'Use the invisible or zerowidth style if you want a visible covering message.'
    );
  }

  const hidden = String(runTransform(chosen.transform, { action: 'encode', text: payload }).output);
  if (!hidden) {
    throw new ConcealError(`the ${style} transform produced no output for this payload`);
  }

  const artifact = cover ? `${cover}${hidden}` : hidden;
  const visiblePreview = visibleOf(artifact);
  const encryptedAs = detectEncryptedPayload(payload);

  const warnings = [];

  // An invisible carrier with no cover text renders as a COMPLETELY BLANK message. That is
  // conspicuous in its own way — an empty message in a chat draws the eye — and the first version
  // of this function said nothing about it.
  if (!cover && chosen.coverText) {
    warnings.push(
      'No cover text, so this artifact renders as a completely blank message. That is its own ' +
        'kind of conspicuous — an empty message invites a second look. Supply cover_text with ' +
        'something ordinary in it.'
    );
  }

  if (!encryptedAs) {
    warnings.push(
      'This payload does not look like anything this tool encrypted. Concealment on its own is ' +
        'representation, not secrecy - anyone who notices the hidden characters reads it with no key.'
    );
  }

  return {
    artifact,
    style,
    // Exactly what the recipient will see rendered. For the invisible styles this must equal the
    // cover text; a test asserts it, because if anything extra shows up the feature has failed.
    visiblePreview,
    coverText: cover,
    encrypted: Boolean(encryptedAs),
    encryptedAs,
    warnings,
    sizes: {
      payloadChars: payload.length,
      artifactChars: [...artifact].length,
      visibleChars: [...visiblePreview].length,
    },
    confidentiality: encryptedAs
      ? `The payload is an encrypted ${encryptedAs}. Concealment adds low observability on top of ` +
        'that — it makes the message look ordinary; the encryption is what makes it secret.'
      : 'WARNING: this payload is NOT encrypted as far as this tool can tell. Concealment is ' +
        'representation only - anyone who notices the hidden characters can read it with no key. ' +
        'This is not secure.',
  };
}

/** Pull a concealed payload back out of a carrier. */
function reveal({ artifact, style = null }) {
  if (typeof artifact !== 'string' || !artifact) {
    throw new ConcealError('nothing to reveal');
  }

  const order = style ? [style] : STYLE_NAMES;
  const attempts = [];

  for (const name of order) {
    const candidate = STYLES[name];
    if (!candidate) continue;
    try {
      const output = String(runTransform(candidate.transform, { action: 'decode', text: artifact }).output);
      // A style that yields nothing did not match; keep looking rather than reporting success.
      if (output) return { payload: output, style: name, attempts };
      attempts.push({ style: name, result: 'no payload found' });
    } catch (err) {
      attempts.push({ style: name, result: err.message.slice(0, 80) });
    }
  }

  throw new ConcealError(
    'no hidden payload found in that text. Either it carries nothing, the concealment was ' +
      'stripped in transit (some platforms remove invisible characters), or it used a style this ' +
      `build does not know. Tried: ${order.join(', ')}.`
  );
}

/** Visible rendering of a string: everything a human would actually see. */
function visibleOf(text) {
  return [...String(text)]
    .filter((char) => {
      const cp = char.codePointAt(0);
      if (cp >= 0x200b && cp <= 0x200f) return false; // zero-width, directional marks
      if (cp >= 0x202a && cp <= 0x202e) return false; // bidi controls
      if (cp >= 0x2060 && cp <= 0x2064) return false; // word joiner, invisible operators
      if (cp >= 0x2066 && cp <= 0x2069) return false; // bidi isolates
      if (cp >= 0xfe00 && cp <= 0xfe0f) return false; // variation selectors
      if (cp === 0xfeff) return false; // BOM
      if (cp >= 0xe0000 && cp <= 0xe007f) return false; // Unicode tags
      if (cp >= 0xe0100 && cp <= 0xe01ef) return false; // variation selector supplement
      return true;
    })
    .join('');
}

/** Does this text appear to carry a concealed payload? Structural only, no decode attempted. */
function looksConcealed(text) {
  const report = inspectText(text);
  return {
    likely: report.counts.hidden > 0,
    hiddenCharacters: report.counts.hidden,
    kinds: report.hidden.map((h) => h.name),
    visiblePreview: visibleOf(text),
    note:
      report.counts.hidden > 0
        ? 'This text contains invisible characters consistent with a concealed payload. That does ' +
          'not prove it is one, and it does not prove the payload is encrypted.'
        : 'No invisible characters found. An emoji-style carrier would not show up here - it is ' +
          'made of visible emoji.',
  };
}

module.exports = {
  ConcealError,
  STYLES,
  STYLE_NAMES,
  conceal,
  describeStyles,
  looksConcealed,
  reveal,
  visibleOf,
};
