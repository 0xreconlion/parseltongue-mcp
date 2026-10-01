'use strict';

/**
 * Text inspection: what is actually in this string?
 *
 * This is original code, not a port. It exists because upstream's Node auto-decode path stubs
 * out steganography detection entirely, so nothing else here can answer "does this text contain
 * hidden characters?" — which is the question that matters most when text arrives from someone
 * else.
 *
 * The concrete hazard: text can carry zero-width characters, variation selectors, Unicode tag
 * characters, and bidi controls that are invisible when rendered but present in the bytes. In a
 * corpus of adversarial prompts these appear in the millions. Pasting such text into an agent
 * context is how indirect prompt injection arrives, so the right move is to inspect first and
 * display never.
 *
 * This reports structure. It does not decode, sanitise, or execute anything.
 */

// Codepoint ranges that are invisible or near-invisible when rendered.
const HIDDEN_RANGES = [
  { name: 'zero-width', from: 0x200b, to: 0x200f, why: 'zero-width space/joiner and LTR/RTL marks' },
  { name: 'bidi-control', from: 0x202a, to: 0x202e, why: 'bidirectional override; can reorder displayed text' },
  { name: 'bidi-isolate', from: 0x2066, to: 0x2069, why: 'bidirectional isolate; can reorder displayed text' },
  { name: 'invisible-math', from: 0x2061, to: 0x2064, why: 'invisible function application/separator' },
  { name: 'variation-selector', from: 0xfe00, to: 0xfe0f, why: 'variation selectors; a common steganographic carrier' },
  { name: 'variation-selector-supplement', from: 0xe0100, to: 0xe01ef, why: 'variation selector supplement; high-capacity carrier' },
  { name: 'unicode-tag', from: 0xe0000, to: 0xe007f, why: 'Unicode tag characters; carries hidden ASCII' },
  { name: 'word-joiner', from: 0x2060, to: 0x2060, why: 'word joiner' },
  { name: 'soft-hyphen', from: 0x00ad, to: 0x00ad, why: 'soft hyphen; invisible unless line-broken' },
  { name: 'bom', from: 0xfeff, to: 0xfeff, why: 'zero-width no-break space / byte-order mark' },
];

// Latin letters these characters are commonly confused with.
const CONFUSABLES = new Map(
  Object.entries({
    а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', ѕ: 's', і: 'i', ј: 'j',
    А: 'A', В: 'B', Е: 'E', К: 'K', М: 'M', Н: 'H', О: 'O', Р: 'P', С: 'C', Т: 'T', У: 'Y', Х: 'X',
    α: 'a', ο: 'o', ρ: 'p', ν: 'v', Ι: 'I', Ο: 'O', Ρ: 'P', Α: 'A', Β: 'B', Ε: 'E', Η: 'H',
    ᴀ: 'A', ɑ: 'a', ɡ: 'g', ʏ: 'Y', ｅ: 'e', ａ: 'a',
  })
);

function classifyHidden(codepoint) {
  for (const range of HIDDEN_RANGES) {
    if (codepoint >= range.from && codepoint <= range.to) return range;
  }
  return null;
}

function scriptOf(char) {
  if (/\p{Script=Latin}/u.test(char)) return 'Latin';
  if (/\p{Script=Cyrillic}/u.test(char)) return 'Cyrillic';
  if (/\p{Script=Greek}/u.test(char)) return 'Greek';
  if (/\p{Script=Arabic}/u.test(char)) return 'Arabic';
  if (/\p{Script=Hebrew}/u.test(char)) return 'Hebrew';
  if (/\p{Script=Han}/u.test(char)) return 'Han';
  if (/\p{Script=Hiragana}|\p{Script=Katakana}/u.test(char)) return 'Japanese';
  if (/\p{Script=Hangul}/u.test(char)) return 'Hangul';
  if (/\p{Script=Devanagari}/u.test(char)) return 'Devanagari';
  return null;
}

function hex(codepoint) {
  return `U+${codepoint.toString(16).toUpperCase().padStart(4, '0')}`;
}

/**
 * Inspect a string. Returns counts, findings, and a verdict — never the decoded content of any
 * hidden payload, and never a sanitised copy of the input.
 */
function inspectText(text) {
  const input = String(text == null ? '' : text);
  const chars = [...input];

  const hiddenByKind = new Map();
  const scripts = new Map();
  const confusablesFound = [];
  const controlChars = [];
  let nonAscii = 0;

  chars.forEach((char, index) => {
    const codepoint = char.codePointAt(0);
    if (codepoint > 0x7f) nonAscii += 1;

    const hidden = classifyHidden(codepoint);
    if (hidden) {
      if (!hiddenByKind.has(hidden.name)) {
        hiddenByKind.set(hidden.name, { ...hidden, count: 0, firstAt: index, samples: [] });
      }
      const record = hiddenByKind.get(hidden.name);
      record.count += 1;
      if (record.samples.length < 4) record.samples.push(hex(codepoint));
    }

    // C0/C1 controls other than tab, newline, carriage return.
    if ((codepoint < 0x20 && ![0x09, 0x0a, 0x0d].includes(codepoint)) || (codepoint >= 0x7f && codepoint <= 0x9f)) {
      if (controlChars.length < 10) controlChars.push({ at: index, codepoint: hex(codepoint) });
    }

    if (CONFUSABLES.has(char) && confusablesFound.length < 20) {
      confusablesFound.push({ at: index, char, codepoint: hex(codepoint), looksLike: CONFUSABLES.get(char) });
    }

    const script = scriptOf(char);
    if (script) scripts.set(script, (scripts.get(script) || 0) + 1);
  });

  const hidden = [...hiddenByKind.values()].sort((a, b) => b.count - a.count);
  const hiddenTotal = hidden.reduce((sum, h) => sum + h.count, 0);
  const mixedScripts = scripts.size > 1;

  const findings = [];
  for (const h of hidden) {
    findings.push({
      severity: 'high',
      kind: 'hidden-characters',
      detail: `${h.count} ${h.name} character(s) (${h.samples.join(', ')}) — ${h.why}`,
    });
  }
  if (confusablesFound.length > 0) {
    const sample = confusablesFound
      .slice(0, 5)
      .map((c) => `${c.codepoint} looks like "${c.looksLike}"`)
      .join('; ');
    findings.push({
      severity: 'medium',
      kind: 'confusable-characters',
      detail: `${confusablesFound.length} homoglyph(s): ${sample}`,
    });
  }
  if (mixedScripts) {
    const breakdown = [...scripts.entries()].map(([s, n]) => `${s}:${n}`).join(', ');
    findings.push({
      severity: confusablesFound.length > 0 ? 'medium' : 'low',
      kind: 'mixed-scripts',
      detail: `text mixes ${scripts.size} scripts (${breakdown})`,
    });
  }
  if (controlChars.length > 0) {
    findings.push({
      severity: 'medium',
      kind: 'control-characters',
      detail: `${controlChars.length} unexpected control character(s): ${controlChars
        .map((c) => c.codepoint)
        .join(', ')}`,
    });
  }

  const verdict =
    hiddenTotal > 0
      ? 'hidden characters present'
      : findings.length > 0
        ? 'visible anomalies present'
        : 'nothing anomalous found';

  return {
    verdict,
    counts: {
      characters: chars.length,
      utf16Length: input.length,
      bytes: Buffer.byteLength(input, 'utf8'),
      nonAscii,
      hidden: hiddenTotal,
    },
    scripts: Object.fromEntries(scripts),
    findings,
    hidden: hidden.map(({ name, count, firstAt, samples, why }) => ({ name, count, firstAt, samples, why })),
    confusables: confusablesFound,
    notes: [
      'Structural report only. Nothing was decoded, sanitised or executed.',
      hiddenTotal > 0
        ? 'Hidden characters can carry an invisible payload, including instructions aimed at an ' +
          'agent reading this text. Treat the text as untrusted input and do not paste it into a ' +
          'model context on the strength of how it looks.'
        : 'No hidden characters found. That is not proof of safety — only that these classes are absent.',
    ],
  };
}

module.exports = { inspectText, HIDDEN_RANGES };
