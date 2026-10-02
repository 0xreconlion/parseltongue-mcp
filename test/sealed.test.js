'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const sealed = require('../packages/capsule-core/src/sealed');
const { WORDLIST, DROPPED, differsByOneLetter } = require('../packages/capsule-core/src/wordlist');
const { upstreamRoot } = require('./helpers/upstream-root');

// Must be set before the bridge is required - it resolves the checkout at load time.
process.env.PARSELTONGUE_ROOT = upstreamRoot();

const bridge = require('../packages/parseltongue-bridge/src');

const SECRET = 'the drop is at 0400, east gate';
const FAST_KDF = { alg: 'argon2id', m: 8192, t: 1, p: 1 };

// Production Argon2id costs ~1.9s per derivation, which would put this file past a minute. Most
// tests exercise format and tamper behavior, not KDF cost, so they use the lightest accepted
// parameters. `exercises the shipped KDF defaults` runs at the real ones.
function seal(payload = SECRET, code = null) {
  return sealed.sealNote({ payload, code, kdf: FAST_KDF });
}

describe('wordlist', () => {
  it('publishes a collision-free list', () => {
    // The module enforces the one-letter rule rather than claiming it; this proves the enforcement
    // works. An earlier draft asserted the rule in a comment while containing 198 violating pairs.
    const pairs = [];
    for (let i = 0; i < WORDLIST.length; i += 1) {
      for (let j = i + 1; j < WORDLIST.length; j += 1) {
        if (differsByOneLetter(WORDLIST[i], WORDLIST[j])) pairs.push(`${WORDLIST[i]}/${WORDLIST[j]}`);
      }
    }
    assert.deepEqual(pairs, [], `one-letter pairs survived the filter: ${pairs.slice(0, 10).join(' ')}`);
  });

  it('is large enough to be worth having, and reports what it dropped', () => {
    assert.ok(WORDLIST.length >= 400, `only ${WORDLIST.length} words published`);
    assert.ok(WORDLIST.every((w) => /^[a-z]{3,7}$/.test(w)), 'a malformed word reached the list');
    assert.equal(new Set(WORDLIST).size, WORDLIST.length, 'duplicates in the published list');
    // The filter must be able to account for what it removed, or a word can vanish unnoticed.
    assert.ok(DROPPED.collided.length > 0, 'expected the collision filter to have removed something');
  });
});

describe('code generation', () => {
  it('clears the entropy floor, measured against the live wordlist', () => {
    // Measured, not asserted in a comment: if a word is added or removed this moves.
    const bits = sealed.codeEntropyBits();
    const expected = 6 * Math.log2(WORDLIST.length) + Math.log2(9000);
    assert.ok(Math.abs(bits - expected) < 0.01, `entropy drifted from the wordlist: ${bits}`);
    assert.ok(bits >= sealed.MIN_CODE_ENTROPY_BITS + 10, `only ${bits.toFixed(1)} bits generated`);
  });

  it('generates distinct codes made only of known words and a number', () => {
    const wordSet = new Set(WORDLIST);
    const seen = new Set();
    for (let i = 0; i < 50; i += 1) {
      const code = sealed.generateCode();
      seen.add(code);
      const tokens = code.split('-');
      assert.equal(tokens.length, 7, `unexpected shape: ${code}`);
      const numbers = tokens.filter((t) => /^\d{4}$/.test(t));
      assert.equal(numbers.length, 1, `expected exactly one 4-digit group: ${code}`);
      for (const token of tokens) {
        assert.ok(wordSet.has(token) || /^\d{4}$/.test(token), `unknown token "${token}" in ${code}`);
      }
    }
    assert.ok(seen.size > 45, 'generated codes repeat far too often');
  });
});

describe('code strength gates', () => {
  it('refuses the passwords people actually pick', () => {
    // password123 scored 57 bits on the character-class model and was ACCEPTED before the
    // guessability gate existed. Entropy measures length, not obviousness.
    for (const weak of [
      'hunter2', 'password123', 'p@ssw0rd', 'PASSWORD123', 'Password-123',
      'letmein', 'iloveyou', 'secret', 'qwertyuiop123', 'abc123', '12345678',
      'aaaaaaaaaaaaaaaa', 'abcabcabcabc', 'correct-horse-battery-staple',
    ]) {
      assert.throws(
        () => sealed.assertCodeStrength(weak),
        (err) => {
          // The refusal must say why, or the user just tries another bad one.
          assert.match(err.message, /will not do|too weak/);
          return true;
        },
        `"${weak}" was accepted`
      );
    }
  });

  it('accepts a generated code and a strong word code', () => {
    sealed.assertCodeStrength(sealed.generateCode());
    sealed.assertCodeStrength('river-amber-9312-vault-crisp-mesa');
  });

  it('refuses an empty or missing code', () => {
    for (const bad of ['', '   ', null, undefined, 42]) {
      assert.throws(() => sealed.assertCodeStrength(bad), /code is required/);
    }
  });

  it('checks guessability before entropy, so length cannot rescue a dictionary hit', () => {
    // A long string built from a known password still fails.
    const padded = 'password123';
    assert.ok(sealed.estimateCodeEntropyBits(padded) > 50, 'precondition: entropy model rates it as fine');
    assert.ok(sealed.guessableReason(padded), 'the guessability gate must catch it');
    assert.throws(() => sealed.assertCodeStrength(padded), /will not do/);
  });
});

describe('seal and open', () => {
  it('round-trips through the envelope', () => {
    const note = seal();
    const opened = sealed.openNote({ note: note.envelope, code: note.code });
    assert.equal(opened.payload, SECRET);
  });

  it('returns the code so the sender can transmit it', () => {
    const note = seal();
    assert.equal(typeof note.code, 'string');
    assert.equal(note.codeGenerated, true);
    assert.ok(note.codeEntropyBits >= sealed.MIN_CODE_ENTROPY_BITS);
    // And warns about the one mistake that destroys the scheme.
    assert.match(note.warning, /DIFFERENT route/);
  });

  it('never claims to prove authorship', () => {
    const note = seal();
    const opened = sealed.openNote({ note: note.note, code: note.code });
    assert.match(opened.authorship, /cannot prove who that was/);
  });

  it('produces different ciphertext for identical text under the same code', () => {
    const code = sealed.generateCode();
    const a = seal('identical', code);
    const b = seal('identical', code);
    assert.notEqual(a.note.ct, b.note.ct);
    assert.notEqual(a.note.salt, b.note.salt);
    assert.notEqual(a.note.nonce, b.note.nonce);
  });

  it('round-trips unicode and multi-line text intact', () => {
    const payload = 'line one\nline two\t🦁 ünïcödé — "quoted" \\ backslash\n';
    const note = seal(payload);
    assert.equal(sealed.openNote({ note: note.envelope, code: note.code }).payload, payload);
  });

  it('refuses an empty or oversized payload', () => {
    assert.throws(() => seal(''), /empty message/);
    assert.throws(() => seal('x'.repeat(sealed.MAX_PAYLOAD_BYTES + 1)), /the limit is/);
  });

  it('exercises the shipped KDF defaults, not just the fast test ones', () => {
    // Every other test here uses FAST_KDF. Without this, a change that weakened the real defaults
    // would pass a fully green suite.
    const note = sealed.sealNote({ payload: 'production defaults' });
    assert.equal(note.note.kdf.alg, 'argon2id');
    assert.ok(
      note.note.kdf.m >= 19456 && note.note.kdf.t >= 2,
      `shipped KDF is below OWASP's floor (m=${note.note.kdf.m} t=${note.note.kdf.t})`
    );
    assert.equal(sealed.openNote({ note: note.note, code: note.code }).payload, 'production defaults');
  });
});

describe('tamper resistance', () => {
  it('rejects a wrong code and a tampered note identically', () => {
    const note = seal();
    const wrongCode = () => sealed.openNote({ note: note.note, code: sealed.generateCode() });

    const tampered = JSON.parse(JSON.stringify(note.note));
    const bytes = Buffer.from(tampered.ct.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    bytes[3] ^= 0xff;
    tampered.ct = bytes.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const tamperedOpen = () => sealed.openNote({ note: tampered, code: note.code });

    let wrongMessage;
    let tamperedMessage;
    assert.throws(wrongCode, (e) => { wrongMessage = e.message; return true; });
    assert.throws(tamperedOpen, (e) => { tamperedMessage = e.message; return true; });
    // Distinguishing them would tell an attacker which of the two they achieved.
    assert.equal(wrongMessage, tamperedMessage, 'wrong code and tampering must be indistinguishable');
  });

  it('rejects an edited timestamp', () => {
    const note = seal();
    const t = JSON.parse(JSON.stringify(note.note));
    t.created = '2020-01-01T00:00:00.000Z';
    assert.throws(() => sealed.openNote({ note: t, code: note.code }), /could not open/);
  });

  it('defeats a plausible KDF downgrade through the AAD binding', () => {
    const note = seal();
    const t = JSON.parse(JSON.stringify(note.note));
    t.kdf.m = 16384; // above the hard floor, so only the associated-data binding catches it
    assert.throws(() => sealed.openNote({ note: t, code: note.code }), /could not open/);
  });

  it('refuses an absurdly weak stored KDF outright', () => {
    const note = seal();
    const t = JSON.parse(JSON.stringify(note.note));
    t.kdf.m = 8;
    assert.throws(() => sealed.openNote({ note: t, code: note.code }), /too weak to trust/);
  });

  it('rejects a swapped salt', () => {
    const note = seal();
    const other = seal();
    const t = JSON.parse(JSON.stringify(note.note));
    t.salt = other.note.salt;
    assert.throws(() => sealed.openNote({ note: t, code: note.code }), /could not open/);
  });

  it('rejects malformed and wrong-version notes', () => {
    assert.throws(() => sealed.openNote({ note: '{}', code: 'x'.repeat(20) }), /unsupported sealed note version/);
    const note = seal();
    const future = JSON.parse(JSON.stringify(note.note));
    future.v = 99;
    assert.throws(() => sealed.openNote({ note: future, code: note.code }), /unsupported sealed note version/);
  });
});

describe('envelope damage tolerance', () => {
  // capsule.js lost 4 of 5 of these. The sealed note parser concatenates every base64url run
  // between the markers instead of filtering lines, which is what makes it survive re-flowing.
  const DAMAGE = {
    'newlines stripped (chat paste)': (e) => e.replace(/\n/g, ' '),
    'newlines removed entirely': (e) => e.replace(/\n/g, ''),
    'quoted-printable soft breaks': (e) => e.replace(/(.{60})/g, '$1=\n'),
    'unicode dashes substituted': (e) => e.replace(/-----/g, '—————'),
    'markdown indentation': (e) => e.split('\n').map((l) => `    ${l}`).join('\n'),
    'zero-width noise injected': (e) => e.replace(/\n/g, '​\n'),
    'trailing whitespace added': (e) => e.split('\n').map((l) => `${l}   `).join('\n'),
  };

  for (const [name, damage] of Object.entries(DAMAGE)) {
    it(`survives ${name}`, () => {
      const note = seal();
      const opened = sealed.openNote({ note: damage(note.envelope), code: note.code });
      assert.equal(opened.payload, SECRET);
    });
  }

  it('still fails on truncation, and says so', () => {
    const note = seal();
    assert.throws(
      () => sealed.openNote({ note: note.envelope.slice(0, 200), code: note.code }),
      /truncated|incomplete|no readable body/
    );
  });

  it('names a likely cause rather than saying the envelope is empty', () => {
    // capsule.js reported "capsule envelope is empty" for the most common damage mode, which told
    // the user nothing actionable.
    assert.throws(
      () => sealed.fromEnvelope('----- PARSELTONGUE SEALED NOTE v1 -----\nid: abc\n'),
      (err) => {
        assert.ok(!/is empty$/.test(err.message), 'unhelpful error message');
        assert.match(err.message, /truncated|file attachment/);
        return true;
      }
    );
  });
});

describe('inspect without a code', () => {
  it('reports structure and the absence of any identity', () => {
    const note = seal();
    const report = sealed.inspectNote(note.envelope);
    assert.equal(report.wellFormed, true);
    assert.ok(report.encrypted.approximatePlaintextBytes > 0);
    const notes = report.notes.join(' ');
    assert.match(notes, /NO sender identity and NO signature/);
    assert.match(notes, /nothing was decrypted/i);
  });

  it('returns a finding rather than throwing on garbage', () => {
    const report = sealed.inspectNote('not a note at all');
    assert.equal(report.wellFormed, false);
    assert.ok(report.findings.length > 0);
  });
});

describe('concealment layer', () => {
  const STYLES = ['invisible', 'zerowidth', 'emoji'];
  const COVER = 'Hey! Running late, see you at the thing 🙂';

  for (const style of STYLES) {
    it(`${style}: conceal then reveal returns the exact payload`, () => {
      const note = seal();
      const concealed = bridge.conceal({
        payload: note.envelope,
        style,
        coverText: style === 'emoji' ? '' : COVER,
      });
      const found = bridge.revealConcealed({ artifact: concealed.artifact, style });
      assert.equal(found.payload, note.envelope);
      assert.equal(sealed.openNote({ note: found.payload, code: note.code }).payload, SECRET);
    });
  }

  it('invisible styles show the cover text and NOTHING else', () => {
    // The whole feature. If the recipient can see anything extra, it has failed.
    for (const style of ['invisible', 'zerowidth']) {
      const note = seal();
      const concealed = bridge.conceal({ payload: note.envelope, style, coverText: COVER });
      assert.equal(
        concealed.visiblePreview,
        COVER,
        `${style} leaked visible characters beyond the cover text`
      );
      assert.ok(concealed.sizes.artifactChars > concealed.sizes.visibleChars);
    }
  });

  it('refuses emoji with cover text, naming the reason', () => {
    const note = seal();
    assert.throws(
      () => bridge.conceal({ payload: note.envelope, style: 'emoji', coverText: COVER }),
      /cannot carry cover text/
    );
  });

  it('auto-detects the style on reveal', () => {
    for (const style of STYLES) {
      const note = seal();
      const concealed = bridge.conceal({
        payload: note.envelope,
        style,
        coverText: style === 'emoji' ? '' : COVER,
      });
      assert.equal(bridge.revealConcealed({ artifact: concealed.artifact }).style, style);
    }
  });

  it('detects an unencrypted payload rather than trusting a caller flag', () => {
    // An earlier version took a `payloadIsEncrypted` boolean that DEFAULTED TO TRUE, so handing
    // it plaintext produced a confident statement that the payload had been encrypted. A
    // safe-sounding default that lies is the worst kind, so the state is now detected.
    const clear = bridge.conceal({ payload: 'this is plaintext', style: 'invisible', coverText: 'hi' });
    assert.equal(clear.encrypted, false);
    assert.equal(clear.encryptedAs, null);
    assert.match(clear.confidentiality, /NOT encrypted/);
    assert.match(clear.confidentiality, /not secure/);
    assert.ok(clear.warnings.some((w) => /not look like anything this tool encrypted/.test(w)));
  });

  it('recognises a sealed note and a capsule as encrypted', () => {
    const note = seal();
    const sealedCarrier = bridge.conceal({ payload: note.envelope, style: 'invisible', coverText: 'hi' });
    assert.equal(sealedCarrier.encrypted, true);
    assert.equal(sealedCarrier.encryptedAs, 'sealed note');
    assert.match(sealedCarrier.confidentiality, /encryption is what makes it secret/);
    assert.deepEqual(sealedCarrier.warnings, [], 'a correct call should produce no warnings');
  });

  it('warns that an invisible carrier with no cover text renders as a blank message', () => {
    // Conspicuous in its own way: an empty message in a chat invites a second look. The first
    // version said nothing about it.
    const note = seal();
    const blank = bridge.conceal({ payload: note.envelope, style: 'invisible', coverText: '' });
    assert.equal(blank.visiblePreview, '');
    assert.ok(
      blank.warnings.some((w) => /completely blank message/.test(w)),
      'no warning given for a carrier that renders as nothing'
    );
  });

  it('finds nothing in ordinary text and explains the emoji blind spot', () => {
    const look = bridge.looksConcealed('just a normal message');
    assert.equal(look.likely, false);
    assert.match(look.note, /emoji-style carrier would not show up/);
  });

  it('flags an invisible carrier as present without decoding it', () => {
    const note = seal();
    const concealed = bridge.conceal({ payload: note.envelope, style: 'invisible', coverText: COVER });
    const look = bridge.looksConcealed(concealed.artifact);
    assert.equal(look.likely, true);
    assert.ok(look.hiddenCharacters > 100);
    assert.equal(look.visiblePreview, COVER);
  });

  it('rejects an unknown style and an empty payload', () => {
    assert.throws(() => bridge.conceal({ payload: 'x', style: 'telepathy' }), /unknown style/);
    assert.throws(() => bridge.conceal({ payload: '', style: 'invisible' }), /nothing to conceal/);
    assert.throws(() => bridge.revealConcealed({ artifact: 'plain text' }), /no hidden payload/);
  });

  it('describes styles with cover-text compatibility resolved', () => {
    const withCover = bridge.describeConcealStyles({ payloadLength: 450, hasCoverText: true });
    const emoji = withCover.find((s) => s.style === 'emoji');
    assert.equal(emoji.compatibleWithYourRequest, false);
    assert.match(emoji.incompatibleReason, /cannot carry any/);

    const withoutCover = bridge.describeConcealStyles({ payloadLength: 450, hasCoverText: false });
    assert.ok(withoutCover.every((s) => s.compatibleWithYourRequest));
    // Size estimates must be real, since a user picks a style on them.
    assert.equal(withoutCover.find((s) => s.style === 'zerowidth').estimatedCarrierChars, 1800);
  });
});

describe('the full two-person flow', () => {
  it('A conceals under a cover message, B reveals it with the code alone', () => {
    const COVER = 'running late, see you there';
    const secret = 'east gate, 0400, bring the drive';

    // Person A. No identity, no contact card, no key exchange — the entire point of this mode.
    const note = sealed.sealNote({ payload: secret, kdf: FAST_KDF });
    const artifact = bridge.conceal({
      payload: note.envelope,
      style: 'invisible',
      coverText: COVER,
    }).artifact;

    // What travels: one innocuous-looking message, and a code sent some other way.
    assert.equal(bridge.visibleOf(artifact), COVER);

    // Person B, holding only the artifact and the code.
    const found = bridge.revealConcealed({ artifact });
    assert.equal(sealed.openNote({ note: found.payload, code: note.code }).payload, secret);

    // And without the code, B gets nothing.
    assert.throws(
      () => sealed.openNote({ note: found.payload, code: sealed.generateCode() }),
      /could not open/
    );
  });

  it('survives the kinds of mangling a chat client actually applies to the artifact', () => {
    // An earlier version of this test replaced newlines in the artifact — which contains none,
    // so it asserted nothing and passed for the wrong reason. These are mutations that genuinely
    // land on a concealed artifact in transit.
    const secret = 'through a chat app';
    const note = sealed.sealNote({ payload: secret, kdf: FAST_KDF });
    const artifact = bridge.conceal({
      payload: note.envelope,
      style: 'invisible',
      coverText: 'running late',
    }).artifact;

    const mutations = {
      'leading and trailing whitespace': `  \n${artifact}\n  `,
      'cover text edited by the sender': artifact.replace('running late', 'running VERY late'),
      'quoted with a prefix': `> ${artifact}`,
      'NFC normalised': artifact.normalize('NFC'),
    };

    for (const [name, mutated] of Object.entries(mutations)) {
      const found = bridge.revealConcealed({ artifact: mutated });
      assert.equal(
        sealed.openNote({ note: found.payload, code: note.code }).payload,
        secret,
        `did not survive: ${name}`
      );
    }
  });

  it('fails clearly, not silently, when a platform strips the invisible characters', () => {
    // The realistic way this flow breaks: some platforms remove zero-width and tag characters.
    // The recipient then sees a perfectly normal message with nothing in it, and the tool has to
    // say which of the two it is rather than leaving them guessing.
    const note = sealed.sealNote({ payload: 'gone', kdf: FAST_KDF });
    const concealed = bridge.conceal({
      payload: note.envelope,
      style: 'invisible',
      coverText: 'running late',
    });

    const sanitised = bridge.visibleOf(concealed.artifact);
    assert.equal(sanitised, 'running late', 'precondition: stripping leaves only the cover');

    assert.throws(
      () => bridge.revealConcealed({ artifact: sanitised }),
      (err) => {
        assert.match(err.message, /no hidden payload/);
        // Must name the likely cause, since the user cannot see the difference themselves.
        assert.match(err.message, /stripped in transit|carries nothing/);
        return true;
      }
    );

    const look = bridge.looksConcealed(sanitised);
    assert.equal(look.likely, false);
    assert.equal(look.hiddenCharacters, 0);
  });
});

describe('wizard page parity', () => {
  /**
   * wizard/index.html re-implements the concealment extraction so it can work offline with zero
   * dependencies. Two implementations of the same encoding is where divergence bugs live, so the
   * page's own function is pulled out of the HTML and run against a real artifact here — it
   * cannot drift without this failing.
   */
  const fs = require('node:fs');
  const path = require('node:path');

  function pageDecodeTags() {
    const html = fs.readFileSync(path.join(__dirname, '..', 'wizard', 'index.html'), 'utf8');
    const start = html.indexOf('function decodeTags');
    const end = html.indexOf('function analyse');
    assert.ok(start > 0 && end > start, 'could not locate decodeTags in the page');
    // eslint-disable-next-line no-new-func
    return new Function(`${html.slice(start, end)}; return decodeTags;`)();
  }

  it('extracts a real artifact well enough to decrypt it', () => {
    const decodeTags = pageDecodeTags();
    const note = seal('east gate 0400');
    const artifact = bridge.conceal({
      payload: note.envelope,
      style: 'invisible',
      coverText: 'Hey! Running late 🙂',
    }).artifact;

    const extracted = decodeTags(artifact);
    assert.match(extracted, /PARSELTONGUE SEALED NOTE/, 'page did not recognise the envelope');

    // Newlines do not survive the tag block (printable ASCII only), so this is deliberately NOT
    // a byte-identical assertion. What matters is that the result still decrypts.
    assert.ok(extracted.length < note.envelope.length, 'expected newlines to be dropped');
    assert.equal(sealed.openNote({ note: extracted, code: note.code }).payload, 'east gate 0400');
  });

  it('finds nothing in a message with no payload', () => {
    const decodeTags = pageDecodeTags();
    assert.equal(decodeTags('just an ordinary message 🙂'), '');
  });

  it('ships no external references', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'wizard', 'index.html'), 'utf8');
    // The page must stay openable from the filesystem with the network unplugged.
    for (const pattern of [/<script[^>]+src=/i, /<link[^>]+href=/i, /\bfetch\s*\(/, /XMLHttpRequest/, /@import/]) {
      assert.ok(!pattern.test(html), `page contains an external reference: ${pattern}`);
    }
  });
});
