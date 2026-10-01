'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const core = require('../packages/capsule-core/src');

const VAULT_PASS = 'vault-passphrase-for-tests';
const BACKUP_PASS = 'backup-passphrase-for-tests-longer';
const SAMPLE = 'Rendezvous at 0400. Bring the drive.';

/**
 * Argon2id at production settings costs ~2s per vault operation and ~5s per backup, which put
 * this suite at 78 seconds - slow enough that it stops being run, which is worse than any
 * coverage it buys. Most tests therefore use the lightest parameters the implementation will
 * still accept, since what they exercise is format and tamper behavior, not KDF cost.
 *
 * `exercises the production KDF defaults` below runs at the real settings, so the defaults are
 * never only asserted in a comment. Any test about KDF strength itself must use real values.
 */
const TEST_KDF = { alg: 'argon2id', m: 8192, t: 1, p: 1 };
const TEST_BACKUP_KDF = { alg: 'argon2id', m: 8192, t: 1, p: 1 };

function fastVault(identity, passphrase = VAULT_PASS) {
  return core.createVault({ identity, passphrase, kdf: TEST_KDF });
}

function pair() {
  const alice = core.createIdentity({ label: 'Alice' });
  const bob = core.createIdentity({ label: 'Bob' });
  const bobContact = core.importContactCard(core.exportContactCard(bob.public).card).contact;
  return { alice, bob, bobContact };
}

function seal({ alice, bobContact }, payload = SAMPLE, meta = { subject: 'logistics' }) {
  return core.sealCapsule({
    senderSecret: alice.secret,
    senderPublic: alice.public,
    recipientContact: bobContact,
    payload,
    meta,
  });
}

describe('identity and contact cards', () => {
  it('generates distinct signing and encryption keys', () => {
    const id = core.createIdentity({ label: 'x' });
    assert.notEqual(id.public.sign, id.public.encrypt);
    assert.notEqual(id.secret.sign, id.secret.encrypt);
    assert.notEqual(id.public.signFingerprint, id.public.encryptFingerprint);
  });

  it('round-trips a contact card with a matching checksum', () => {
    const id = core.createIdentity({ label: 'Carol' });
    const { card } = core.exportContactCard(id.public);
    const result = core.importContactCard(card);
    assert.equal(result.checksumOk, true);
    assert.deepEqual(result.warnings, []);
    assert.equal(result.contact.id, id.public.id);
    assert.equal(result.contact.signFingerprint, id.public.signFingerprint);
  });

  it('flags an altered card without claiming the checksum proves authorship', () => {
    const id = core.createIdentity({ label: 'Carol' });
    const { card } = core.exportContactCard(id.public);
    const tampered = card.replace('label:    Carol', 'label:    Mallory');
    const result = core.importContactCard(tampered);
    assert.equal(result.checksumOk, false);
    assert.match(result.warnings.join(' '), /not a signature/);
  });

  it('refuses a card carrying a private-looking field', () => {
    const id = core.createIdentity({});
    const { card } = core.exportContactCard(id.public);
    const poisoned = card.replace('checksum:', `private:  ${id.secret.sign}\nchecksum:`);
    assert.throws(() => core.importContactCard(poisoned), /carry public keys only/);
  });

  it('refuses to export a card from the full identity object', () => {
    const id = core.createIdentity({});
    // Passing the whole identity rather than identity.public is the obvious mistake, and it
    // would put the private key in a file meant for sharing.
    assert.throws(() => core.exportContactCard(id), /carries a "secret" field/);
  });

  it('rejects a card whose keys are the wrong length', () => {
    const bad = [
      '----- PARSELTONGUE CONTACT CARD v1 -----',
      'sign:     AAAA',
      'encrypt:  BBBB',
      '----- END PARSELTONGUE CONTACT CARD -----',
    ].join('\n');
    assert.throws(() => core.importContactCard(bad), /32-byte/);
  });
});

describe('vault', () => {
  it('round-trips and re-derives the public identity from the secret keys', () => {
    const id = core.createIdentity({ label: 'Zach' });
    const record = fastVault(id);
    const unlocked = core.unlockVault(record, VAULT_PASS);
    assert.equal(unlocked.public.id, id.public.id);
    assert.equal(unlocked.secret.sign, id.secret.sign);
  });

  it('rejects the wrong passphrase without distinguishing it from tampering', () => {
    const record = fastVault(core.createIdentity({}));
    assert.throws(() => core.unlockVault(record, 'a-different-passphrase'), (err) => {
      // One message for both causes: telling an attacker which they achieved is a gift.
      assert.match(err.message, /wrong passphrase, or the vault file has been altered/);
      return true;
    });
  });

  it('rejects a short passphrase', () => {
    assert.throws(
      () => core.createVault({ identity: core.createIdentity({}), passphrase: 'short' }),
      /at least 10 characters/
    );
  });

  it('refuses an implausibly weak stored KDF parameter', () => {
    const record = core.createVault({ identity: core.createIdentity({}), passphrase: VAULT_PASS });
    const downgraded = JSON.parse(JSON.stringify(record));
    downgraded.kdf.m = 8;
    assert.throws(() => core.unlockVault(downgraded, VAULT_PASS), /too weak to trust/);
  });

  it('defeats a plausible-but-weaker KDF downgrade via the AAD binding', () => {
    // The explicit floor above catches absurd values. This one is above the floor, so only the
    // fact that KDF params are bound as associated data stops it.
    const record = core.createVault({ identity: core.createIdentity({}), passphrase: VAULT_PASS });
    const downgraded = JSON.parse(JSON.stringify(record));
    downgraded.kdf.m = 16384;
    assert.throws(() => core.unlockVault(downgraded, VAULT_PASS), /could not unlock/);
  });

  it('detects a swapped cleartext identity header', () => {
    const record = core.createVault({ identity: core.createIdentity({}), passphrase: VAULT_PASS });
    const tampered = JSON.parse(JSON.stringify(record));
    tampered.identity.sign = core.createIdentity({}).public.sign;
    assert.throws(() => core.unlockVault(tampered, VAULT_PASS), /could not unlock|has been altered/);
  });

  it('keeps no private material in the cleartext part of the record', () => {
    const id = core.createIdentity({ label: 'Zach' });
    const record = fastVault(id);
    const cleartext = JSON.stringify({ ...record, ct: '<redacted>' });
    assert.ok(!cleartext.includes(id.secret.sign), 'signing private key leaked into vault cleartext');
    assert.ok(!cleartext.includes(id.secret.encrypt), 'encryption private key leaked into vault cleartext');
    assert.ok(!cleartext.includes(VAULT_PASS), 'passphrase leaked into vault cleartext');
  });

  it('exercises the production KDF defaults, not just the fast test ones', () => {
    // Every other vault test above runs at TEST_KDF for speed. This one runs at whatever the
    // shipped defaults actually are, so a future change that broke or weakened them cannot hide
    // behind a suite that never uses them. Deliberately slow (~4s); that is the point.
    const id = core.createIdentity({ label: 'production-defaults' });
    const record = core.createVault({ identity: id, passphrase: VAULT_PASS });

    assert.equal(record.kdf.alg, 'argon2id');
    assert.ok(
      record.kdf.m >= 19456 && record.kdf.t >= 2,
      `shipped vault KDF is weaker than OWASP's floor (m=${record.kdf.m} t=${record.kdf.t})`
    );
    assert.equal(core.unlockVault(record, VAULT_PASS).public.id, id.public.id);

    const backup = core.exportIdentityBackup({
      secret: id.secret, publicIdentity: id.public, passphrase: BACKUP_PASS,
    });
    assert.ok(
      backup.record.kdf.m >= record.kdf.m && backup.record.kdf.t >= record.kdf.t,
      'backup KDF must be at least as hard as the vault KDF - it is a longer-lived artifact'
    );
  });

  it('changes passphrase without changing identity', () => {
    const id = core.createIdentity({ label: 'Zach' });
    const record = fastVault(id);
    const updated = core.changeVaultPassphrase(record, VAULT_PASS, 'a-brand-new-passphrase', TEST_KDF);
    assert.throws(() => core.unlockVault(updated, VAULT_PASS));
    assert.equal(core.unlockVault(updated, 'a-brand-new-passphrase').public.id, id.public.id);
  });
});

describe('capsule seal and open', () => {
  it('round-trips a message', () => {
    const parties = pair();
    const sealed = seal(parties);
    const opened = core.openCapsule({ capsule: sealed.envelope, recipientSecret: parties.bob.secret });
    assert.equal(opened.payload, SAMPLE);
    assert.equal(opened.sender.verified, true);
  });

  it('confirms a sender against an expected contact', () => {
    const parties = pair();
    const sealed = seal(parties);
    const opened = core.openCapsule({
      capsule: sealed.capsule,
      recipientSecret: parties.bob.secret,
      expectedSenderContact: parties.alice.public,
    });
    assert.equal(opened.sender.matchesExpected, true);
  });

  it('warns when the sender is not the expected contact', () => {
    const parties = pair();
    const impostor = core.createIdentity({ label: 'Mallory' });
    const sealed = core.sealCapsule({
      senderSecret: impostor.secret,
      senderPublic: impostor.public,
      recipientContact: parties.bobContact,
      payload: 'trust me',
    });
    const opened = core.openCapsule({
      capsule: sealed.capsule,
      recipientSecret: parties.bob.secret,
      expectedSenderContact: parties.alice.public,
    });
    assert.equal(opened.sender.matchesExpected, false);
    assert.match(opened.sender.note, /does NOT match/);
  });

  it('never states that a signature proves identity', () => {
    const parties = pair();
    const opened = core.openCapsule({
      capsule: seal(parties).capsule,
      recipientSecret: parties.bob.secret,
    });
    assert.match(opened.sender.note, /does not prove who that person is/);
  });

  it('produces different ciphertext for identical content', () => {
    const parties = pair();
    const a = seal(parties, 'same text', {});
    const b = seal(parties, 'same text', {});
    assert.notEqual(a.capsule.ct, b.capsule.ct, 'ephemeral keys should make each capsule unique');
    assert.notEqual(a.capsule.epk, b.capsule.epk);
  });

  it('rejects an empty payload and an oversized one', () => {
    const parties = pair();
    assert.throws(() => seal(parties, ''), /empty payload/);
    assert.throws(() => seal(parties, 'x'.repeat(core.MAX_PAYLOAD_BYTES + 1)), /the limit is/);
  });

  it('refuses metadata that looks like a secret, because metadata is visible', () => {
    const parties = pair();
    for (const key of ['api_key', 'password', 'secret_note', 'private_thing', 'auth_token']) {
      assert.throws(() => seal(parties, 'x', { [key]: 'v' }), /VISIBLE/, `${key} should be refused`);
    }
  });

  it('round-trips unicode and multi-line payloads intact', () => {
    const parties = pair();
    const payload = 'line one\nline two\t🦁 ünïcödé — "quoted" \\ backslash\n';
    const opened = core.openCapsule({
      capsule: seal(parties, payload, {}).envelope,
      recipientSecret: parties.bob.secret,
    });
    assert.equal(opened.payload, payload);
  });
});

describe('capsule tamper resistance', () => {
  it('rejects a flipped ciphertext byte', () => {
    const parties = pair();
    const capsule = JSON.parse(JSON.stringify(seal(parties).capsule));
    const bytes = Buffer.from(capsule.ct.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    bytes[4] ^= 0xff;
    capsule.ct = bytes.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    assert.throws(() => core.openCapsule({ capsule, recipientSecret: parties.bob.secret }), /signature|decryption/);
  });

  it('rejects edited VISIBLE metadata', () => {
    // The whole point of binding the header into the AEAD and the signature.
    const parties = pair();
    const capsule = JSON.parse(JSON.stringify(seal(parties).capsule));
    capsule.meta.subject = 'tampered';
    assert.throws(() => core.openCapsule({ capsule, recipientSecret: parties.bob.secret }), /signature|decryption/);
  });

  it('rejects an edited timestamp', () => {
    const parties = pair();
    const capsule = JSON.parse(JSON.stringify(seal(parties).capsule));
    capsule.created = '2020-01-01T00:00:00.000Z';
    assert.throws(() => core.openCapsule({ capsule, recipientSecret: parties.bob.secret }), /signature|decryption/);
  });

  it('rejects a swapped ephemeral key', () => {
    const parties = pair();
    const capsule = JSON.parse(JSON.stringify(seal(parties).capsule));
    capsule.epk = core.createIdentity({}).public.encrypt;
    assert.throws(() => core.openCapsule({ capsule, recipientSecret: parties.bob.secret }), /signature|decryption/);
  });

  it('refuses to open a capsule addressed to someone else', () => {
    const parties = pair();
    const eve = core.createIdentity({ label: 'Eve' });
    assert.throws(
      () => core.openCapsule({ capsule: seal(parties).capsule, recipientSecret: eve.secret }),
      /was not sealed to you/
    );
  });

  it('defeats a re-signed forgery through the AEAD layer alone', () => {
    // An attacker who edits the visible header and re-signs with their OWN key produces a capsule
    // whose signature verifies. Only the associated-data and HKDF-info binding catch it. Without
    // this test the second layer is asserted rather than demonstrated, because every other tamper
    // case above is stopped by the signature first.
    const { ed25519 } = require('@noble/curves/ed25519.js');
    const { canonicalBytes, b64u, toBytes, unb64u } = require('../packages/capsule-core/src/codec');

    const parties = pair();
    const eve = core.createIdentity({ label: 'Eve' });
    const capsule = JSON.parse(JSON.stringify(seal(parties).capsule));

    capsule.meta.subject = 'FORGED';
    capsule.sender.sign = eve.public.sign;
    capsule.sender.signFingerprint = eve.public.signFingerprint;

    const header = {
      v: capsule.v, created: capsule.created, sender: capsule.sender,
      recipient: capsule.recipient, epk: capsule.epk, meta: capsule.meta, nonce: capsule.nonce,
    };
    const message = toBytes(`${Buffer.from(canonicalBytes(header)).toString('utf8')}.${capsule.ct}`);
    capsule.sig = b64u(ed25519.sign(message, unb64u(eve.secret.sign)));

    // The forgery's signature must genuinely verify, or this test proves nothing.
    assert.equal(
      core.inspectCapsule(capsule).signatureVerifies,
      true,
      'forged capsule signature must verify for this test to be meaningful'
    );
    assert.throws(
      () => core.openCapsule({ capsule, recipientSecret: parties.bob.secret }),
      /decryption failed even though the signature verified/
    );
  });

  it('rejects malformed, truncated and wrong-version capsules', () => {
    const parties = pair();
    const sealed = seal(parties);
    assert.throws(() => core.openCapsule({ capsule: sealed.envelope.slice(0, 100), recipientSecret: parties.bob.secret }), /truncated|not a Parseltongue/);
    assert.throws(() => core.openCapsule({ capsule: '{}', recipientSecret: parties.bob.secret }), /unsupported capsule version/);
    const future = JSON.parse(JSON.stringify(sealed.capsule));
    future.v = 99;
    assert.throws(() => core.openCapsule({ capsule: future, recipientSecret: parties.bob.secret }), /unsupported capsule version/);
  });
});

describe('inspect without keys', () => {
  it('verifies a good capsule and reports what leaks', () => {
    const report = core.inspectCapsule(seal(pair()).envelope);
    assert.equal(report.wellFormed, true);
    assert.equal(report.signatureVerifies, true);
    assert.ok(report.visible.senderFingerprint);
    assert.ok(report.encrypted.approximatePlaintextBytes > 0);
    // The honesty requirements, asserted rather than trusted to code review.
    const notes = report.notes.join(' ');
    assert.match(notes, /hides its PAYLOAD only/);
    assert.match(notes, /adds NO confidentiality/);
  });

  it('detects tampering with no private key present', () => {
    const capsule = JSON.parse(JSON.stringify(seal(pair()).capsule));
    capsule.meta.subject = 'changed';
    assert.equal(core.inspectCapsule(capsule).signatureVerifies, false);
  });

  it('flags a capsule id that does not match its ciphertext', () => {
    const capsule = JSON.parse(JSON.stringify(seal(pair()).capsule));
    capsule.id = '0000000000000000';
    const report = core.inspectCapsule(capsule);
    assert.ok(report.findings.some((f) => /does not match its ciphertext/.test(f.detail)));
  });

  it('returns a finding rather than throwing on garbage input', () => {
    const report = core.inspectCapsule('this is not a capsule at all');
    assert.equal(report.wellFormed, false);
    assert.ok(report.findings.length > 0);
  });
});

describe('backup and recovery', () => {
  it('restores an identity and reopens a capsule sealed before the loss', () => {
    const parties = pair();
    const sealed = seal(parties);

    const record = fastVault(parties.bob);
    const unlocked = core.unlockVault(record, VAULT_PASS);
    const backup = core.exportIdentityBackup({
      secret: unlocked.secret,
      publicIdentity: unlocked.public,
      passphrase: BACKUP_PASS,
      kdf: TEST_BACKUP_KDF,
    });

    // Total loss: only the backup text survives.
    const restored = core.importIdentityBackup({ backup: backup.text, passphrase: BACKUP_PASS });
    assert.equal(restored.public.id, parties.bob.public.id);

    const opened = core.openCapsule({ capsule: sealed.envelope, recipientSecret: restored.secret });
    assert.equal(opened.payload, SAMPLE);
  });

  it('carries the contact book inside the encrypted payload', () => {
    // Without this, a restore loses every contact and sender verification silently degrades from
    // "matches your contact" to "unconfirmed" - the check a user is most likely to stop doing.
    const id = core.createIdentity({ label: 'Bob' });
    const contacts = { v: 1, contacts: { alice: { sign: 'x', encrypt: 'y', label: 'Alice' } } };
    const backup = core.exportIdentityBackup({
      secret: id.secret,
      publicIdentity: id.public,
      passphrase: BACKUP_PASS,
      contacts,
      kdf: TEST_BACKUP_KDF,
    });
    assert.ok(!backup.text.includes('Alice'), 'contact book must be inside the ciphertext, not the header');
    const restored = core.importIdentityBackup({ backup: backup.text, passphrase: BACKUP_PASS });
    assert.deepEqual(restored.contacts, contacts);
    // `secret` must stay exactly key material so nothing downstream guesses what is sensitive.
    assert.deepEqual(Object.keys(restored.secret).sort(), ['encrypt', 'sign', 'v']);
  });

  it('requires a longer passphrase than the vault', () => {
    const id = core.createIdentity({});
    assert.throws(
      () => core.exportIdentityBackup({ secret: id.secret, publicIdentity: id.public, passphrase: 'only-fifteen!!' }),
      /at least 16 characters/
    );
  });

  it('rejects a tampered backup header', () => {
    const id = core.createIdentity({});
    const backup = core.exportIdentityBackup({
      secret: id.secret, publicIdentity: id.public, passphrase: BACKUP_PASS, kdf: TEST_BACKUP_KDF,
    });
    const tampered = JSON.parse(JSON.stringify(backup.record));
    tampered.identity.signFingerprint = '0000-0000-0000-0000';
    assert.throws(() => core.importIdentityBackup({ backup: tampered, passphrase: BACKUP_PASS }), /could not decrypt|has been altered/);
  });

  it('keeps no private material in the backup cleartext header', () => {
    const id = core.createIdentity({ label: 'Zach' });
    const backup = core.exportIdentityBackup({
      secret: id.secret, publicIdentity: id.public, passphrase: BACKUP_PASS, kdf: TEST_BACKUP_KDF,
    });
    const header = JSON.stringify({ ...backup.record, ct: '<redacted>' });
    assert.ok(!header.includes(id.secret.sign));
    assert.ok(!header.includes(id.secret.encrypt));
    assert.ok(!header.includes(BACKUP_PASS));
  });
});

describe('no private key material escapes', () => {
  /**
   * The single most important property in this package. Enumerates every value a user might
   * plausibly share - contact card, capsule envelope, inspection report, vault record, backup
   * header, and every error message - and asserts the private keys and passphrases appear in none
   * of them.
   */
  function assertClean(label, haystack, secrets) {
    const text = typeof haystack === 'string' ? haystack : JSON.stringify(haystack);
    for (const [name, secret] of Object.entries(secrets)) {
      assert.ok(!text.includes(secret), `${label} leaked ${name}`);
    }
  }

  it('leaks nothing through anything shareable', () => {
    const alice = core.createIdentity({ label: 'Alice' });
    const bob = core.createIdentity({ label: 'Bob' });
    const bobContact = core.importContactCard(core.exportContactCard(bob.public).card).contact;

    const secrets = {
      'alice signing key': alice.secret.sign,
      'alice encryption key': alice.secret.encrypt,
      'bob signing key': bob.secret.sign,
      'bob encryption key': bob.secret.encrypt,
      'vault passphrase': VAULT_PASS,
      'backup passphrase': BACKUP_PASS,
    };

    const card = core.exportContactCard(alice.public);
    const sealed = core.sealCapsule({
      senderSecret: alice.secret, senderPublic: alice.public,
      recipientContact: bobContact, payload: SAMPLE, meta: { subject: 's' },
    });
    const vaultRecord = fastVault(alice);
    const unlocked = core.unlockVault(vaultRecord, VAULT_PASS);
    const backup = core.exportIdentityBackup({
      secret: unlocked.secret, publicIdentity: unlocked.public, passphrase: BACKUP_PASS, kdf: TEST_BACKUP_KDF,
    });
    const opened = core.openCapsule({ capsule: sealed.capsule, recipientSecret: bob.secret });

    assertClean('contact card', card.card, secrets);
    assertClean('contact card object', card, secrets);
    assertClean('imported contact', bobContact, secrets);
    assertClean('capsule envelope', sealed.envelope, secrets);
    assertClean('capsule object', sealed.capsule, secrets);
    assertClean('seal result', { ...sealed }, secrets);
    assertClean('inspection report', core.inspectCapsule(sealed.envelope), secrets);
    assertClean('opened capsule result', opened, secrets);
    assertClean('public identity', alice.public, secrets);
    assertClean('vault cleartext header', { ...vaultRecord, ct: '<redacted>' }, secrets);
    assertClean('backup cleartext header', { ...backup.record, ct: '<redacted>' }, secrets);
    assertClean('backup warning text', backup.warning, secrets);
  });

  it('leaks nothing through error messages', () => {
    const alice = core.createIdentity({ label: 'Alice' });
    const secrets = { 'signing key': alice.secret.sign, 'vault passphrase': VAULT_PASS };
    const record = fastVault(alice);

    const attempts = [
      () => core.unlockVault(record, 'wrong-passphrase-entirely'),
      () => core.createVault({ identity: alice, passphrase: 'tiny' }),
      () => core.exportContactCard(alice),
      () => core.importContactCard('garbage'),
      () => core.openCapsule({ capsule: '{}', recipientSecret: alice.secret }),
      () => core.exportIdentityBackup({ secret: alice.secret, publicIdentity: alice.public, passphrase: 'short' }),
      () => core.sealCapsule({ senderSecret: alice.secret, senderPublic: alice.public, recipientContact: {}, payload: 'x' }),
    ];

    let thrown = 0;
    for (const attempt of attempts) {
      try {
        attempt();
      } catch (error) {
        thrown += 1;
        assertClean('error message', error.message, secrets);
        assertClean('error stack', error.stack || '', secrets);
      }
    }
    // A loop that caught nothing would pass vacuously.
    assert.equal(thrown, attempts.length, 'every attempt above should have thrown');
  });

  it('the leak detector itself actually works', () => {
    // Positive control. Without this, the assertions above could be passing because the detector
    // is broken rather than because nothing leaks.
    const alice = core.createIdentity({});
    const secrets = { 'signing key': alice.secret.sign };
    assert.throws(
      () => assertClean('planted', `prefix ${alice.secret.sign} suffix`, secrets),
      /leaked signing key/
    );
  });
});

describe('wizard parity', () => {
  /**
   * wizard/wizard.html re-implements canonical JSON, the signed-bytes construction, and the
   * capsule-id derivation so it can verify a signature in a browser with no bundled library. Two
   * implementations of the same format is exactly where divergence bugs live, so the browser logic
   * is re-derived here and checked against the Node one.
   */
  function wizardCanonical(value) {
    const sortDeep = (v) => {
      if (Array.isArray(v)) return v.map(sortDeep);
      if (v === null || typeof v !== 'object') return v;
      const out = {};
      for (const k of Object.keys(v).sort()) if (v[k] !== undefined) out[k] = sortDeep(v[k]);
      return out;
    };
    return JSON.stringify(sortDeep(value));
  }

  function wizardUnb64u(text) {
    return new Uint8Array(Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  }

  it('verifies a real capsule with the browser construction via WebCrypto', async () => {
    const parties = pair();
    const capsule = seal(parties).capsule;

    const header = {
      v: capsule.v, created: capsule.created, sender: capsule.sender,
      recipient: capsule.recipient, epk: capsule.epk, meta: capsule.meta, nonce: capsule.nonce,
    };
    const message = new TextEncoder().encode(`${wizardCanonical(header)}.${capsule.ct}`);
    const key = await crypto.subtle.importKey(
      'raw', wizardUnb64u(capsule.sender.sign), { name: 'Ed25519' }, false, ['verify']
    );
    assert.equal(
      await crypto.subtle.verify({ name: 'Ed25519' }, key, wizardUnb64u(capsule.sig), message),
      true,
      'browser-side verification diverged from the Node implementation'
    );
  });

  it('rejects a tampered capsule with the browser construction', async () => {
    const parties = pair();
    const capsule = JSON.parse(JSON.stringify(seal(parties).capsule));
    capsule.meta.subject = 'tampered';

    const header = {
      v: capsule.v, created: capsule.created, sender: capsule.sender,
      recipient: capsule.recipient, epk: capsule.epk, meta: capsule.meta, nonce: capsule.nonce,
    };
    const message = new TextEncoder().encode(`${wizardCanonical(header)}.${capsule.ct}`);
    const key = await crypto.subtle.importKey(
      'raw', wizardUnb64u(capsule.sender.sign), { name: 'Ed25519' }, false, ['verify']
    );
    assert.equal(
      await crypto.subtle.verify({ name: 'Ed25519' }, key, wizardUnb64u(capsule.sig), message),
      false
    );
  });

  it('derives the same capsule id as the Node implementation', async () => {
    const capsule = seal(pair()).capsule;
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(capsule.ct));
    const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
    assert.equal(hex.slice(0, 16), capsule.id);
  });
});
