'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { upstreamRoot } = require('./helpers/upstream-root');

// Must be set before the bridge is required - it resolves the checkout at load time.
process.env.PARSELTONGUE_ROOT = upstreamRoot();

const bridge = require('../packages/parseltongue-bridge/src');

describe('catalog', () => {
  it('loads a non-empty catalog', () => {
    const summary = bridge.catalogSummary();
    // Guard against a silently-empty catalog looking like "no results".
    assert.ok(summary.total > 100, `expected >100 transforms, got ${summary.total}`);
    assert.ok(Object.keys(summary.byCategory).length > 5);
  });

  it('records which upstream commit fidelity was measured against', () => {
    const summary = bridge.catalogSummary();
    assert.ok(summary.upstreamCommit, 'fidelity data must name its upstream commit');
    assert.equal(
      summary.fidelityStale,
      false,
      'fidelity data is stale for the loaded checkout — re-run scripts/probe-fidelity.js'
    );
  });

  it('gives every transform a measured fidelity tier', () => {
    const unmeasured = bridge.listTransforms().filter((t) => t.fidelity === 'unmeasured');
    assert.equal(
      unmeasured.length,
      0,
      `${unmeasured.length} transform(s) have no measured fidelity: ${unmeasured
        .slice(0, 5)
        .map((t) => t.key)
        .join(', ')}`
    );
  });

  it('never leaks the implementation or search tokens through the public surface', () => {
    for (const entry of bridge.listTransforms()) {
      assert.equal(entry._impl, undefined, `${entry.key} leaked _impl`);
      assert.equal(entry._tokens, undefined, `${entry.key} leaked _tokens`);
    }
  });
});

describe('fuzzy lookup', () => {
  it('resolves an exact key', () => {
    assert.equal(bridge.findTransform('base64').key, 'base64');
  });

  it('resolves a spaced variant to the right transform', () => {
    assert.equal(bridge.findTransform('base 64').key, 'base64');
  });

  it('resolves a dashed variant', () => {
    assert.equal(bridge.findTransform('rot-13').key, 'rot13');
  });

  it('returns nothing for an empty query rather than a random transform', () => {
    assert.deepEqual(bridge.findTransforms(''), []);
    assert.equal(bridge.findTransform(''), null);
  });
});

describe('runTransform', () => {
  it('encodes and reports fidelity alongside the output', () => {
    const result = bridge.runTransform('base64', { action: 'encode', text: 'Attack at dawn' });
    assert.equal(result.output, 'QXR0YWNrIGF0IGRhd24=');
    // A decode result must never arrive without a trust signal next to it.
    assert.ok(result.fidelity, 'result must carry a fidelity tier');
    assert.ok(result.fidelityNote, 'result must carry a fidelity note');
  });

  it('round-trips an exact-tier transform', () => {
    const text = 'Attack at dawn 123';
    const encoded = bridge.runTransform('base64', { action: 'encode', text }).output;
    const decoded = bridge.runTransform('base64', { action: 'decode', text: encoded }).output;
    assert.equal(decoded, text);
  });

  it('rejects an unknown transform by name', () => {
    assert.throws(
      () => bridge.runTransform('definitely_not_a_transform', { text: 'x' }),
      /Unknown transform/
    );
  });

  it('refuses to decode an encode-only transform instead of crashing', () => {
    const encodeOnly = bridge.listTransforms({ canDecode: false })[0];
    assert.ok(encodeOnly, 'expected at least one encode-only transform');
    assert.throws(
      () => bridge.runTransform(encodeOnly.key, { action: 'decode', text: 'x' }),
      /encode-only/
    );
  });

  it('rejects an unsupported action', () => {
    assert.throws(
      () => bridge.runTransform('base64', { action: 'obliterate', text: 'x' }),
      /Unsupported action/
    );
  });

  it('warns when a transform returns empty for non-empty input', () => {
    // Upstream `morse` does this. The warning is what stops it reading as "your text was empty".
    const result = bridge.runTransform('morse', { action: 'encode', text: 'ATTACKATDAWN' });
    if (result.output === '') {
      assert.match(result.warning || '', /empty string for non-empty input/);
    }
  });
});

describe('every transform in the catalog is callable', () => {
  it('encodes without throwing, or is a known upstream defect', () => {
    const known = new Set(['randomizer']); // depends on a browser global absent under Node
    const broken = [];

    for (const entry of bridge.listTransforms()) {
      try {
        bridge.runTransform(entry.key, { action: 'encode', text: 'Hello World 123' });
      } catch (err) {
        if (!known.has(entry.key)) broken.push(`${entry.key}: ${err.message}`);
      }
    }

    assert.deepEqual(broken, [], `transforms threw on encode:\n  ${broken.join('\n  ')}`);
  });

  it('round-trips every exact-tier transform', () => {
    const text = 'Hello World 123';
    const failures = [];

    for (const entry of bridge.listTransforms({ fidelity: 'exact' })) {
      try {
        const encoded = bridge.runTransform(entry.key, { action: 'encode', text }).output;
        const decoded = bridge.runTransform(entry.key, { action: 'decode', text: encoded }).output;
        if (decoded !== text) failures.push(`${entry.key}: got ${JSON.stringify(String(decoded).slice(0, 40))}`);
      } catch (err) {
        failures.push(`${entry.key}: threw ${err.message}`);
      }
    }

    // This is the point of the 'exact' tier: if it does not hold, the metadata is lying.
    assert.deepEqual(failures, [], `exact-tier transforms failed to round-trip:\n  ${failures.join('\n  ')}`);
  });
});

describe('autoDecode', () => {
  it('identifies base64 and states its limitations', () => {
    const { result, limitations } = bridge.autoDecode('QXR0YWNrIGF0IGRhd24=');
    assert.equal(result.text, 'Attack at dawn');
    // The steganography blind spot must always be declared, never left implicit.
    assert.ok(limitations.some((l) => /steganograph/i.test(l)));
  });
});

describe('inspectText', () => {
  it('finds nothing in clean ASCII', () => {
    const report = bridge.inspectText('Hello World');
    assert.equal(report.verdict, 'nothing anomalous found');
    assert.equal(report.counts.hidden, 0);
  });

  it('detects zero-width characters', () => {
    const report = bridge.inspectText('Pay​​ment');
    assert.equal(report.verdict, 'hidden characters present');
    assert.equal(report.counts.hidden, 2);
    assert.ok(report.findings.some((f) => f.kind === 'hidden-characters' && f.severity === 'high'));
  });

  it('detects Unicode tag characters', () => {
    const report = bridge.inspectText('ok\u{e0041}\u{e0042}');
    assert.ok(report.hidden.some((h) => h.name === 'unicode-tag'));
  });

  it('detects variation selectors', () => {
    const report = bridge.inspectText('a️\u{e0100}');
    const names = report.hidden.map((h) => h.name);
    assert.ok(names.includes('variation-selector'));
    assert.ok(names.includes('variation-selector-supplement'));
  });

  it('detects a Cyrillic homoglyph and the script mix', () => {
    const report = bridge.inspectText('аccount');
    assert.ok(report.confusables.some((c) => c.looksLike === 'a'));
    assert.ok(report.findings.some((f) => f.kind === 'mixed-scripts'));
  });

  it('detects bidi overrides', () => {
    const report = bridge.inspectText('file‮gnp.exe');
    assert.ok(report.hidden.some((h) => h.name === 'bidi-control'));
  });

  it('handles empty and null input without throwing', () => {
    assert.equal(bridge.inspectText('').counts.characters, 0);
    assert.equal(bridge.inspectText(null).counts.characters, 0);
    assert.equal(bridge.inspectText(undefined).counts.characters, 0);
  });

  it('never returns a decoded hidden payload', () => {
    const report = bridge.inspectText('ok\u{e0041}\u{e0042}\u{e0043}');
    const serialised = JSON.stringify(report);
    // Codepoints may be named; the reconstructed "ABC" string must not appear.
    assert.ok(
      !serialised.includes('"ABC"'),
      'inspectText must report structure, not decode the hidden payload'
    );
  });
});
