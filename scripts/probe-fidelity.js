#!/usr/bin/env node
'use strict';

/**
 * Round-trip fidelity probe.
 *
 * `canDecode` in the upstream catalog only means "a reverse() function exists". It does not mean
 * decode recovers the input. Measured against upstream at the pinned audit commit, of 185
 * reversible transforms only about half return the original text byte-for-byte; many classical
 * ciphers are alphabet-only by design and legitimately drop case, spacing, and digits; and a
 * handful simply do not recover the input at all.
 *
 * An agent told only "canDecode: true" will confidently hand back corrupted text. So the bridge
 * reports a measured fidelity tier per transform instead, and this script produces it.
 *
 * Tiers:
 *   exact       - every sample round-trips byte for byte
 *   lossy       - every sample recovers under normalisation (drops case / spacing / digits);
 *                 normal for classical ciphers and case transforms
 *   constrained - round-trips for some input classes and corrupts others. The useful case is a
 *                 classical cipher that handles A-Z correctly but mangles digits and
 *                 punctuation. `safeFor` names the input classes that do work.
 *   unreliable  - recovers no sample. Treat as encode-only.
 *   encode_only - no reverse() at all
 *   error       - throws on encode or decode
 *
 * Collapsing `constrained` into `unreliable` was the first thing this probe got wrong:
 * columnar_transposition round-trips ATTACKATDAWN perfectly and only corrupts input containing
 * digits. Calling that "unreliable" would have been as misleading as calling it "exact".
 *
 * This is a measurement of UPSTREAM behavior, not a judgement of it, and it is only valid for
 * the commit it was run against — which is why the output records that commit. Re-run after any
 * upstream pull.
 *
 *   node scripts/probe-fidelity.js            # writes the data file
 *   node scripts/probe-fidelity.js --report   # prints a summary, writes nothing
 */

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { loadTransforms, resolveParseltongueRoot } = require('../packages/parseltongue-bridge/src/loader');

const OUT_PATH = path.resolve(__dirname, '..', 'packages', 'parseltongue-bridge', 'data', 'fidelity.json');

// Several samples, because a single sample misclassifies. "Hello World 123" alone cannot tell an
// alphabet-only cipher (correctly drops digits) from a broken one (mangles letters). Each sample
// is labelled with the input class it represents, so a partial pass can say *what* it is safe for.
const SAMPLES = [
  { id: 'uppercase-letters', text: 'ATTACKATDAWN' },
  { id: 'lowercase-words', text: 'the quick brown fox' },
  { id: 'mixed-with-digits', text: 'Hello World 123' },
  { id: 'punctuation', text: "It's 40% done -- really?" },
];

const normalise = {
  // Case and separators are the most common intentional loss.
  caseless: (s) => String(s).toUpperCase().replace(/[\s_\-]+/g, ''),
  // Classical ciphers are usually A-Z only and legitimately drop digits entirely.
  lettersOnly: (s) => String(s).toUpperCase().replace(/[^A-Z]/g, ''),
};

function classify(transform) {
  if (typeof transform.func !== 'function') {
    return { tier: 'error', note: 'no encode function' };
  }
  if (typeof transform.reverse !== 'function') {
    return { tier: 'encode_only', note: 'no reverse function' };
  }

  const perSample = {};
  const errors = [];
  let emptyEncodes = 0;

  for (const sample of SAMPLES) {
    let encoded;
    try {
      encoded = transform.func(sample.text, {});
    } catch (err) {
      perSample[sample.id] = 'error';
      errors.push(`${sample.id}: encode threw: ${err.message}`);
      continue;
    }

    // An encoder that returns empty for non-empty input is broken, not lossy. Upstream `morse`
    // does exactly this, and it is invisible to a null/undefined check.
    if (encoded === '' && sample.text !== '') {
      perSample[sample.id] = 'empty';
      emptyEncodes += 1;
      continue;
    }

    let decoded;
    try {
      decoded = transform.reverse(encoded, {});
    } catch (err) {
      perSample[sample.id] = 'error';
      errors.push(`${sample.id}: decode threw: ${err.message}`);
      continue;
    }

    if (decoded === sample.text) {
      perSample[sample.id] = 'exact';
    } else if (normalise.caseless(decoded) === normalise.caseless(sample.text)) {
      perSample[sample.id] = 'caseless';
    } else if (
      normalise.lettersOnly(sample.text).length > 0 &&
      normalise.lettersOnly(decoded) === normalise.lettersOnly(sample.text)
    ) {
      perSample[sample.id] = 'letters';
    } else {
      perSample[sample.id] = 'corrupt';
    }
  }

  const verdicts = Object.values(perSample);
  const recovered = new Set(['exact', 'caseless', 'letters']);
  const safeFor = SAMPLES.filter((s) => recovered.has(perSample[s.id])).map((s) => s.id);
  const result = { perSample };
  if (errors.length) result.errors = errors;

  if (emptyEncodes === SAMPLES.length) {
    return {
      tier: 'error',
      note: 'encode returns an empty string for every sample; the transform is broken upstream',
      ...result,
    };
  }
  if (verdicts.every((v) => v === 'exact')) {
    return { tier: 'exact', note: 'round-trips byte for byte on every sample', ...result };
  }
  if (verdicts.every((v) => recovered.has(v))) {
    const dropsLetters = verdicts.includes('letters');
    return {
      tier: 'lossy',
      note: dropsLetters
        ? 'recovers letters only; drops case, spacing, digits and punctuation'
        : 'recovers text but drops case and/or separators',
      ...result,
    };
  }
  if (safeFor.length > 0) {
    return {
      tier: 'constrained',
      note:
        `round-trips ${safeFor.join(' and ')} input, but corrupts the rest. ` +
        'Decode only input of a shape it handles.',
      safeFor,
      ...result,
    };
  }
  // Distinguish "decode is wrong" from "encode produced nothing to decode" — upstream `morse`
  // returns an empty string for most input, which is an encode bug wearing a decode bug's mask.
  let note;
  if (emptyEncodes > 0) {
    note =
      `encode returns an empty string for ${emptyEncodes} of ${SAMPLES.length} samples, ` +
      'and decode recovers none; broken upstream, do not rely on it';
  } else if (errors.length) {
    note = `decode never recovers the input (${errors[0]})`;
  } else {
    note = 'decode never recovers the input; treat as encode-only';
  }
  return { tier: 'unreliable', note, ...result };
}

function upstreamCommit(root) {
  try {
    return execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return null;
  }
}

function main() {
  const reportOnly = process.argv.includes('--report');
  const root = resolveParseltongueRoot();
  const transforms = loadTransforms(root);
  const keys = Object.keys(transforms).sort();

  if (keys.length === 0) {
    console.error('fidelity probe: FAIL - loaded 0 transforms. Nothing was measured.');
    process.exit(1);
  }

  const results = {};
  const tally = {};
  for (const key of keys) {
    const verdict = classify(transforms[key]);
    results[key] = verdict;
    tally[verdict.tier] = (tally[verdict.tier] || 0) + 1;
  }

  const payload = {
    _comment:
      'Generated by scripts/probe-fidelity.js. Measures UPSTREAM round-trip behavior, valid only ' +
      'for the commit below. Re-run after any upstream pull. Do not hand-edit.',
    generatedAt: new Date().toISOString(),
    upstreamCommit: upstreamCommit(root),
    samples: SAMPLES.map((s) => s.text),
    totals: { transforms: keys.length, ...tally },
    transforms: results,
  };

  console.log(`fidelity probe: ${keys.length} transforms against commit ${payload.upstreamCommit || '(unknown)'}`);
  for (const [tier, count] of Object.entries(tally).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${tier.padEnd(12)} ${count}`);
  }

  for (const tier of ['unreliable', 'error']) {
    const hits = keys.filter((k) => results[k].tier === tier);
    if (hits.length) console.log(`\n  ${tier}: ${hits.join(', ')}`);
  }
  const constrained = keys.filter((k) => results[k].tier === 'constrained');
  if (constrained.length) {
    console.log(`\n  constrained (safe for some input shapes only): ${constrained.length}`);
    for (const k of constrained.slice(0, 8)) {
      console.log(`    ${k.padEnd(26)} safe for: ${results[k].safeFor.join(', ')}`);
    }
    if (constrained.length > 8) console.log(`    ... and ${constrained.length - 8} more`);
  }

  if (reportOnly) {
    console.log('\n--report given; no file written.');
    return;
  }

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, `${JSON.stringify(payload, null, 2)}\n`);
  console.log(`\nwrote ${path.relative(path.resolve(__dirname, '..'), OUT_PATH)}`);
}

main();
