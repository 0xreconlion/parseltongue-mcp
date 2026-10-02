'use strict';

/**
 * Locate the upstream P4RS3LT0NGV3 checkout for tests.
 *
 * The transform catalog is not vendored, so these tests need a real checkout. Until this repo was
 * prepared for publication the bridge carried an absolute fallback inside one developer's home
 * directory, and the test suite was silently depending on it — removing that path broke 21 tests
 * at once, which is exactly the kind of hidden coupling a publication pass should surface.
 *
 * Resolution order: PARSELTONGUE_ROOT, then conventional locations relative to this repo. If none
 * matches, the error says what to set rather than failing deep inside a loader.
 */

const fs = require('node:fs');
const path = require('node:path');

const REPO = path.resolve(__dirname, '..', '..');
const MARKER = path.join('src', 'transformers', 'loader-node.js');

const CANDIDATES = [
  path.join(REPO, 'vendor', 'P4RS3LT0NGV3'),
  path.resolve(REPO, '..', 'P4RS3LT0NGV3'),
  path.resolve(REPO, '..', 'p4rs3lt0ngv3'),
];

function looksRight(root) {
  return Boolean(root) && fs.existsSync(path.join(root, MARKER));
}

/** Resolve the checkout, or throw with instructions. */
function upstreamRoot() {
  if (looksRight(process.env.PARSELTONGUE_ROOT)) return path.resolve(process.env.PARSELTONGUE_ROOT);

  for (const candidate of CANDIDATES) {
    if (looksRight(candidate)) return candidate;
  }

  throw new Error(
    'These tests need a P4RS3LT0NGV3 checkout and could not find one.\n' +
      '  export PARSELTONGUE_ROOT=/path/to/P4RS3LT0NGV3\n' +
      `  (or clone it to ${path.join(REPO, 'vendor', 'P4RS3LT0NGV3')})\n` +
      `Looked in: ${CANDIDATES.join(', ')}`
  );
}

/**
 * Environment for a spawned server process.
 *
 * Passed explicitly rather than inherited so a test cannot pass by accident on a machine where the
 * variable happens to be exported globally.
 */
function serverEnv(extra = {}) {
  return { ...process.env, PARSELTONGUE_ROOT: upstreamRoot(), ...extra };
}

module.exports = { serverEnv, upstreamRoot };
