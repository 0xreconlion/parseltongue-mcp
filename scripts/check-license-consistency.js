#!/usr/bin/env node
'use strict';

/**
 * License consistency guard.
 *
 * Upstream P4RS3LT0NGV3 ships an AGPL-3.0 LICENSE file alongside `"license": "MIT"` in
 * package.json. That single inconsistency is why this repo has to assume the restrictive
 * reading, and it is the exact mistake not to repeat. Every package here must agree with
 * itself: the LICENSE file on disk and the manifest declaration must name the same license.
 *
 * Fails loudly if it found no packages to check — a guard covering zero items is not a pass.
 */

const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..');

// Package dir (relative to repo root) -> license it must declare, in both places.
const EXPECTED = {
  '.': 'AGPL-3.0-only',
  'packages/capsule-core': 'Apache-2.0',
  'packages/parseltongue-bridge': 'AGPL-3.0-only',
  'servers/transforms': 'AGPL-3.0-only',
  'servers/capsules': 'AGPL-3.0-only',
  cli: 'AGPL-3.0-only',
};

// How to recognise each license from the first lines of its text.
const TEXT_SIGNATURE = {
  'AGPL-3.0-only': /GNU AFFERO GENERAL PUBLIC LICENSE/,
  'Apache-2.0': /Apache License/,
};

function main() {
  const problems = [];
  let checked = 0;

  for (const [dir, expected] of Object.entries(EXPECTED)) {
    const pkgDir = path.join(REPO_ROOT, dir);
    const manifestPath = path.join(pkgDir, 'package.json');
    const licensePath = path.join(pkgDir, 'LICENSE');
    const label = dir === '.' ? '<root>' : dir;

    if (!fs.existsSync(manifestPath)) {
      problems.push(`${label}: no package.json`);
      continue;
    }
    checked += 1;

    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (manifest.license !== expected) {
      problems.push(
        `${label}: package.json says "${manifest.license}", expected "${expected}"`
      );
    }

    // cli/ and servers/capsules are Phase B stubs under the root AGPL; they need no own file.
    const needsOwnFile = !['cli', 'servers/capsules'].includes(dir);
    if (!fs.existsSync(licensePath)) {
      if (needsOwnFile) {
        problems.push(`${label}: no LICENSE file (expected ${expected} text)`);
      }
      continue;
    }

    const head = fs.readFileSync(licensePath, 'utf8').slice(0, 400);
    const signature = TEXT_SIGNATURE[expected];
    if (signature && !signature.test(head)) {
      problems.push(
        `${label}: LICENSE text does not look like ${expected} — ` +
          'this is upstream\'s exact bug (file and manifest disagreeing). Fix the file.'
      );
    }
  }

  if (problems.length > 0) {
    console.error('license consistency: FAIL\n');
    for (const p of problems) console.error(`  - ${p}`);
    console.error(
      '\nA LICENSE file that contradicts its manifest is what forced the restrictive\n' +
        'assumption about upstream. Do not ship that ambiguity downstream.\n'
    );
    process.exit(1);
  }

  if (checked === 0) {
    console.error(
      'license consistency: FAIL - checked 0 packages. Nothing was verified, so this is\n' +
        'not a pass. The EXPECTED map is probably out of sync with the repo layout.'
    );
    process.exit(1);
  }

  console.log(
    `license consistency: PASS - ${checked} package(s), LICENSE text and manifest agree in each.`
  );
}

main();
