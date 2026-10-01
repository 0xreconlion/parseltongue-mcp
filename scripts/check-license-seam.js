#!/usr/bin/env node
'use strict';

/**
 * License seam guard.
 *
 * packages/capsule-core is Apache-2.0 and must stay a standalone work. The moment it imports
 * anything derived from P4RS3LT0NGV3 (AGPL-3.0), it becomes an AGPL derivative and loses the
 * reusability that is the entire point of the split. This check is the only thing standing
 * between "reusable Apache-2.0 core" and "accidentally AGPL".
 *
 * It fails loudly on a violation and fails loudly if it inspected nothing — a guard that
 * examines zero files must never report PASS.
 */

const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..');
const GUARDED_DIR = path.join(REPO_ROOT, 'packages', 'capsule-core');

// Anything matching these in an import/require specifier taints the Apache-2.0 boundary.
const FORBIDDEN_SPECIFIERS = [
  { pattern: /@reconlion\/parseltongue-bridge/, why: 'the AGPL Parseltongue bridge' },
  { pattern: /parseltongue-bridge/, why: 'the AGPL Parseltongue bridge' },
  { pattern: /p4rs3lt0ngv3/i, why: 'upstream P4RS3LT0NGV3 source' },
  { pattern: /loader-node/, why: 'the P4RS3LT0NGV3 transform loader' },
  { pattern: /transformers?\//, why: 'the P4RS3LT0NGV3 transform catalog' },
  { pattern: /cli_bridge/, why: 'the P4RS3LT0NGV3 CLI bridge' },
];

// require('x'), require("x"), import ... from 'x', import('x'), export ... from 'x'
const SPECIFIER_RE =
  /(?:require\s*\(\s*|(?:import|export)[\s\S]{0,200}?from\s*|import\s*\(\s*)['"]([^'"]+)['"]/g;

function walk(dir) {
  const out = [];
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    if (err.code === 'ENOENT') return out;
    throw err;
  }
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walk(full));
    } else if (/\.(js|cjs|mjs|ts|mts|cts)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function main() {
  if (!fs.existsSync(GUARDED_DIR)) {
    console.error(
      `seam guard: FAIL - guarded directory does not exist: ${path.relative(REPO_ROOT, GUARDED_DIR)}\n` +
        'The guard cannot vouch for a tree that is not there. Create it or fix this path.'
    );
    process.exit(1);
  }

  const files = walk(GUARDED_DIR);
  const violations = [];

  for (const file of files) {
    const source = fs.readFileSync(file, 'utf8');
    const lines = source.split('\n');

    SPECIFIER_RE.lastIndex = 0;
    let match;
    while ((match = SPECIFIER_RE.exec(source)) !== null) {
      const specifier = match[1];
      for (const { pattern, why } of FORBIDDEN_SPECIFIERS) {
        if (!pattern.test(specifier)) continue;
        const line = source.slice(0, match.index).split('\n').length;
        violations.push({
          file: path.relative(REPO_ROOT, file),
          line,
          specifier,
          why,
          text: (lines[line - 1] || '').trim(),
        });
        break;
      }
    }
  }

  // Also check the manifest, so a dependency declaration is caught even with no import yet.
  const manifestPath = path.join(GUARDED_DIR, 'package.json');
  if (fs.existsSync(manifestPath)) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (manifest.license !== 'Apache-2.0') {
      violations.push({
        file: path.relative(REPO_ROOT, manifestPath),
        line: 0,
        specifier: manifest.license,
        why: 'capsule-core must declare Apache-2.0',
        text: `"license": "${manifest.license}"`,
      });
    }
    for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
      for (const dep of Object.keys(manifest[field] || {})) {
        for (const { pattern, why } of FORBIDDEN_SPECIFIERS) {
          if (!pattern.test(dep)) continue;
          violations.push({
            file: path.relative(REPO_ROOT, manifestPath),
            line: 0,
            specifier: dep,
            why: `${why} (declared in ${field})`,
            text: `"${dep}"`,
          });
          break;
        }
      }
    }
  }

  if (violations.length > 0) {
    console.error('seam guard: FAIL - Apache-2.0 boundary of packages/capsule-core is breached\n');
    for (const v of violations) {
      const where = v.line ? `${v.file}:${v.line}` : v.file;
      console.error(`  ${where}`);
      console.error(`    imports ${JSON.stringify(v.specifier)} - ${v.why}`);
      console.error(`    ${v.text}\n`);
    }
    console.error(
      'capsule-core is Apache-2.0 so the crypto stays reusable outside this repo. Importing\n' +
        'AGPL-derived code here makes the whole package an AGPL derivative. Move the code that\n' +
        'needs both into servers/ or cli/, which are already AGPL-3.0.\n'
    );
    process.exit(1);
  }

  // A guard that inspected nothing must not claim success.
  if (files.length === 0) {
    console.error(
      `seam guard: FAIL - inspected 0 source files under ${path.relative(REPO_ROOT, GUARDED_DIR)}.\n` +
        'Nothing was actually checked, so this is not a pass. Either the package is empty\n' +
        '(expected before Phase B - remove this guard from `npm test` only deliberately) or the\n' +
        'walk is broken.'
    );
    process.exit(1);
  }

  console.log(
    `seam guard: PASS - ${files.length} file(s) under packages/capsule-core, no AGPL-derived imports.`
  );
}

main();
