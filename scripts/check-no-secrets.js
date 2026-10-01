#!/usr/bin/env node
'use strict';

/**
 * Artifact guard: refuse to let a real vault, identity backup, or capsule into the repository.
 *
 * .gitignore covers the filenames the tool writes, but a user can name a backup anything, and a
 * gitignore says nothing about a file that is already tracked. This checks for the artifact
 * FORMATS instead of trusting names.
 *
 * Detecting the header strings alone would be useless - backup.js and capsule.js legitimately
 * define them, and wizard.html matches on them. So a hit requires a header followed by a long
 * base64 body, which is what an actual artifact looks like and what no source file contains.
 *
 * gitleaks already covers generic credentials on push. This covers the thing gitleaks has no rule
 * for: this project's own key-bearing formats.
 *
 *   node scripts/check-no-secrets.js            # scan tracked + untracked files
 *   node scripts/check-no-secrets.js --staged   # scan what is staged for commit
 */

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..');

// A header line, then (allowing metadata/comment lines between) a run of base64url at least 60
// characters long. Source files contain the headers but never a body.
const BASE64_BODY = '[A-Za-z0-9_-]{60,}';

/**
 * Each pattern requires EVERY regex in `all` to match somewhere in the file.
 *
 * The first version used proximity regexes ("header, then within 400 characters a base64 body").
 * A positive control caught that out immediately: a real vault file renamed to config-notes.json
 * passed, because pretty-printed JSON puts the whole identity block between the kdf and the
 * ciphertext and blows past any window worth setting. Independent conditions combined with AND
 * have no such blind spot, and the headers still cannot match source files on their own because
 * a body is always required too.
 */
const ARTIFACT_PATTERNS = [
  {
    name: 'identity backup (PRIVATE KEYS)',
    severity: 'critical',
    all: [/PARSELTONGUE IDENTITY BACKUP/, new RegExp(BASE64_BODY)],
  },
  {
    name: 'sealed capsule',
    severity: 'warning',
    all: [/PARSELTONGUE CAPSULE v1 -----/, new RegExp(BASE64_BODY)],
  },
  {
    name: 'vault or backup record (encrypted private keys)',
    severity: 'critical',
    all: [/"alg"\s*:\s*"argon2id"/, /"ct"\s*:\s*"[A-Za-z0-9_-]{40,}"/],
  },
  {
    name: 'argon2id-wrapped record with a salt and nonce',
    severity: 'critical',
    all: [/argon2id/, /"salt"\s*:\s*"[A-Za-z0-9_-]{16,}"/, /"nonce"\s*:\s*"[A-Za-z0-9_-]{16,}"/],
  },
  {
    name: 'raw 32-byte base64url key beside a private-looking field name',
    severity: 'critical',
    all: [/"(?:secret|private|seed|mnemonic)"\s*:\s*\{?\s*"?(?:sign|encrypt)?"?\s*:?\s*"[A-Za-z0-9_-]{43}"/],
  },
];

// Files that legitimately contain the header strings or example shapes.
const ALLOWED = new Set([
  'packages/capsule-core/src/backup.js',
  'packages/capsule-core/src/capsule.js',
  'packages/capsule-core/src/vault.js',
  'packages/capsule-core/src/identity.js',
  'wizard/wizard.html',
  'scripts/check-no-secrets.js',
  'test/capsule-core.test.js',
  'test/capsules-server.test.js',
]);

const SKIP_DIRS = ['node_modules', '.git'];
const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|woff2?|ttf|mp4|wasm)$/i;

function gitFiles(staged) {
  try {
    const args = staged
      ? ['diff', '--cached', '--name-only', '--diff-filter=ACM']
      : ['ls-files', '--cached', '--others', '--exclude-standard'];
    return execFileSync('git', ['-C', REPO_ROOT, ...args], { encoding: 'utf8' })
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
  } catch {
    return null;
  }
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else out.push(path.relative(REPO_ROOT, full));
  }
  return out;
}

function main() {
  const staged = process.argv.includes('--staged');
  const files = gitFiles(staged) || walk(REPO_ROOT);

  const findings = [];
  let scanned = 0;

  for (const relative of files) {
    if (ALLOWED.has(relative)) continue;
    if (BINARY_EXT.test(relative)) continue;

    const full = path.join(REPO_ROOT, relative);
    let stat;
    try {
      stat = fs.statSync(full);
    } catch {
      continue; // deleted or unreadable
    }
    if (!stat.isFile() || stat.size > 5 * 1024 * 1024) continue;

    let content;
    try {
      content = fs.readFileSync(full, 'utf8');
    } catch {
      continue;
    }
    scanned += 1;

    for (const pattern of ARTIFACT_PATTERNS) {
      if (pattern.all.every((regex) => regex.test(content))) {
        findings.push({ file: relative, name: pattern.name, severity: pattern.severity });
      }
    }
  }

  const critical = findings.filter((f) => f.severity === 'critical');

  if (findings.length > 0) {
    console.error('artifact guard: FAIL\n');
    for (const finding of findings) {
      console.error(`  [${finding.severity}] ${finding.file}`);
      console.error(`      looks like a ${finding.name}\n`);
    }
    console.error(
      'A vault or identity backup in version control hands over the private keys for every\n' +
        'capsule ever sealed to that identity. Remove the file, and if it was ever committed,\n' +
        'treat the identity as compromised and generate a new one - rewriting history is not\n' +
        'enough once it has been pushed.\n'
    );
    process.exit(critical.length > 0 ? 1 : 1);
  }

  if (scanned === 0) {
    console.error(
      'artifact guard: FAIL - scanned 0 files. Nothing was checked, so this is not a pass.'
    );
    process.exit(1);
  }

  console.log(`artifact guard: PASS - ${scanned} file(s) scanned, no vault/backup/capsule artifacts.`);
}

main();
