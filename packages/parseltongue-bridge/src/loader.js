'use strict';

/**
 * Locating and loading the upstream P4RS3LT0NGV3 transform catalog.
 *
 * Upstream is never vendored into this repo — it stays a separate checkout, pointed at by
 * PARSELTONGUE_ROOT. That keeps the AGPL derivative boundary visible and keeps upstream's
 * history out of ours.
 *
 * Two things here are not incidental:
 *
 *  1. STDOUT IS PROTECTED. upstream's loader-node.js calls console.warn on a missing optional
 *     data file. console.warn goes to stderr today, so it is harmless — but this module is
 *     loaded by an MCP server speaking JSON-RPC over stdout, where a single stray byte corrupts
 *     the stream and the failure looks like an unrelated protocol error. We do not want that to
 *     depend on upstream never switching a warn to a log. Any stdout write during load is
 *     redirected to stderr.
 *
 *  2. THE LOAD PATH IS NOT CALLER-CONTROLLED. upstream's loader uses node:vm to evaluate all
 *     ~222 transform files with `export` keywords stripped. node:vm is NOT a security boundary,
 *     so the set of files evaluated must never be influenced by tool input. Callers choose a
 *     root once, from the environment; no MCP tool accepts a path or filename.
 */

const fs = require('node:fs');
const path = require('node:path');

const LOADER_RELATIVE = path.join('src', 'transformers', 'loader-node.js');
const TRANSFORMS_RELATIVE = path.join('src', 'transformers');

// Non-transform files living in the transformers tree.
const SKIP_FILES = new Set(['BaseTransformer.js', 'index.js', 'loader-node.js', 'README.md']);

/**
 * Conventional places to look when PARSELTONGUE_ROOT is unset, relative to this repository.
 *
 * These were absolute paths inside one developer's home directory until this repo was prepared
 * for publication. That was wrong twice over: it leaked a username and directory layout, and the
 * fallback was meaningless on any other machine — it would simply never match, so the error
 * message was doing all the work anyway. Relative conventional locations actually help someone
 * who cloned both repositories side by side.
 */
const CANDIDATE_ROOTS = [
  path.resolve(__dirname, '..', '..', '..', 'vendor', 'P4RS3LT0NGV3'),
  path.resolve(__dirname, '..', '..', '..', '..', 'P4RS3LT0NGV3'),
  path.resolve(__dirname, '..', '..', '..', '..', 'p4rs3lt0ngv3'),
];

class ParseltongueRootError extends Error {}

function looksLikeParseltongueRoot(root) {
  return fs.existsSync(path.join(root, LOADER_RELATIVE));
}

/**
 * Resolve the upstream checkout. PARSELTONGUE_ROOT wins; otherwise fall back to known local
 * checkouts so the server starts without configuration on this machine.
 */
function resolveParseltongueRoot() {
  const configured = process.env.PARSELTONGUE_ROOT;
  if (configured) {
    const root = path.resolve(configured);
    if (!looksLikeParseltongueRoot(root)) {
      throw new ParseltongueRootError(
        `PARSELTONGUE_ROOT=${configured} does not look like a P4RS3LT0NGV3 checkout ` +
          `(expected ${LOADER_RELATIVE} inside it).`
      );
    }
    return root;
  }

  for (const candidate of CANDIDATE_ROOTS) {
    if (looksLikeParseltongueRoot(candidate)) return candidate;
  }

  throw new ParseltongueRootError(
    'Could not find a P4RS3LT0NGV3 checkout. Set PARSELTONGUE_ROOT to one.\n' +
      `Looked in: ${CANDIDATE_ROOTS.join(', ')}`
  );
}

/**
 * Run `fn` with process.stdout.write diverted to stderr. See note 1 above.
 */
function withProtectedStdout(fn) {
  const original = process.stdout.write.bind(process.stdout);
  let leaked = 0;
  process.stdout.write = function (chunk, encoding, callback) {
    leaked += 1;
    return process.stderr.write(chunk, encoding, callback);
  };
  try {
    return fn();
  } finally {
    process.stdout.write = original;
    if (leaked > 0) {
      process.stderr.write(
        `[parseltongue-bridge] diverted ${leaked} stdout write(s) during transform load; ` +
          'stdout is reserved for the MCP JSON-RPC stream.\n'
      );
    }
  }
}

/**
 * Load the upstream transform map: { key -> { name, priority, description, func, reverse,
 * preview, configurableOptions, ... } }.
 */
function loadTransforms(root = resolveParseltongueRoot()) {
  const loaderPath = path.join(root, LOADER_RELATIVE);
  const transforms = withProtectedStdout(() => require(loaderPath));

  if (!transforms || typeof transforms !== 'object') {
    throw new Error(`${loaderPath} did not export a transform map`);
  }
  const count = Object.keys(transforms).length;
  if (count === 0) {
    // Fail loud rather than serving an empty catalog that looks like "no results".
    throw new Error(
      `${loaderPath} exported 0 transforms. The checkout is probably incomplete — ` +
        'upstream needs `npm install` to have been run at least once.'
    );
  }
  return transforms;
}

/**
 * Map transform key -> category, by walking the transformers directory. Upstream's own CLI
 * bridge derives category this way; the exported map carries no category field.
 */
function loadCategories(root = resolveParseltongueRoot()) {
  const transformsRoot = path.join(root, TRANSFORMS_RELATIVE);
  const categories = new Map();

  const dirs = fs
    .readdirSync(transformsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  for (const category of dirs) {
    const files = fs
      .readdirSync(path.join(transformsRoot, category))
      .filter((file) => file.endsWith('.js') && !SKIP_FILES.has(file))
      .sort();
    for (const file of files) {
      // Upstream's key convention: filename minus .js, dashes to underscores.
      categories.set(file.replace(/\.js$/, '').replace(/-/g, '_'), category);
    }
  }

  return categories;
}

module.exports = {
  ParseltongueRootError,
  SKIP_FILES,
  loadCategories,
  loadTransforms,
  resolveParseltongueRoot,
  withProtectedStdout,
};
