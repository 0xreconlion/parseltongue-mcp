'use strict';

/**
 * The transform registry: upstream's exported map, plus category, option schema, and measured
 * round-trip fidelity, assembled once and cached.
 *
 * Caching is not a micro-optimisation. Upstream's loader evaluates ~222 files through node:vm on
 * first require, and this runs on a Raspberry Pi. Building the registry per tool call would make
 * every call pay for it.
 *
 * Fidelity metadata is the reason this module exists rather than just re-exporting upstream's
 * map. Upstream's `canDecode` means only "a reverse() function exists" — it says nothing about
 * whether decode returns the original text. See scripts/probe-fidelity.js.
 */

const fs = require('node:fs');
const path = require('node:path');

const { loadCategories, loadTransforms, resolveParseltongueRoot } = require('./loader');

const FIDELITY_PATH = path.join(__dirname, '..', 'data', 'fidelity.json');

let cache = null;

function loadFidelity() {
  try {
    return JSON.parse(fs.readFileSync(FIDELITY_PATH, 'utf8'));
  } catch {
    // Absent fidelity data must not look like "everything is fine". Every transform becomes
    // 'unmeasured' and says so.
    return null;
  }
}

/**
 * Default values for a transform's configurable options. Ported from upstream's cli_bridge.js
 * so option handling matches what upstream's own CLI does.
 */
function defaultOptions(transform) {
  const options = transform.configurableOptions || [];
  const defaults = {};
  for (const opt of options) {
    let value = opt.default;
    if (value === undefined || value === null) {
      if (opt.type === 'boolean') value = false;
      else if (opt.type === 'select' && opt.options && opt.options.length) value = opt.options[0].value;
      else if (opt.type === 'number') value = 0;
      else value = '';
    }
    defaults[opt.id] = value;
  }
  return defaults;
}

function optionSchema(transform) {
  return (transform.configurableOptions || []).map((opt) => ({
    id: opt.id,
    label: opt.label,
    type: opt.type,
    default: opt.default,
    ...(opt.min !== undefined ? { min: opt.min } : {}),
    ...(opt.max !== undefined ? { max: opt.max } : {}),
    ...(opt.step !== undefined ? { step: opt.step } : {}),
    ...(opt.options ? { choices: opt.options } : {}),
  }));
}

/**
 * Search tokens for fuzzy lookup. Ported from the token-overlap half of upstream's agent.py
 * find_transform; the natural-language prompt parsing in that file is deliberately NOT ported,
 * because MCP callers pass structured arguments and do not need an English parser.
 */
function searchTokens(key, name, category, description) {
  const tokens = new Set();
  for (const source of [key, name, category, description]) {
    if (!source) continue;
    for (const token of String(source).toLowerCase().match(/[a-z0-9]+/g) || []) {
      if (token.length > 1) tokens.add(token);
    }
  }
  return tokens;
}

function build() {
  const root = resolveParseltongueRoot();
  const transforms = loadTransforms(root);
  const categories = loadCategories(root);
  const fidelityData = loadFidelity();

  const entries = new Map();

  for (const key of Object.keys(transforms).sort()) {
    const transform = transforms[key];
    if (!transform || typeof transform.func !== 'function') continue;

    const category = categories.get(key) || 'uncategorised';
    const description = transform.description || '';
    const measured = fidelityData && fidelityData.transforms[key];

    entries.set(key, {
      key,
      category,
      name: transform.name || key,
      description,
      priority: transform.priority ?? 0,
      // Upstream's own definition of canDecode: a reverse function exists. Kept, but never
      // presented without the fidelity tier beside it.
      canDecode: typeof transform.reverse === 'function',
      fidelity: measured ? measured.tier : 'unmeasured',
      fidelityNote: measured
        ? measured.note
        : 'round-trip fidelity not measured; run scripts/probe-fidelity.js',
      ...(measured && measured.safeFor ? { safeFor: measured.safeFor } : {}),
      options: optionSchema(transform),
      _tokens: searchTokens(key, transform.name, category, description),
      _impl: transform,
    });
  }

  if (entries.size === 0) {
    throw new Error('registry built with 0 usable transforms; refusing to serve an empty catalog');
  }

  return {
    root,
    upstreamCommit: fidelityData ? fidelityData.upstreamCommit : null,
    fidelityMeasuredAt: fidelityData ? fidelityData.generatedAt : null,
    // True when the fidelity data was measured against a different commit than the one loaded.
    fidelityStale: Boolean(
      fidelityData && fidelityData.upstreamCommit && fidelityData.upstreamCommit !== currentCommit(root)
    ),
    entries,
  };
}

function currentCommit(root) {
  try {
    return require('node:child_process')
      .execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      })
      .trim();
  } catch {
    return null;
  }
}

function getRegistry() {
  if (!cache) cache = build();
  return cache;
}

/** Public metadata for one transform — never includes the implementation or search tokens. */
function publicEntry(entry) {
  const { _impl, _tokens, ...rest } = entry;
  return rest;
}

module.exports = { getRegistry, publicEntry, defaultOptions, searchTokens };
