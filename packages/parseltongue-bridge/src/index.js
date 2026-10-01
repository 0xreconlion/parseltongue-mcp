'use strict';

/**
 * @reconlion/parseltongue-bridge - AGPL-3.0-only
 *
 * Node access to the P4RS3LT0NGV3 transform catalog. This is the only package in this repo that
 * touches upstream source, which is what makes it the only AGPL-derivative package and keeps
 * @reconlion/capsule-core clean. See ../../docs/LICENSING.md.
 *
 * Transforms are REPRESENTATION, not confidentiality. Everything exposed here is reversible by
 * anyone, with no key. Nothing in this package provides secrecy.
 */

const { ParseltongueRootError, resolveParseltongueRoot } = require('./loader');
const { getRegistry, publicEntry, defaultOptions } = require('./registry');
const { findTransform, findTransforms } = require('./find');
const { TransformError, autoDecode, runTransform } = require('./run');
const { inspectText } = require('./inspect');

/** Every transform's public metadata, optionally filtered. */
function listTransforms({ category = null, canDecode = null, fidelity = null } = {}) {
  const { entries } = getRegistry();
  let list = [...entries.values()];

  if (category) list = list.filter((e) => e.category === category);
  if (canDecode !== null) list = list.filter((e) => e.canDecode === canDecode);
  if (fidelity) {
    const wanted = Array.isArray(fidelity) ? fidelity : [fidelity];
    list = list.filter((e) => wanted.includes(e.fidelity));
  }

  return list.map(publicEntry);
}

/** Catalog shape: categories, counts, fidelity spread, and provenance. */
function catalogSummary() {
  const registry = getRegistry();
  const byCategory = {};
  const byFidelity = {};

  for (const entry of registry.entries.values()) {
    byCategory[entry.category] = (byCategory[entry.category] || 0) + 1;
    byFidelity[entry.fidelity] = (byFidelity[entry.fidelity] || 0) + 1;
  }

  return {
    total: registry.entries.size,
    byCategory,
    byFidelity,
    upstreamRoot: registry.root,
    upstreamCommit: registry.upstreamCommit,
    fidelityMeasuredAt: registry.fidelityMeasuredAt,
    fidelityStale: registry.fidelityStale,
  };
}

module.exports = {
  ParseltongueRootError,
  TransformError,

  autoDecode,
  catalogSummary,
  defaultOptions,
  findTransform,
  findTransforms,
  getRegistry,
  inspectText,
  listTransforms,
  resolveParseltongueRoot,
  runTransform,
};
