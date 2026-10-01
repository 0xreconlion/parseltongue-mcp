'use strict';

/**
 * Fuzzy transform lookup.
 *
 * Ported from the matching logic in upstream's p4rs3lt0ngv3_cli/agent.py find_transform: exact
 * key, exact name, token membership, edit-distance, then token overlap. The NL prompt parsing
 * around it (plan_prompt, extract_option_hints, extract_text) is intentionally not ported — an
 * MCP caller passes structured arguments, so an English parser would be dead weight and an extra
 * place for the tool to guess wrong.
 *
 * 222 transforms is too many to put in front of a caller as a flat list, which is what makes
 * this worth having rather than requiring exact keys.
 */

const { getRegistry } = require('./registry');

/** Normalised edit distance, 0..1 where 1 is identical. Stands in for difflib's ratio(). */
function similarity(a, b) {
  if (a === b) return 1;
  if (!a.length || !b.length) return 0;

  // Levenshtein, single-row.
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const row = [i];
    for (let j = 1; j <= b.length; j += 1) {
      row[j] = Math.min(
        prev[j] + 1,
        row[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
    prev = row;
  }
  return 1 - prev[b.length] / Math.max(a.length, b.length);
}

function normaliseQuery(query) {
  return String(query || '').trim().toLowerCase().replace(/-/g, '_');
}

/**
 * Rank transforms against a free-text query. Returns [{ entry, score, why }], best first.
 */
function findTransforms(query, { limit = 10 } = {}) {
  const normalised = normaliseQuery(query);
  if (!normalised) return [];

  const { entries } = getRegistry();

  // Exact key wins outright — no point ranking anything else.
  if (entries.has(normalised)) {
    return [{ entry: entries.get(normalised), score: 1, why: 'exact key match' }];
  }

  const queryTokens = new Set(normalised.match(/[a-z0-9]+/g) || []);
  const ranked = [];

  for (const entry of entries.values()) {
    let score = 0;
    let why = null;

    if (entry.name.toLowerCase() === normalised) {
      score = 1;
      why = 'exact name match';
    } else if (entry._tokens.has(normalised)) {
      score = 0.9;
      why = 'query is one of its tokens';
    } else {
      const overlap = [...queryTokens].filter((t) => entry._tokens.has(t)).length;
      const keySimilarity = similarity(normalised, entry.key);
      const nameSimilarity = similarity(normalised, entry.name.toLowerCase());
      const best = Math.max(keySimilarity, nameSimilarity);

      if (overlap > 0) {
        score = 0.5 + (0.3 * overlap) / Math.max(queryTokens.size, 1);
        why = `${overlap} matching token${overlap === 1 ? '' : 's'}`;
      } else if (best >= 0.55) {
        score = best * 0.6;
        why = `name is similar (${best.toFixed(2)})`;
      }
    }

    if (score > 0) {
      // Upstream priority breaks ties between equally-good matches.
      ranked.push({ entry, score: score + entry.priority * 1e-6, why });
    }
  }

  ranked.sort((a, b) => b.score - a.score);
  return ranked.slice(0, limit);
}

/** Single best match, or null. */
function findTransform(query) {
  const [best] = findTransforms(query, { limit: 1 });
  return best ? best.entry : null;
}

module.exports = { findTransform, findTransforms, similarity };
