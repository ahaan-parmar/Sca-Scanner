'use strict';

/**
 * checks/typosquat_check.js
 *
 * Detects potential typosquatting by comparing the target package name
 * against a curated list of top npm packages using:
 *   - Levenshtein edit distance (self-implemented, no external dep)
 *   - Character transposition detection
 *   - Prefix/suffix manipulation (e.g., "node-axios", "axiosjs")
 *   - Homoglyph substitution patterns
 */

const path = require('path');
const config = require('../config.json');
const logger = require('../utils/logger');

// Load popular packages list once at module load time
const TOP_PACKAGES = require('../data/top_packages.json').packages;

// ─── Levenshtein distance (self-implemented) ─────────────────────────────────

/**
 * Compute the edit distance between two strings.
 * Uses Wagner–Fischer dynamic programming algorithm.
 * Time: O(mn), Space: O(mn) → optimised to O(n) below.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;

  // Optimise for empty strings
  if (m === 0) return n;
  if (n === 0) return m;

  // Use two rows instead of the full matrix
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array(n + 1).fill(0);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        curr[j] = prev[j - 1];
      } else {
        curr[j] = 1 + Math.min(prev[j], curr[j - 1], prev[j - 1]);
      }
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n];
}

// ─── Similarity helpers ────────────────────────────────────────────────────

/**
 * Strip common npm-specific prefixes/suffixes for normalization.
 * e.g.  "node-axios" → "axios",  "axiosjs" → "axios"
 *
 * @param {string} name
 * @returns {string}
 */
function normalizePackageName(name) {
  return name
    .toLowerCase()
    .replace(/^node-/, '')
    .replace(/^nodejs-/, '')
    .replace(/-js$/, '')
    .replace(/\.js$/, '')
    .replace(/-node$/, '')
    .replace(/-npm$/, '')
    .replace(/_/g, '-');
}

/**
 * Returns true if the names are an exact match after normalization.
 * This filters out false positives where we're installing the exact package.
 */
function isExactMatch(a, b) {
  return a === b || normalizePackageName(a) === normalizePackageName(b);
}

/**
 * Check whether the target looks like a scoped variant of a popular package.
 * e.g.  "@evil/axios" targeting "axios"
 *
 * @param {string} target   possibly "@scope/name" or "name"
 * @returns {string}        just the bare name portion
 */
function stripScope(name) {
  if (name.startsWith('@')) {
    const parts = name.split('/');
    return parts[1] ?? name;
  }
  return name;
}

/**
 * Homoglyph map: characters that look similar and are used in typosquatting.
 * Normalize both names through this map before distance comparison.
 *
 * @param {string} name
 * @returns {string}
 */
function normalizeHomoglyphs(name) {
  return name
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/\$/g, 's');
}

// ─── Main checker ───────────────────────────────────────────────────────────

/**
 * Score representing how suspicious the name looks (0–10).
 * 0 = clearly not a typosquat, 10 = almost certainly one.
 *
 * @param {Array} matches  Output of findTyposquatMatches()
 * @returns {number}
 */
function computeTyposquatScore(matches) {
  if (matches.length === 0) return 0;
  // The closest match drives the score
  const best = matches[0];
  if (best.distance === 1) return 9;   // One edit away from a popular pkg
  if (best.distance === 2) return 6;   // Two edits — suspicious
  return 3;                             // Further but still flagged
}

/**
 * Find all popular packages that are suspiciously close to the target name.
 *
 * @param {string} packageName
 * @returns {Array<{ match: string, distance: number, type: string }>}
 */
function findTyposquatMatches(packageName) {
  const { max_distance, min_package_length } = config.typosquat;

  // Don't flag very short names (too many false positives)
  if (packageName.length < min_package_length) return [];

  const bare   = stripScope(packageName);
  const normT  = normalizePackageName(bare);
  const homoT  = normalizeHomoglyphs(normT);

  const matches = [];

  for (const popular of TOP_PACKAGES) {
    // Skip if target IS the popular package (exact match)
    if (isExactMatch(bare, popular)) continue;

    const normP = normalizePackageName(popular);

    // 1) Direct Levenshtein on original names
    const d1 = levenshtein(bare.toLowerCase(), popular.toLowerCase());

    // 2) Normalized names (strips node-, -js, etc.)
    const d2 = levenshtein(normT, normP);

    // 3) Homoglyph-normalized comparison
    const homoP = normalizeHomoglyphs(normP);
    const d3 = levenshtein(homoT, homoP);

    const minDist = Math.min(d1, d2, d3);

    if (minDist <= max_distance) {
      let type = 'edit-distance';
      if (d3 < d1 && d3 < d2) type = 'homoglyph';
      else if (d2 < d1) type = 'normalized';

      matches.push({ match: popular, distance: minDist, type });
    }
  }

  // Sort by closest distance first
  matches.sort((a, b) => a.distance - b.distance);

  // Deduplicate (same popular package, keep best distance)
  const seen = new Set();
  return matches.filter((m) => {
    if (seen.has(m.match)) return false;
    seen.add(m.match);
    return true;
  });
}

/**
 * Run the full typosquatting check.
 *
 * @param {string} packageName
 * @returns {{ findings: Array, riskScore: number }}
 */
function runTyposquatCheck(packageName) {
  logger.debug(`Typosquat check: ${packageName}`);

  const matches = findTyposquatMatches(packageName);
  const riskScore = computeTyposquatScore(matches);

  logger.debug(
    `Typosquat check: ${matches.length} matches found (risk: ${riskScore})`
  );

  return { findings: matches, riskScore };
}

module.exports = { runTyposquatCheck, levenshtein, findTyposquatMatches };
