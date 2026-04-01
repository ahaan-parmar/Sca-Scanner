'use strict';

/**
 * core/risk_engine.js
 *
 * Aggregates individual check scores into a single weighted risk score
 * and maps it to a human-readable risk level.
 *
 * Formula:
 *   score = (cve * 0.5) + (script * 0.2) + (typosquat * 0.2) + (maintainer * 0.1)
 *
 * Level mapping (from config.json):
 *   score < 2.5  → LOW
 *   score < 5.0  → MEDIUM
 *   score < 7.5  → HIGH
 *   score >= 7.5 → CRITICAL
 */

const config = require('../config.json');
const logger = require('../utils/logger');

const { weights, thresholds } = config.risk;

// ─── Score → Level mapping ──────────────────────────────────────────────────

/**
 * Map a numeric 0–10 score to a severity level string.
 *
 * @param {number} score
 * @returns {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'}
 */
function scoreToLevel(score) {
  if (score >= thresholds.high)   return 'CRITICAL';
  if (score >= thresholds.medium) return 'HIGH';
  if (score >= thresholds.low)    return 'MEDIUM';
  return 'LOW';
}

/**
 * Return a one-sentence description of the risk level for the report.
 *
 * @param {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} level
 * @returns {string}
 */
function levelDescription(level) {
  const descriptions = {
    LOW:      'No significant risks detected. Installation appears safe.',
    MEDIUM:   'Some risks detected. Review findings before proceeding.',
    HIGH:     'Significant risks detected. Installation blocked in --strict mode.',
    CRITICAL: 'Critical security risks detected. Do NOT install without review.',
  };
  return descriptions[level] ?? 'Unknown risk level.';
}

// ─── Risk engine ────────────────────────────────────────────────────────────

/**
 * Compute the final aggregate risk score and level.
 *
 * @param {object} checkResults
 * @param {number} checkResults.cveScore
 * @param {number} checkResults.scriptScore
 * @param {number} checkResults.typosquatScore
 * @param {number} checkResults.maintainerScore
 * @param {number} [checkResults.licenseScore]
 * @returns {{ score: number, level: string, description: string, breakdown: object }}
 */
function computeRisk({ cveScore, scriptScore, typosquatScore, maintainerScore, licenseScore = 0 }) {
  const cve        = clamp(cveScore, 0, 10);
  const script     = clamp(scriptScore, 0, 10);
  const typosquat  = clamp(typosquatScore, 0, 10);
  const maintainer = clamp(maintainerScore, 0, 10);
  const license    = clamp(licenseScore, 0, 10);

  // Weights from config — fall back gracefully if license weight not present
  const wLicense = weights.license ?? 0;

  const score = (
    (cve        * weights.cve)        +
    (script     * weights.script)     +
    (typosquat  * weights.typosquat)  +
    (maintainer * weights.maintainer) +
    (license    * wLicense)
  );

  const finalScore = parseFloat(clamp(score, 0, 10).toFixed(2));
  const level      = scoreToLevel(finalScore);
  const description = levelDescription(level);

  logger.debug(
    `Risk breakdown — CVE: ${cve}×${weights.cve}, Script: ${script}×${weights.script}, ` +
    `Typosquat: ${typosquat}×${weights.typosquat}, Maintainer: ${maintainer}×${weights.maintainer}, ` +
    `License: ${license}×${wLicense} → ${finalScore} (${level})`
  );

  return {
    score: finalScore,
    level,
    description,
    breakdown: {
      cve:        { raw: cve,        weighted: +(cve * weights.cve).toFixed(2) },
      script:     { raw: script,     weighted: +(script * weights.script).toFixed(2) },
      typosquat:  { raw: typosquat,  weighted: +(typosquat * weights.typosquat).toFixed(2) },
      maintainer: { raw: maintainer, weighted: +(maintainer * weights.maintainer).toFixed(2) },
      license:    { raw: license,    weighted: +(license * wLicense).toFixed(2) },
    },
  };
}

// ─── Helper ─────────────────────────────────────────────────────────────────

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val ?? 0));
}

// ─── Strict mode check ──────────────────────────────────────────────────────

/**
 * Returns true if the risk level should block installation in --strict mode.
 *
 * @param {string} level
 * @returns {boolean}
 */
function shouldBlock(level) {
  return level === 'HIGH' || level === 'CRITICAL';
}

module.exports = { computeRisk, scoreToLevel, shouldBlock, levelDescription };
