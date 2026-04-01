'use strict';

/**
 * checks/cve_check.js
 *
 * Queries OSV.dev to find known CVEs and security advisories
 * for a given package@version. Normalizes severity across CVSS v2/v3/GHSA.
 */

const { fetchOSVVulnerabilities } = require('../core/fetcher');
const logger = require('../utils/logger');

// ─── Severity normalizer ────────────────────────────────────────────────────

/**
 * Estimate a numeric CVSS base score from a CVSS v3 vector string.
 * Uses per-metric weights to approximate the base score without full formula.
 * Reference: CVSS v3.1 specification.
 *
 * @param {string} vector  e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
 * @returns {number}  Approximate 0–10 score
 */
function estimateCvssScore(vector) {
  if (!vector || typeof vector !== 'string') return 0;

  // Extract metric key=value pairs
  const metrics = {};
  for (const part of vector.split('/')) {
    const [key, val] = part.split(':');
    if (key && val) metrics[key] = val;
  }

  // Simple approximation: weight by common high-impact combos
  const av   = { N: 1.0, A: 0.7, L: 0.55, P: 0.2 }[metrics.AV] ?? 0.5;
  const ac   = { L: 1.0, H: 0.44 }[metrics.AC] ?? 0.7;
  const pr   = { N: 1.0, L: 0.68, H: 0.5 }[metrics.PR] ?? 0.7;
  const ui   = { N: 1.0, R: 0.62 }[metrics.UI] ?? 0.85;
  const ci   = { H: 10, L: 4, N: 0 }[metrics.C] ?? 0;
  const ii   = { H: 10, L: 4, N: 0 }[metrics.I] ?? 0;
  const ai   = { H: 10, L: 4, N: 0 }[metrics.A] ?? 0;

  const impact = Math.max(ci, ii, ai);
  if (impact === 0) return 0;

  const exploitability = av * ac * pr * ui;
  const score = (impact / 10) * exploitability * 10;
  return Math.min(Math.round(score * 10) / 10, 10);
}

/**
 * Normalize OSV severity fields into a standard level string.
 * OSV can return CVSS v2/v3 vectors, plain numeric scores, or string labels.
 * Priority: database_specific.severity > CVSS vector parsing > string labels.
 *
 * @param {Array}  severities       Array of { type, score } from OSV
 * @param {object} [vuln]           Full OSV vulnerability record (for database_specific)
 * @returns {{ level: string, score: number }}
 */
function normalizeSeverity(severities = [], vuln = {}) {
  let maxScore = 0;

  // ── Priority 1: database_specific.severity (GitHub Advisory string labels) ──
  const dbSeverity = vuln?.database_specific?.severity;
  if (typeof dbSeverity === 'string') {
    const upper = dbSeverity.toUpperCase();
    if (upper === 'CRITICAL') maxScore = Math.max(maxScore, 9.5);
    else if (upper === 'HIGH')     maxScore = Math.max(maxScore, 7.5);
    else if (upper === 'MODERATE' || upper === 'MEDIUM') maxScore = Math.max(maxScore, 5.5);
    else if (upper === 'LOW')      maxScore = Math.max(maxScore, 2.0);
  }

  // ── Priority 2: CVSS vector / numeric score ────────────────────────────────
  for (const s of (severities ?? [])) {
    const raw = s.score ?? '';

    if (typeof raw === 'number') {
      maxScore = Math.max(maxScore, raw);
    } else if (typeof raw === 'string') {
      // Try plain numeric first (e.g. "7.5")
      const numMatch = raw.match(/^(\d+(?:\.\d+)?)$/);
      if (numMatch) {
        maxScore = Math.max(maxScore, parseFloat(numMatch[1]));
      }
      // Try CVSS vector (e.g. "CVSS:3.1/AV:N/...")
      else if (raw.startsWith('CVSS:')) {
        const estimated = estimateCvssScore(raw);
        maxScore = Math.max(maxScore, estimated);
      }
      // Severity label strings
      else {
        const upper = raw.toUpperCase();
        if (upper === 'CRITICAL') maxScore = Math.max(maxScore, 9.5);
        else if (upper === 'HIGH')     maxScore = Math.max(maxScore, 7.5);
        else if (upper === 'MEDIUM' || upper === 'MODERATE') maxScore = Math.max(maxScore, 5.5);
        else if (upper === 'LOW')      maxScore = Math.max(maxScore, 2.0);
      }
    }
  }

  // ── Map numeric score → level ──────────────────────────────────────────────
  let level;
  if (maxScore >= 9.0)      level = 'CRITICAL';
  else if (maxScore >= 7.0) level = 'HIGH';
  else if (maxScore >= 4.0) level = 'MEDIUM';
  else if (maxScore > 0)    level = 'LOW';
  else                      level = 'UNKNOWN';

  return { level, score: maxScore };
}

/**
 * Map severity level to numeric risk score (0–10) for the risk engine.
 * @param {string} level
 * @returns {number}
 */
function severityToScore(level) {
  const map = { CRITICAL: 10, HIGH: 7.5, MEDIUM: 4, LOW: 1.5, UNKNOWN: 1 };
  return map[level] ?? 1;
}

// ─── Alias / withdrawn detection ────────────────────────────────────────────

/**
 * OSV can return records for aliased CVEs or withdrawn advisories.
 * Filter out withdrawn / disputed entries.
 *
 * @param {object} vuln  Single OSV vulnerability record
 * @returns {boolean}
 */
function isWithdrawn(vuln) {
  return !!(vuln.withdrawn || vuln.summary?.toLowerCase().includes('withdrawn'));
}

// ─── Main checker ───────────────────────────────────────────────────────────

/**
 * Run CVE check for a package@version.
 *
 * @param {string} packageName
 * @param {string} version     Concrete semver string
 * @returns {Promise<{
 *   findings: Array<{ id: string, severity: string, score: number, summary: string, aliases: string[], url: string }>,
 *   riskScore: number,
 *   raw: Array
 * }>}
 */
async function runCveCheck(packageName, version) {
  logger.debug(`CVE check: ${packageName}@${version}`);

  let vulns;
  try {
    vulns = await fetchOSVVulnerabilities(packageName, version);
  } catch (err) {
    logger.warn(`CVE lookup failed: ${err.message}`);
    return { findings: [], riskScore: 0, raw: [], error: err.message };
  }

  const findings = [];
  let maxSeverityScore = 0;

  for (const vuln of vulns) {
    if (isWithdrawn(vuln)) continue;

    const { level, score } = normalizeSeverity(vuln.severity ?? [], vuln);
    const numericScore = severityToScore(level);

    if (numericScore > maxSeverityScore) {
      maxSeverityScore = numericScore;
    }

    // Collect all CVE aliases
    const aliases = (vuln.aliases ?? []).filter((a) => a.startsWith('CVE-'));
    const primaryId = aliases[0] ?? vuln.id;

    // Try to extract a clean summary (OSV has verbose details sometimes)
    let summary = vuln.summary ?? vuln.details ?? 'No description available';
    if (summary.length > 100) summary = summary.slice(0, 97) + '...';

    findings.push({
      id: primaryId,
      osvId: vuln.id,
      severity: level,
      score: numericScore,
      cvssScore: score,
      summary,
      aliases: vuln.aliases ?? [],
      url: `https://osv.dev/vulnerability/${vuln.id}`,
      published: vuln.published,
      modified: vuln.modified,
    });
  }

  // Sort findings by severity descending
  findings.sort((a, b) => b.score - a.score);

  // CVE risk score: use max severity score, cap at 10
  const riskScore = Math.min(maxSeverityScore, 10);

  logger.debug(`CVE check complete: ${findings.length} vulnerabilities found (risk: ${riskScore})`);

  return { findings, riskScore, raw: vulns };
}

module.exports = { runCveCheck, normalizeSeverity, severityToScore };
