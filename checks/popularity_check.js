'use strict';

/**
 * checks/popularity_check.js
 *
 * Assesses package legitimacy through popularity signals:
 *   - Weekly npm download count (from npm downloads API)
 *   - GitHub stars, forks, open issues, last push date
 *   - Repository archival status
 *
 * Low popularity does NOT automatically mean malicious, but combined with
 * other findings it raises suspicion. This check provides informational
 * context and minor risk signal rather than driving the score heavily.
 */

const { fetchNpmDownloads, fetchGitHubStats } = require('../core/fetcher');
const config = require('../config.json');
const logger  = require('../utils/logger');

const { very_low_downloads_weekly, low_downloads_weekly } = config.popularity;

/**
 * Format a large number with K/M suffix.
 * @param {number} n
 * @returns {string}
 */
function formatCount(n) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

/**
 * Run popularity / reputation checks for a package.
 *
 * @param {string} packageName
 * @param {object} packument       Full npm packument (for repository URL)
 * @returns {Promise<{
 *   findings: string[],
 *   riskScore: number,
 *   data: { downloads: number|null, githubStats: object|null }
 * }>}
 */
async function runPopularityCheck(packageName, packument) {
  logger.debug(`Popularity check: ${packageName}`);

  const findings  = [];
  let   riskScore = 0;

  // ── npm Download Stats ──────────────────────────────────────────────────
  let downloads = null;
  try {
    downloads = await fetchNpmDownloads(packageName);
  } catch {
    // Non-critical — log at debug level only
  }

  if (downloads !== null) {
    if (downloads < very_low_downloads_weekly) {
      findings.push(
        `Very low weekly downloads (${formatCount(downloads)}) — extremely obscure package`
      );
      riskScore = Math.max(riskScore, 5);
    } else if (downloads < low_downloads_weekly) {
      findings.push(
        `Low weekly downloads (${formatCount(downloads)}) — niche or little-known package`
      );
      riskScore = Math.max(riskScore, 2);
    }
  }

  // ── GitHub Stats ────────────────────────────────────────────────────────
  let githubStats = null;
  const repoUrl = packument?.repository?.url ?? '';

  if (repoUrl) {
    try {
      githubStats = await fetchGitHubStats(repoUrl);
    } catch {
      // Non-critical
    }
  }

  if (githubStats) {
    if (githubStats.isArchived) {
      findings.push('GitHub repository is archived — package is no longer maintained');
      riskScore = Math.max(riskScore, 4);
    }

    if (githubStats.stars < 10) {
      findings.push(
        `Very few GitHub stars (${githubStats.stars}) — very limited community adoption`
      );
      riskScore = Math.max(riskScore, 2);
    }

    if (
      githubStats.daysSinceLastPush !== null &&
      githubStats.daysSinceLastPush > 730
    ) {
      const years = (githubStats.daysSinceLastPush / 365).toFixed(1);
      findings.push(
        `Repository has not been updated in ${years} year(s) — may be abandoned`
      );
      riskScore = Math.max(riskScore, 3);
    }
  }

  logger.debug(
    `Popularity check: downloads=${downloads}, stars=${githubStats?.stars ?? 'N/A'}, ` +
    `riskScore=${riskScore}`
  );

  return {
    findings,
    riskScore,
    data: { downloads, githubStats },
  };
}

module.exports = { runPopularityCheck, formatCount };
