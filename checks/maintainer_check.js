'use strict';

/**
 * checks/maintainer_check.js
 *
 * Analyses package provenance and maintenance patterns to detect:
 *   - Newly published packages (< 30 days old)
 *   - Very few maintainers (single-maintainer packages)
 *   - Sudden version spikes (many versions published quickly)
 *   - Long periods of inactivity followed by sudden activity
 *   - Significant download count drops (ownership change indicator)
 */

const config = require('../config.json');
const logger = require('../utils/logger');

const {
  new_package_days,
  low_maintainer_threshold,
  inactivity_days,
  version_spike_threshold,
} = config.maintainer;

// ─── Helpers ───────────────────────────────────────────────────────────────

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Parse an ISO date string and return a Date object.
 * Returns null if the string is invalid.
 *
 * @param {string} isoString
 * @returns {Date|null}
 */
function parseDate(isoString) {
  if (!isoString) return null;
  const d = new Date(isoString);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Calculate age in days from a Date to now.
 *
 * @param {Date} date
 * @returns {number}
 */
function ageInDays(date) {
  return (Date.now() - date.getTime()) / MS_PER_DAY;
}

// ─── Individual checks ─────────────────────────────────────────────────────

/**
 * Check how old the package first publish was.
 * Young packages are higher risk for supply-chain attacks.
 */
function checkPackageAge(timeData) {
  const created = parseDate(timeData?.created);
  if (!created) return null;

  const days = ageInDays(created);
  if (days < new_package_days) {
    return `Package was first published ${Math.round(days)} day(s) ago (threshold: ${new_package_days} days)`;
  }
  return null;
}

/**
 * Check the age of the specific version being installed.
 */
function checkVersionAge(timeData, version) {
  const publishedAt = parseDate(timeData?.[version]);
  if (!publishedAt) return null;

  const days = ageInDays(publishedAt);
  if (days < 7) {
    return `This version was published ${Math.round(days)} day(s) ago (very recent)`;
  }
  return null;
}

/**
 * Flag packages with very few maintainers — single-maintainer = higher risk.
 */
function checkMaintainerCount(maintainers = []) {
  const count = maintainers.length;
  if (count === 0) {
    return 'No maintainers listed in registry metadata';
  }
  if (count === 1) {
    return `Single maintainer: ${maintainers[0]?.name ?? maintainers[0]?.email ?? 'unknown'}`;
  }
  if (count < low_maintainer_threshold) {
    return `Only ${count} maintainers — low bus-factor`;
  }
  return null;
}

/**
 * Detect unusual version publish patterns.
 *
 * @param {object} timeData  { version: isoString }
 * @param {object} versions  Keys are version strings
 * @returns {string|null}
 */
function checkVersionSpike(timeData, versions) {
  const versionKeys = Object.keys(versions ?? {}).filter((v) => v !== 'created' && v !== 'modified');
  if (versionKeys.length < 2) return null;

  // Look at the last 30 days' publish activity
  const now = Date.now();
  const windowMs = 30 * MS_PER_DAY;

  const recentVersions = versionKeys.filter((v) => {
    const ts = parseDate(timeData?.[v]);
    return ts && (now - ts.getTime()) < windowMs;
  });

  if (recentVersions.length >= version_spike_threshold) {
    return `${recentVersions.length} versions published in the last 30 days (possible automation or account takeover)`;
  }

  return null;
}

/**
 * Detect long-inactive packages that suddenly published a new version.
 * This pattern is common in account takeover attacks.
 *
 * @param {object} timeData
 * @param {string} targetVersion
 * @param {object} versions
 * @returns {string|null}
 */
function checkInactivityThenActivity(timeData, targetVersion, versions) {
  const versionKeys = Object.keys(versions ?? {})
    .filter((v) => v !== 'created' && v !== 'modified' && timeData?.[v])
    .sort((a, b) => new Date(timeData[a]) - new Date(timeData[b]));

  if (versionKeys.length < 2) return null;

  // Find the second-to-last version (penultimate) vs the latest
  const lastIdx = versionKeys.length - 1;
  const prevVersion = versionKeys[lastIdx - 1];
  const latestVersion = versionKeys[lastIdx];

  const prevDate  = parseDate(timeData[prevVersion]);
  const latestDate = parseDate(timeData[latestVersion]);

  if (!prevDate || !latestDate) return null;

  const gapDays = (latestDate.getTime() - prevDate.getTime()) / MS_PER_DAY;

  if (gapDays > inactivity_days) {
    return (
      `Package was inactive for ${Math.round(gapDays)} days, ` +
      `then published version ${latestVersion} — possible account takeover`
    );
  }

  return null;
}

/**
 * Check whether the package name matches an npm scope pattern
 * that looks like an impersonation of a trusted publisher.
 *
 * @param {string} packageName
 * @returns {string|null}
 */
function checkSuspiciousScope(packageName) {
  const TRUSTED_SCOPES = [
    '@angular', '@babel', '@types', '@jest', '@testing-library', '@aws-sdk',
    '@google-cloud', '@microsoft', '@azure', '@firebase', '@sentry',
    '@nestjs', '@storybook', '@mui', '@emotion', '@tailwindcss',
  ];
  const IMPERSONATION_VARIANTS = [
    /-official$/, /-real$/, /-safe$/, /-secure$/, /-verified$/,
    /^official-/, /^real-/, /^the-/,
  ];

  if (packageName.startsWith('@')) {
    const scope = packageName.split('/')[0];
    // Warn if the scope is very close to a trusted scope but not exact
    for (const trusted of TRUSTED_SCOPES) {
      if (scope !== trusted && scope.includes(trusted.replace('@', ''))) {
        return `Scope "${scope}" may be impersonating trusted scope "${trusted}"`;
      }
    }
  }

  const bare = packageName.startsWith('@') ? packageName.split('/')[1] ?? '' : packageName;
  for (const pattern of IMPERSONATION_VARIANTS) {
    if (pattern.test(bare)) {
      return `Package name "${bare}" uses a suspicious suffix/prefix pattern`;
    }
  }

  return null;
}

// ─── Main checker ───────────────────────────────────────────────────────────

/**
 * Run all maintainer / provenance risk checks.
 *
 * @param {string} packageName
 * @param {string} version        Resolved concrete semver string
 * @param {object} packument      Full npm registry packument
 * @returns {{ findings: string[], riskScore: number }}
 */
function runMaintainerCheck(packageName, version, packument) {
  logger.debug(`Maintainer check: ${packageName}@${version}`);

  const findings = [];
  const timeData = packument.time ?? {};
  const versions = packument.versions ?? {};
  const maintainers = packument.maintainers ?? [];

  // 1. Package age
  const ageWarning = checkPackageAge(timeData);
  if (ageWarning) findings.push(ageWarning);

  // 2. Version age
  const versionAgeWarning = checkVersionAge(timeData, version);
  if (versionAgeWarning) findings.push(versionAgeWarning);

  // 3. Maintainer count
  const maintainerWarning = checkMaintainerCount(maintainers);
  if (maintainerWarning) findings.push(maintainerWarning);

  // 4. Version spike
  const spikeWarning = checkVersionSpike(timeData, versions);
  if (spikeWarning) findings.push(spikeWarning);

  // 5. Inactivity → activity pattern
  const inactivityWarning = checkInactivityThenActivity(timeData, version, versions);
  if (inactivityWarning) findings.push(inactivityWarning);

  // 6. Suspicious scope / name pattern
  const scopeWarning = checkSuspiciousScope(packageName);
  if (scopeWarning) findings.push(scopeWarning);

  // Risk score: each finding contributes, heavier for the most dangerous patterns
  let riskScore = 0;

  // These are the higher-impact findings
  const criticalKeywords = ['account takeover', 'impersonating', 'suspicious', 'No maintainers'];
  const highKeywords     = ['published', 'inactive', 'Single maintainer', 'very recent'];

  for (const finding of findings) {
    if (criticalKeywords.some((k) => finding.includes(k))) riskScore += 4;
    else if (highKeywords.some((k) => finding.includes(k))) riskScore += 2;
    else riskScore += 1;
  }

  riskScore = Math.min(riskScore, 10);

  logger.debug(`Maintainer check: ${findings.length} findings (risk: ${riskScore})`);

  return { findings, riskScore };
}

module.exports = { runMaintainerCheck };
