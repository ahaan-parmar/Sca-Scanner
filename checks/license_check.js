'use strict';

/**
 * checks/license_check.js
 *
 * Analyses the declared license of an npm package for legal and security risks.
 *
 * Risk categories:
 *   NO_LICENSE     — No license declared; redistribution may be illegal          (HIGH)
 *   RESTRICTIVE    — AGPL, SSPL, CC-BY-NC; very restrictive for commercial use   (HIGH)
 *   COPYLEFT       — GPL-2/3, BUSL; strong copyleft obligations                  (MEDIUM)
 *   WEAK_COPYLEFT  — LGPL, MPL, EPL; weak copyleft, usually OK for libraries     (LOW)
 *   UNKNOWN        — Unrecognized SPDX expression                                 (LOW)
 *   PERMISSIVE     — MIT, ISC, Apache, BSD, etc.                                  (NONE)
 */

const config = require('../config.json');
const logger  = require('../utils/logger');

const { restrictive, copyleft, weak_copyleft, permissive } = config.license;

// Map risk category to numeric risk score contribution
const CATEGORY_SCORE = {
  NO_LICENSE:    8,
  RESTRICTIVE:   6,
  COPYLEFT:      3,
  WEAK_COPYLEFT: 1,
  UNKNOWN:       1,
  PERMISSIVE:    0,
};

// Human-readable descriptions for each category
const CATEGORY_DESC = {
  NO_LICENSE:    'No license declared — redistribution may not be legally permitted',
  RESTRICTIVE:   'Highly restrictive license — commercial use may be prohibited or require source disclosure',
  COPYLEFT:      'Strong copyleft license — derivative works must use the same license',
  WEAK_COPYLEFT: 'Weak copyleft license — dynamic linking/usage is generally permitted',
  UNKNOWN:       'Unrecognized license identifier — verify compatibility manually',
  PERMISSIVE:    'Permissive license — minimal restrictions on use and redistribution',
};

/**
 * Classify a license string into a risk category.
 *
 * @param {string} license  SPDX identifier or custom string
 * @returns {'NO_LICENSE'|'RESTRICTIVE'|'COPYLEFT'|'WEAK_COPYLEFT'|'UNKNOWN'|'PERMISSIVE'}
 */
function classifyLicense(license) {
  if (!license || license === 'UNKNOWN' || license.trim() === '') {
    return 'NO_LICENSE';
  }

  const normalized = license.trim();

  // Explicit UNLICENSED means deliberately no license
  if (normalized.toUpperCase() === 'UNLICENSED') {
    return 'NO_LICENSE';
  }

  // Check against known lists (exact match, then partial)
  const checkList = (list) => list.some(
    (l) => normalized === l || normalized.toUpperCase() === l.toUpperCase()
  );

  if (checkList(permissive))    return 'PERMISSIVE';
  if (checkList(restrictive))   return 'RESTRICTIVE';
  if (checkList(copyleft))      return 'COPYLEFT';
  if (checkList(weak_copyleft)) return 'WEAK_COPYLEFT';

  // Try partial matches for SPDX expressions like "GPL-3.0-or-later" or "MIT AND Apache-2.0"
  const upper = normalized.toUpperCase();

  if (restrictive.some((l) => upper.includes(l.toUpperCase()))) return 'RESTRICTIVE';
  if (copyleft.some((l)    => upper.includes(l.toUpperCase()))) return 'COPYLEFT';
  if (weak_copyleft.some((l) => upper.includes(l.toUpperCase()))) return 'WEAK_COPYLEFT';
  if (permissive.some((l)  => upper.includes(l.toUpperCase()))) return 'PERMISSIVE';

  return 'UNKNOWN';
}

/**
 * Run the license risk check.
 *
 * @param {string} license  License string from package metadata
 * @returns {{ findings: Array<{ type: string, detail: string, severity: string }>, riskScore: number, category: string }}
 */
function runLicenseCheck(license) {
  logger.debug(`License check: "${license}"`);

  const category = classifyLicense(license);
  const riskScore = CATEGORY_SCORE[category];
  const findings  = [];

  if (category !== 'PERMISSIVE') {
    const severityMap = {
      NO_LICENSE:    'HIGH',
      RESTRICTIVE:   'HIGH',
      COPYLEFT:      'MEDIUM',
      WEAK_COPYLEFT: 'LOW',
      UNKNOWN:       'LOW',
    };

    findings.push({
      type:     category,
      detail:   `${license || 'none'} — ${CATEGORY_DESC[category]}`,
      severity: severityMap[category],
    });
  }

  logger.debug(`License "${license}" → category: ${category}, riskScore: ${riskScore}`);

  return { findings, riskScore, category };
}

module.exports = { runLicenseCheck, classifyLicense, CATEGORY_DESC };
