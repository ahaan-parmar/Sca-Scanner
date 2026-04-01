'use strict';

/**
 * core/scanner.js
 *
 * Orchestrates all security checks for a given package@version.
 * Returns a unified scan result object consumed by the CLI and risk engine.
 *
 * Flow:
 *   1. Fetch full packument from npm registry
 *   2. Resolve exact version
 *   3. Run all checks in parallel (CVE, typosquat, script, maintainer)
 *   4. Feed results to risk_engine → final score + level
 *   5. Return unified result
 */

const fetcher        = require('./fetcher');
const riskEngine     = require('./risk_engine');
const cveCheck       = require('../checks/cve_check');
const typosquatCheck = require('../checks/typosquat_check');
const scriptCheck    = require('../checks/script_check');
const maintainerCheck  = require('../checks/maintainer_check');
const licenseCheck   = require('../checks/license_check');
const popularityCheck = require('../checks/popularity_check');
const logger         = require('../utils/logger');

// ─── Version diff helper ───────────────────────────────────────────────────

/**
 * Compare scripts between two versions to flag newly added install hooks.
 * Returns an array of warning strings.
 *
 * @param {object} prevScripts
 * @param {object} currScripts
 * @returns {string[]}
 */
function diffScripts(prevScripts = {}, currScripts = {}) {
  const warnings = [];
  const prevHooks = new Set(Object.keys(prevScripts));
  const currHooks = new Set(Object.keys(currScripts));

  for (const hook of currHooks) {
    if (!prevHooks.has(hook)) {
      warnings.push(`New script hook added in this version: "${hook}" → ${currScripts[hook]}`);
    } else if (prevScripts[hook] !== currScripts[hook]) {
      warnings.push(`Script hook "${hook}" changed between versions`);
    }
  }

  for (const hook of prevHooks) {
    if (!currHooks.has(hook)) {
      warnings.push(`Script hook "${hook}" was removed in this version`);
    }
  }

  return warnings;
}

// ─── Scan a single package ─────────────────────────────────────────────────

/**
 * Scan a package for security risks.
 *
 * @param {string}  packageName     e.g. "axios"
 * @param {string}  [requestedVersion]  e.g. "0.21.1" or "latest" (default)
 * @param {object}  [opts]
 * @param {boolean} [opts.diffMode]  Whether to run version diff analysis
 * @returns {Promise<ScanResult>}
 */
async function scan(packageName, requestedVersion = 'latest', opts = {}) {
  logger.info(`Scanning ${packageName}@${requestedVersion || 'latest'} ...`);

  // ── 1. Fetch packument ─────────────────────────────────────────────────
  let packument;
  try {
    packument = await fetcher.fetchPackageMetadata(packageName);
  } catch (err) {
    if (err.message.startsWith('NOT_FOUND')) {
      throw new Error(`Package "${packageName}" not found on npm registry`);
    }
    throw err;
  }

  // ── 2. Resolve version ─────────────────────────────────────────────────
  let version;
  try {
    version = fetcher.resolveVersion(packument, requestedVersion);
  } catch (err) {
    throw new Error(`Version resolution failed: ${err.message}`);
  }

  logger.debug(`Resolved version: ${version}`);

  const versionMeta = packument.versions?.[version];
  if (!versionMeta) {
    throw new Error(`Version metadata not available for ${packageName}@${version}`);
  }

  const scripts = fetcher.extractScripts(versionMeta);

  // ── 3. Run all checks in parallel ─────────────────────────────────────
  logger.debug('Running security checks in parallel...');

  const license = versionMeta.license ?? packument.license ?? 'UNKNOWN';

  const [cveResult, scriptResult, maintainerResult, popularityResult] = await Promise.all([
    cveCheck.runCveCheck(packageName, version),
    Promise.resolve(scriptCheck.runScriptCheck(scripts)),
    Promise.resolve(maintainerCheck.runMaintainerCheck(packageName, version, packument)),
    popularityCheck.runPopularityCheck(packageName, packument),
  ]);

  // Typosquat and license are synchronous
  const typosquatResult = typosquatCheck.runTyposquatCheck(packageName);
  const licenseResult   = licenseCheck.runLicenseCheck(license);

  // ── 4. Version diff analysis (optional) ───────────────────────────────
  const scriptDiffWarnings = [];
  if (opts.diffMode) {
    const allVersions = Object.keys(packument.versions ?? {});
    const currentIdx  = allVersions.indexOf(version);
    if (currentIdx > 0) {
      const prevVersion = allVersions[currentIdx - 1];
      const prevMeta    = packument.versions[prevVersion];
      const prevScripts = fetcher.extractScripts(prevMeta);
      const diffs       = diffScripts(prevScripts, scripts);
      scriptDiffWarnings.push(...diffs);
      if (diffs.length > 0) {
        logger.debug(`Version diff: ${diffs.length} script changes detected`);
      }
    }
  }

  // ── 5. Aggregate risk score ────────────────────────────────────────────
  const risk = riskEngine.computeRisk({
    cveScore:        cveResult.riskScore,
    scriptScore:     scriptResult.riskScore,
    typosquatScore:  typosquatResult.riskScore,
    maintainerScore: maintainerResult.riskScore,
    licenseScore:    licenseResult.riskScore,
  });

  // ── 6. Build unified result ────────────────────────────────────────────
  /** @type {ScanResult} */
  const result = {
    package:   packageName,
    version,
    requestedVersion: requestedVersion || 'latest',
    scannedAt: new Date().toISOString(),

    risk,

    findings: {
      cve:        cveResult.findings,
      scripts:    scriptResult.findings,
      typosquat:  typosquatResult.findings,
      maintainer: maintainerResult.findings,
      license:    licenseResult.findings,
      scriptDiff: scriptDiffWarnings,
    },

    meta: {
      description:  packument.description ?? '',
      homepage:     packument.homepage ?? '',
      repository:   packument.repository?.url ?? '',
      license:      license,
      maintainers:  packument.maintainers ?? [],
      dependencies: Object.keys(versionMeta.dependencies ?? {}).length,
      devDeps:      Object.keys(versionMeta.devDependencies ?? {}).length,
      scripts:      Object.keys(scripts),
      published:    packument.time?.[version] ?? null,
      created:      packument.time?.created ?? null,
    },

    popularity: {
      findings:  popularityResult.findings,
      data:      popularityResult.data,
      riskScore: popularityResult.riskScore,
    },
  };

  logger.debug(`Scan complete: ${risk.level} (${risk.score})`);
  return result;
}

// ─── Scan a package.json file ──────────────────────────────────────────────

/**
 * Scan all dependencies listed in a package.json file.
 * Used for CI/CD mode: `safe-npm scan package.json --fail-on high`
 *
 * @param {string} filePath
 * @param {object} [opts]
 * @returns {Promise<{ results: ScanResult[], summary: object }>}
 */
async function scanPackageFile(filePath, opts = {}) {
  const fs   = require('fs');
  const path = require('path');

  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  let pkgJson;
  try {
    pkgJson = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    throw new Error(`Failed to parse ${filePath} as JSON`);
  }

  const deps = {
    ...pkgJson.dependencies,
    ...pkgJson.devDependencies,
  };

  const entries = Object.entries(deps);
  if (entries.length === 0) {
    logger.info('No dependencies found in package.json');
    return { results: [], summary: { total: 0, byLevel: {} } };
  }

  logger.info(`Scanning ${entries.length} packages from ${path.basename(filePath)}...`);

  const results = [];
  const errors  = [];

  // Scan sequentially to be polite to APIs
  for (const [name, versionRange] of entries) {
    // Strip semver range operators to get a concrete version hint
    const versionHint = versionRange
      .replace(/^[^0-9@a-zA-Z]*/,'')  // strip ^, ~, >=, etc.
      .split(' ')[0]                    // take first token
      || 'latest';

    try {
      const result = await scan(name, versionHint, opts);
      results.push(result);
    } catch (err) {
      logger.warn(`Skipping ${name}: ${err.message}`);
      errors.push({ package: name, error: err.message });
    }
  }

  const byLevel = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const r of results) {
    byLevel[r.risk.level] = (byLevel[r.risk.level] ?? 0) + 1;
  }

  const summary = {
    total:   results.length,
    errors:  errors.length,
    byLevel,
  };

  return { results, errors, summary };
}

module.exports = { scan, scanPackageFile };
