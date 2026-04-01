'use strict';

/**
 * core/fetcher.js
 *
 * Responsible for all outbound HTTP calls:
 *   - npm registry metadata
 *   - OSV.dev vulnerability API
 *
 * Also provides a simple file-based cache with TTL to avoid
 * hammering external APIs during repeated scans.
 */

const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const os    = require('os');

const config = require('../config.json');
const logger = require('../utils/logger');

// ─── Cache helpers ──────────────────────────────────────────────────────────

const CACHE_DIR = path.join(os.homedir(), config.cache.dir || '.safe-npm-cache');

function ensureCacheDir() {
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  }
}

function cacheKey(key) {
  // Sanitize key to be a safe filename
  return key.replace(/[^a-zA-Z0-9._@-]/g, '_') + '.json';
}

function readCache(key) {
  if (!config.cache.enabled) return null;
  try {
    ensureCacheDir();
    const file = path.join(CACHE_DIR, cacheKey(key));
    if (!fs.existsSync(file)) return null;
    const { ts, data } = JSON.parse(fs.readFileSync(file, 'utf8'));
    const age = (Date.now() - ts) / 1000;
    if (age > config.cache.ttl_seconds) {
      fs.unlinkSync(file);
      return null;
    }
    logger.debug(`Cache HIT for ${key} (age: ${Math.round(age)}s)`);
    return data;
  } catch {
    return null;
  }
}

function writeCache(key, data) {
  if (!config.cache.enabled) return;
  try {
    ensureCacheDir();
    const file = path.join(CACHE_DIR, cacheKey(key));
    fs.writeFileSync(file, JSON.stringify({ ts: Date.now(), data }), 'utf8');
  } catch (err) {
    logger.debug(`Cache write failed for ${key}: ${err.message}`);
  }
}

function clearCache() {
  try {
    if (fs.existsSync(CACHE_DIR)) {
      for (const f of fs.readdirSync(CACHE_DIR)) {
        fs.unlinkSync(path.join(CACHE_DIR, f));
      }
    }
    return true;
  } catch {
    return false;
  }
}

// ─── HTTP helpers ───────────────────────────────────────────────────────────

/**
 * Generic HTTP/HTTPS request helper.
 * Returns parsed JSON response body, or throws on non-2xx.
 *
 * @param {string}  url
 * @param {object}  [opts]         Options passed to https.request
 * @param {string}  [opts.method]  'GET'|'POST' etc.
 * @param {object}  [opts.headers]
 * @param {string}  [body]         Request body string (for POST)
 * @returns {Promise<any>}
 */
function httpRequest(url, opts = {}, body = null) {
  return new Promise((resolve, reject) => {
    const isHttps = url.startsWith('https://');
    const transport = isHttps ? https : http;

    const options = {
      method: opts.method || 'GET',
      headers: {
        'User-Agent': `safe-npm/${require('../package.json').version}`,
        'Accept': 'application/json',
        ...opts.headers,
      },
      timeout: 15000,
    };

    const req = transport.request(url, options, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        if (res.statusCode === 404) {
          return reject(new Error(`NOT_FOUND: ${url}`));
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        }
        try {
          resolve(JSON.parse(raw));
        } catch {
          resolve(raw);
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request timed out: ${url}`));
    });

    req.on('error', (err) => {
      reject(new Error(`Network error fetching ${url}: ${err.message}`));
    });

    if (body) req.write(body);
    req.end();
  });
}

// ─── npm Registry ───────────────────────────────────────────────────────────

/**
 * Fetch full package metadata from the npm registry.
 * Uses the packument format (all versions, all metadata).
 *
 * @param {string} packageName
 * @returns {Promise<object>}  Full packument
 */
async function fetchPackageMetadata(packageName) {
  const cacheKeyStr = `npm_meta_${packageName}`;
  const cached = readCache(cacheKeyStr);
  if (cached) return cached;

  const url = `${config.registry}/${encodeURIComponent(packageName).replace('%40', '@')}`;
  logger.debug(`Fetching npm metadata: ${url}`);

  const data = await httpRequest(url);
  writeCache(cacheKeyStr, data);
  return data;
}

/**
 * Fetch metadata for a specific version of a package.
 *
 * @param {string} packageName
 * @param {string} version      semver string or 'latest'
 * @returns {Promise<object>}
 */
async function fetchVersionMetadata(packageName, version) {
  const cacheKeyStr = `npm_ver_${packageName}_${version}`;
  const cached = readCache(cacheKeyStr);
  if (cached) return cached;

  const url = `${config.registry}/${encodeURIComponent(packageName).replace('%40', '@')}/${version}`;
  logger.debug(`Fetching version metadata: ${url}`);

  const data = await httpRequest(url);
  writeCache(cacheKeyStr, data);
  return data;
}

/**
 * Resolve 'latest' or a dist-tag to a concrete semver string.
 *
 * @param {object} packument
 * @param {string} version
 * @returns {string}
 */
function resolveVersion(packument, version) {
  if (!version || version === 'latest') {
    return packument['dist-tags']?.latest ?? Object.keys(packument.versions || {}).pop();
  }
  // Check if it's a dist-tag (e.g. "next", "beta")
  if (packument['dist-tags']?.[version]) {
    return packument['dist-tags'][version];
  }
  // Check it exists as a concrete version
  if (packument.versions?.[version]) {
    return version;
  }
  throw new Error(`Version "${version}" not found for package "${packument.name}"`);
}

// ─── OSV Vulnerability API ──────────────────────────────────────────────────

/**
 * Query OSV.dev for vulnerabilities affecting a specific package@version.
 *
 * @param {string} packageName
 * @param {string} version     Concrete semver string
 * @returns {Promise<Array>}   Array of OSV vulnerability objects
 */
async function fetchOSVVulnerabilities(packageName, version) {
  const cacheKeyStr = `osv_${packageName}_${version}`;
  const cached = readCache(cacheKeyStr);
  if (cached) return cached;

  const payload = JSON.stringify({
    package: { name: packageName, ecosystem: 'npm' },
    version,
  });

  logger.debug(`Querying OSV.dev for ${packageName}@${version}`);

  const data = await httpRequest(
    config.osv_api,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    },
    payload
  );

  const vulns = data.vulns ?? [];
  writeCache(cacheKeyStr, vulns);
  return vulns;
}

/**
 * Fetch the raw source of an install script from the npm registry tarball
 * for static analysis. We don't download the whole tarball — we just look at
 * the scripts section of the package.json for each version.
 *
 * @param {object} versionMeta  Version-specific metadata from the packument
 * @returns {object}            { preinstall, postinstall, install, ... }
 */
function extractScripts(versionMeta) {
  return versionMeta?.scripts ?? {};
}

// ─── npm Download Stats ──────────────────────────────────────────────────────

/**
 * Fetch weekly download count for a package from the npm downloads API.
 * Returns null on failure (non-critical).
 *
 * @param {string} packageName
 * @returns {Promise<number|null>}
 */
async function fetchNpmDownloads(packageName) {
  const cacheKeyStr = `npm_dl_${packageName}`;
  const cached = readCache(cacheKeyStr);
  if (cached !== null) return cached;

  try {
    const encoded = encodeURIComponent(packageName).replace('%40', '@');
    const url = `https://api.npmjs.org/downloads/point/last-week/${encoded}`;
    logger.debug(`Fetching download stats: ${url}`);
    const data = await httpRequest(url);
    const count = data?.downloads ?? null;
    writeCache(cacheKeyStr, count);
    return count;
  } catch (err) {
    logger.debug(`Download stats failed for ${packageName}: ${err.message}`);
    return null;
  }
}

// ─── GitHub Stats ────────────────────────────────────────────────────────────

/**
 * Extract owner/repo from a GitHub repository URL.
 * Handles: https://github.com/owner/repo, git+https://..., git://..., etc.
 *
 * @param {string} repoUrl
 * @returns {{ owner: string, repo: string }|null}
 */
function parseGitHubRepo(repoUrl) {
  if (!repoUrl) return null;
  const match = repoUrl.match(/github\.com[/:]([^/]+)\/([^/.#]+)/);
  if (!match) return null;
  return { owner: match[1], repo: match[2].replace(/\.git$/, '') };
}

/**
 * Fetch public GitHub repository stats (stars, forks, open issues, last push).
 * No authentication required for public repos (60 req/hour rate limit).
 * Returns null on failure (non-critical).
 *
 * @param {string} repoUrl  GitHub repository URL from npm packument
 * @returns {Promise<{ stars: number, forks: number, openIssues: number, daysSinceLastPush: number, isArchived: boolean }|null>}
 */
async function fetchGitHubStats(repoUrl) {
  const parsed = parseGitHubRepo(repoUrl);
  if (!parsed) return null;

  const { owner, repo } = parsed;
  const cacheKeyStr = `gh_stats_${owner}_${repo}`;
  const cached = readCache(cacheKeyStr);
  if (cached !== null) return cached;

  try {
    const url = `https://api.github.com/repos/${owner}/${repo}`;
    logger.debug(`Fetching GitHub stats: ${url}`);
    const data = await httpRequest(url, {
      headers: {
        'User-Agent': `safe-npm/${require('../package.json').version}`,
        'Accept': 'application/vnd.github.v3+json',
      },
    });

    const lastPush = data.pushed_at ? new Date(data.pushed_at) : null;
    const daysSinceLastPush = lastPush
      ? Math.floor((Date.now() - lastPush.getTime()) / (1000 * 60 * 60 * 24))
      : null;

    const stats = {
      stars:             data.stargazers_count ?? 0,
      forks:             data.forks_count ?? 0,
      openIssues:        data.open_issues_count ?? 0,
      daysSinceLastPush,
      isArchived:        data.archived ?? false,
      hasDescription:    !!(data.description),
      homepage:          data.homepage ?? null,
      language:          data.language ?? null,
      owner,
      repo,
    };

    writeCache(cacheKeyStr, stats);
    return stats;
  } catch (err) {
    logger.debug(`GitHub stats failed for ${owner}/${repo}: ${err.message}`);
    return null;
  }
}

// ─── Exports ────────────────────────────────────────────────────────────────

module.exports = {
  fetchPackageMetadata,
  fetchVersionMetadata,
  fetchOSVVulnerabilities,
  fetchNpmDownloads,
  fetchGitHubStats,
  parseGitHubRepo,
  resolveVersion,
  extractScripts,
  clearCache,
};
