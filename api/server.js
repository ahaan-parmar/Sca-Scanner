'use strict';

/**
 * api/server.js
 *
 * Endpoints:
 *   GET  /api/health
 *   POST /api/scan                     — single package scan
 *   POST /api/scan/batch               — package.json batch scan (SSE)
 *   GET  /api/projects                 — list all projects
 *   POST /api/projects                 — create project { name, githubUrl?, pkgJson? }
 *   GET  /api/projects/:id             — project + latest scan
 *   DELETE /api/projects/:id           — delete project
 *   POST /api/projects/:id/scan        — trigger scan (SSE), saves to DB
 *   GET  /api/projects/:id/history     — scan history
 *   GET  /api/badge/:id                — SVG risk badge
 */

const http    = require('http');
const https   = require('https');
const url     = require('url');
const path    = require('path');
const cron    = require('node-cron');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const { createClient } = require('@supabase/supabase-js');
const scanner = require('../core/scanner');

const PORT     = process.env.PORT || 3001;
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function setCORS(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      try { resolve(JSON.parse(raw)); }
      catch { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

function json(res, status, data) {
  setCORS(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function startSSE(res) {
  setCORS(res);
  res.writeHead(200, {
    'Content-Type':      'text/event-stream',
    'Cache-Control':     'no-cache',
    'Connection':        'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders?.();
}

function sendEvent(res, type, data) {
  res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);
}

function parseSpec(spec) {
  if (typeof spec === 'object' && spec !== null) return spec;
  if (spec.startsWith('@')) {
    const at = spec.indexOf('@', 1);
    return at === -1
      ? { name: spec, version: 'latest' }
      : { name: spec.slice(0, at), version: spec.slice(at + 1) };
  }
  const at = spec.indexOf('@');
  return at === -1
    ? { name: spec, version: 'latest' }
    : { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

// ─── Fetch package.json from a GitHub URL ────────────────────────────────────

function fetchRaw(rawUrl) {
  return new Promise((resolve, reject) => {
    https.get(rawUrl, (r) => {
      if (r.statusCode !== 200) return reject(new Error(`HTTP ${r.statusCode}`));
      let data = '';
      r.on('data', (c) => { data += c; });
      r.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Could not parse JSON')); }
      });
    }).on('error', reject);
  });
}

async function fetchGitHubPkgJson(githubUrl) {
  const match = githubUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
  if (!match) throw new Error('Invalid GitHub URL — expected https://github.com/owner/repo');
  const [, owner, repo] = match;
  try {
    return await fetchRaw(`https://raw.githubusercontent.com/${owner}/${repo}/main/package.json`);
  } catch {
    return await fetchRaw(`https://raw.githubusercontent.com/${owner}/${repo}/master/package.json`);
  }
}

// ─── Core scan runner (saves results to DB, optionally streams via SSE) ───────

async function runProjectScan(projectId, pkgJson, sseRes = null) {
  const deps    = { ...pkgJson.dependencies, ...pkgJson.devDependencies };
  const entries = Object.entries(deps);

  if (sseRes) {
    startSSE(sseRes);
    sendEvent(sseRes, 'start', { total: entries.length, name: pkgJson.name || 'project' });
  }

  const results = [];
  const errors  = [];

  for (let i = 0; i < entries.length; i++) {
    const [name, versionRange] = entries[i];
    const version = String(versionRange).replace(/^[^0-9@a-zA-Z]*/, '').split(' ')[0] || 'latest';

    if (sseRes) sendEvent(sseRes, 'scanning', { package: name, version, index: i + 1, total: entries.length });

    try {
      const result = await scanner.scan(name, version, { diffMode: false });
      results.push(result);
      if (sseRes) sendEvent(sseRes, 'result', { result });
    } catch (err) {
      errors.push({ package: name, error: err.message });
      if (sseRes) sendEvent(sseRes, 'error', { package: name, error: err.message });
    }
  }

  const byLevel = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const r of results) byLevel[r.risk.level] = (byLevel[r.risk.level] ?? 0) + 1;
  const summary = { total: results.length, errors: errors.length, byLevel };

  await supabase.from('scans').insert({ project_id: projectId, summary, results });
  await supabase.from('projects').update({ last_scanned_at: new Date().toISOString() }).eq('id', projectId);

  if (sseRes) {
    sendEvent(sseRes, 'done', { summary, results, errors });
    sseRes.end();
  }

  return { summary, results, errors };
}

// ─── Rate limiter (simple sliding window per IP) ─────────────────────────────

const rateLimitMap = new Map(); // ip → [timestamps]
const RATE_LIMIT    = 30;       // max requests
const RATE_WINDOW   = 60_000;   // per 60 seconds

function isRateLimited(ip) {
  const now = Date.now();
  const hits = (rateLimitMap.get(ip) ?? []).filter((t) => now - t < RATE_WINDOW);
  hits.push(now);
  rateLimitMap.set(ip, hits);
  return hits.length > RATE_LIMIT;
}

// ─── Nightly rescan (midnight every day) ─────────────────────────────────────

cron.schedule('0 0 * * *', async () => {
  const { data: projects } = await supabase
    .from('projects')
    .select('*')
    .not('pkg_json', 'is', null);

  console.log(`[cron] Nightly rescan — ${projects?.length ?? 0} project(s)`);
  for (const p of (projects ?? [])) {
    try {
      await runProjectScan(p.id, p.pkg_json);
      console.log(`[cron]   ✓ ${p.name}`);
    } catch (err) {
      console.error(`[cron]   ✗ ${p.name}: ${err.message}`);
    }
  }
});

// ─── Badge SVG ────────────────────────────────────────────────────────────────

function buildBadge(summary) {
  let label = 'no scans';
  let color = '#6b7280';

  if (summary) {
    const { byLevel } = summary;
    if (byLevel.CRITICAL > 0)    { label = `${byLevel.CRITICAL} critical`; color = '#dc2626'; }
    else if (byLevel.HIGH > 0)   { label = `${byLevel.HIGH} high`;         color = '#ea580c'; }
    else if (byLevel.MEDIUM > 0) { label = `${byLevel.MEDIUM} medium`;     color = '#d97706'; }
    else                          { label = 'secure';                        color = '#16a34a'; }
  }

  const leftW  = 72;
  const rightW = Math.max(Math.ceil(label.length * 6.5) + 16, 52);
  const W      = leftW + rightW;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="${W}" height="20" fill="#555"/>
  <rect rx="3" x="${leftW}" width="${rightW}" height="20" fill="${color}"/>
  <rect width="${W}" height="20" rx="3" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="${leftW / 2}" y="15" fill="#010101" fill-opacity=".3">safe-npm</text>
    <text x="${leftW / 2}" y="14">safe-npm</text>
    <text x="${leftW + rightW / 2}" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="${leftW + rightW / 2}" y="14">${label}</text>
  </g>
</svg>`;
}

// ─── Router ───────────────────────────────────────────────────────────────────

async function handle(req, res) {
  const { pathname } = url.parse(req.url);

  if (req.method === 'OPTIONS') {
    setCORS(res); res.writeHead(204); res.end(); return;
  }

  // Health
  if (req.method === 'GET' && pathname === '/api/health') {
    return json(res, 200, { status: 'ok', version: require('../package.json').version });
  }

  // Single scan
  if (req.method === 'POST' && (pathname === '/api/scan' || pathname === '/api/scan/batch' || pathname === '/api/scan/policy')) {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() ?? req.socket.remoteAddress ?? 'unknown';
    if (isRateLimited(clientIp)) {
      return json(res, 429, { error: 'Rate limit exceeded — max 30 scan requests per minute.' });
    }
  }

  if (req.method === 'POST' && pathname === '/api/scan') {
    let body;
    try { body = await readBody(req); } catch (e) { return json(res, 400, { error: e.message }); }
    const { name, version } = parseSpec(body.package ?? body);
    try {
      return json(res, 200, await scanner.scan(name, version || 'latest', { diffMode: true }));
    } catch (e) { return json(res, 400, { error: e.message }); }
  }

  // Batch scan (one-off, no DB)
  if (req.method === 'POST' && pathname === '/api/scan/batch') {
    let body;
    try { body = await readBody(req); } catch (e) { return json(res, 400, { error: e.message }); }
    const pkgJson = body.pkgJson;
    if (!pkgJson || typeof pkgJson !== 'object') return json(res, 400, { error: 'Expected { pkgJson }' });

    const deps    = { ...pkgJson.dependencies, ...pkgJson.devDependencies };
    const entries = Object.entries(deps);
    startSSE(res);
    sendEvent(res, 'start', { total: entries.length, name: pkgJson.name || 'project' });

    const results = [], errors = [];
    for (let i = 0; i < entries.length; i++) {
      const [name, vr] = entries[i];
      const version = String(vr).replace(/^[^0-9@a-zA-Z]*/, '').split(' ')[0] || 'latest';
      sendEvent(res, 'scanning', { package: name, version, index: i + 1, total: entries.length });
      try {
        const result = await scanner.scan(name, version, { diffMode: false });
        results.push(result);
        sendEvent(res, 'result', { result });
      } catch (err) {
        errors.push({ package: name, error: err.message });
        sendEvent(res, 'error', { package: name, error: err.message });
      }
    }
    const byLevel = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    for (const r of results) byLevel[r.risk.level] = (byLevel[r.risk.level] ?? 0) + 1;
    sendEvent(res, 'done', { summary: { total: results.length, errors: errors.length, byLevel }, results, errors });
    res.end();
    return;
  }

  // Policy check (CI/CD gate) — POST /api/scan/policy
  if (req.method === 'POST' && pathname === '/api/scan/policy') {
    let body;
    try { body = await readBody(req); } catch (e) { return json(res, 400, { error: e.message }); }
    const { pkgJson, policy } = body;
    if (!pkgJson || typeof pkgJson !== 'object') return json(res, 400, { error: 'Expected { pkgJson, policy }' });

    const failOn = (policy?.failOn ?? 'CRITICAL').toUpperCase();
    const warnOn = (policy?.warnOn ?? 'HIGH').toUpperCase();
    const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const failIdx = LEVELS.indexOf(failOn);
    const warnIdx = LEVELS.indexOf(warnOn);

    const deps    = { ...pkgJson.dependencies, ...pkgJson.devDependencies };
    const entries = Object.entries(deps);
    const results = [], errors = [];

    for (const [name, vr] of entries) {
      const version = String(vr).replace(/^[^0-9@a-zA-Z]*/, '').split(' ')[0] || 'latest';
      try {
        results.push(await scanner.scan(name, version, { diffMode: false }));
      } catch (err) {
        errors.push({ package: name, error: err.message });
      }
    }

    const violations = results.filter((r) => LEVELS.indexOf(r.risk.level) >= failIdx)
      .map((r) => ({ package: r.package, version: r.version, level: r.risk.level, score: r.risk.score }));
    const warnings = results.filter((r) => {
      const idx = LEVELS.indexOf(r.risk.level);
      return idx >= warnIdx && idx < failIdx;
    }).map((r) => ({ package: r.package, version: r.version, level: r.risk.level, score: r.risk.score }));

    const byLevel = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    for (const r of results) byLevel[r.risk.level] = (byLevel[r.risk.level] ?? 0) + 1;

    return json(res, 200, {
      pass:       violations.length === 0,
      policy:     { failOn, warnOn },
      violations,
      warnings,
      summary:    { total: results.length, errors: errors.length, byLevel },
      errors,
    });
  }

  // List projects
  if (req.method === 'GET' && pathname === '/api/projects') {
    const { data: rows, error } = await supabase
      .from('projects_with_latest_scan')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) return json(res, 500, { error: error.message });
    return json(res, 200, rows);
  }

  // Create project
  if (req.method === 'POST' && pathname === '/api/projects') {
    let body;
    try { body = await readBody(req); } catch (e) { return json(res, 400, { error: e.message }); }
    const { name, githubUrl, pkgJson } = body;
    if (!name) return json(res, 400, { error: 'name is required' });

    let resolved = pkgJson || null;
    if (githubUrl && !resolved) {
      try { resolved = await fetchGitHubPkgJson(githubUrl); }
      catch (e) {
        return json(res, 400, {
          error: `Could not fetch package.json from GitHub: ${e.message}. Make sure the repo is public and has a package.json at the root.`,
        });
      }
    }

    const { data, error } = await supabase
      .from('projects')
      .insert({ name, github_url: githubUrl || null, pkg_json: resolved })
      .select('id, name, github_url')
      .single();

    if (error) return json(res, 500, { error: error.message });
    return json(res, 201, { id: data.id, name: data.name, githubUrl: data.github_url });
  }

  // Project by id
  // Export latest scan results as JSON/CSV
  const exportRoute = pathname.match(/^\/api\/projects\/(\d+)\/export$/);
  if (exportRoute && req.method === 'GET') {
    const id = Number(exportRoute[1]);
    const format = url.parse(req.url, true).query.format ?? 'json';
    const { data: latest } = await supabase
      .from('scans').select('*').eq('project_id', id)
      .order('scanned_at', { ascending: false }).limit(1).maybeSingle();
    if (!latest) return json(res, 404, { error: 'No scans found' });

    if (format === 'csv') {
      const rows = (latest.results ?? []).map((r) => {
        const cves = Array.isArray(r.findings?.cve) ? r.findings.cve.map((c) => c.id).join('; ') : '';
        return [r.package, r.version, r.risk?.level, r.risk?.score, cves,
          r.findings?.license?.license ?? '', r.findings?.typosquat?.suspicious ? 'yes' : 'no'].join(',');
      });
      const csv = ['package,version,risk_level,risk_score,cves,license,typosquat', ...rows].join('\n');
      setCORS(res);
      res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="scan-${id}.csv"` });
      return res.end(csv);
    }

    setCORS(res);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="scan-${id}.json"` });
    return res.end(JSON.stringify({ scanned_at: latest.scanned_at, summary: latest.summary, results: latest.results }, null, 2));
  }

  // SBOM export (CycloneDX 1.5)
  const sbomRoute = pathname.match(/^\/api\/projects\/(\d+)\/sbom$/);
  if (sbomRoute && req.method === 'GET') {
    const id = Number(sbomRoute[1]);
    const { data: proj } = await supabase.from('projects').select('*').eq('id', id).single();
    if (!proj) return json(res, 404, { error: 'Not found' });
    const { data: latest } = await supabase
      .from('scans').select('*').eq('project_id', id)
      .order('scanned_at', { ascending: false }).limit(1).maybeSingle();
    if (!latest) return json(res, 404, { error: 'No scans found for this project' });

    const components = (latest.results ?? []).map((r) => {
      const purl = `pkg:npm/${encodeURIComponent(r.package)}@${r.version}`;
      const comp = {
        type: 'library',
        name: r.package,
        version: r.version,
        purl,
        properties: [
          { name: 'safe-npm:riskLevel', value: r.risk?.level ?? 'UNKNOWN' },
          { name: 'safe-npm:riskScore', value: String(r.risk?.score ?? 0) },
        ],
      };
      if (r.findings?.license?.license) {
        comp.licenses = [{ license: { id: r.findings.license.license } }];
      }
      return comp;
    });

    const allVulns = [];
    for (const r of (latest.results ?? [])) {
      const cves = Array.isArray(r.findings?.cve) ? r.findings.cve : [];
      const purl = `pkg:npm/${encodeURIComponent(r.package)}@${r.version}`;
      for (const cve of cves) {
        allVulns.push({
          id: cve.id,
          source: { name: 'OSV', url: cve.url },
          ratings: [{ severity: (cve.severity ?? 'unknown').toLowerCase(), score: cve.cvssScore ?? 0, method: 'CVSSv3' }],
          description: cve.summary,
          published: cve.published,
          updated: cve.modified,
          recommendation: cve.fixedIn ? `Upgrade to ${r.package}@${cve.fixedIn}` : undefined,
          affects: [{ ref: purl }],
        });
      }
    }

    const sbom = {
      bomFormat:    'CycloneDX',
      specVersion:  '1.5',
      serialNumber: `urn:uuid:${require('crypto').randomUUID()}`,
      version:      1,
      metadata: {
        timestamp: latest.scanned_at,
        tools: [{ vendor: 'safe-npm', name: 'safe-npm', version: require('../package.json').version }],
        component: { type: 'application', name: proj.name },
      },
      components,
      vulnerabilities: allVulns,
    };

    setCORS(res);
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="${proj.name}-sbom.cdx.json"`,
    });
    return res.end(JSON.stringify(sbom, null, 2));
  }

  const byId       = pathname.match(/^\/api\/projects\/(\d+)$/);
  const scanRoute  = pathname.match(/^\/api\/projects\/(\d+)\/scan$/);
  const histRoute  = pathname.match(/^\/api\/projects\/(\d+)\/history$/);
  const badgeRoute = pathname.match(/^\/api\/badge\/(\d+)$/);

  if (byId) {
    const id = Number(byId[1]);

    if (req.method === 'GET') {
      const { data: p } = await supabase.from('projects').select('*').eq('id', id).single();
      if (!p) return json(res, 404, { error: 'Not found' });
      const { data: latest } = await supabase
        .from('scans')
        .select('*')
        .eq('project_id', id)
        .order('scanned_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      return json(res, 200, {
        id: p.id, name: p.name, github_url: p.github_url,
        created_at: p.created_at, last_scanned_at: p.last_scanned_at,
        latestScan: latest ? {
          id: latest.id, scanned_at: latest.scanned_at,
          summary: latest.summary,
          results: latest.results,
        } : null,
      });
    }

    if (req.method === 'DELETE') {
      await supabase.from('projects').delete().eq('id', id);
      return json(res, 200, { ok: true });
    }
  }

  if (scanRoute && req.method === 'POST') {
    const id = Number(scanRoute[1]);
    const { data: p } = await supabase.from('projects').select('*').eq('id', id).single();
    if (!p)           return json(res, 404, { error: 'Not found' });
    if (!p.pkg_json)  return json(res, 400, { error: 'No package.json stored for this project' });
    await runProjectScan(id, p.pkg_json, res);
    return;
  }

  if (histRoute && req.method === 'GET') {
    const id = Number(histRoute[1]);
    const { data: rows } = await supabase
      .from('scans')
      .select('id, scanned_at, summary')
      .eq('project_id', id)
      .order('scanned_at', { ascending: true });
    return json(res, 200, rows ?? []);
  }

  if (badgeRoute && req.method === 'GET') {
    const id = Number(badgeRoute[1]);
    const { data: latest } = await supabase
      .from('scans')
      .select('summary')
      .eq('project_id', id)
      .order('scanned_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    const svg = buildBadge(latest?.summary ?? null);
    setCORS(res);
    res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-cache, no-store' });
    res.end(svg);
    return;
  }

  json(res, 404, { error: 'Not found' });
}

// ─── Start ────────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  try { await handle(req, res); }
  catch (err) {
    console.error('Unhandled error:', err);
    try { json(res, 500, { error: 'Internal server error' }); } catch {}
  }
});

server.listen(PORT, () => {
  console.log(`\n🔒 safe-npm API  →  http://localhost:${PORT}`);
  console.log(`   Health check   →  http://localhost:${PORT}/api/health\n`);
});

module.exports = server;
