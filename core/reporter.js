'use strict';

/**
 * core/reporter.js
 *
 * Generates a self-contained, beautiful HTML security report from a ScanResult.
 * The output is a single HTML file with embedded CSS, inline Chart.js (CDN),
 * and all scan data baked in as a JSON constant — no server required.
 *
 * Usage:
 *   const reporter = require('./core/reporter');
 *   const filePath = reporter.writeReport(result, './scan-report.html');
 */

const fs   = require('fs');
const path = require('path');
const { formatCount } = require('../checks/popularity_check');

// ─── Helpers ─────────────────────────────────────────────────────────────────

function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDate(iso) {
  if (!iso) return 'N/A';
  try {
    return new Date(iso).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  } catch { return iso; }
}

function levelColor(level) {
  return { LOW: '#10b981', MEDIUM: '#f59e0b', HIGH: '#ef4444', CRITICAL: '#7c3aed' }[level] ?? '#6b7280';
}

function severityColor(sev) {
  const s = (sev ?? '').toUpperCase();
  return { LOW: '#10b981', MEDIUM: '#f59e0b', HIGH: '#ef4444', CRITICAL: '#7c3aed', UNKNOWN: '#6b7280' }[s] ?? '#6b7280';
}

// ─── HTML Template ────────────────────────────────────────────────────────────

function buildHtml(result) {
  const { package: pkg, version, scannedAt, risk, findings, meta } = result;
  const popularity = result.popularity ?? { data: {}, findings: [] };
  const licenseFindings = findings.license ?? [];
  const lc = levelColor(risk.level);
  const b  = risk.breakdown;

  // Score breakdown data for chart
  const breakdownLabels  = ['CVE', 'Scripts', 'Typosquat', 'Maintainer', 'License'];
  const breakdownWeighted = [
    b.cve?.weighted ?? 0,
    b.script?.weighted ?? 0,
    b.typosquat?.weighted ?? 0,
    b.maintainer?.weighted ?? 0,
    b.license?.weighted ?? 0,
  ];
  const breakdownRaw = [
    b.cve?.raw ?? 0,
    b.script?.raw ?? 0,
    b.typosquat?.raw ?? 0,
    b.maintainer?.raw ?? 0,
    b.license?.raw ?? 0,
  ];

  // CVE rows
  const cveRows = findings.cve.map((c) => `
    <tr>
      <td><a href="${esc(c.url)}" target="_blank" rel="noopener" class="link">${esc(c.id)}</a></td>
      <td><span class="badge" style="background:${severityColor(c.severity)}20;color:${severityColor(c.severity)};border:1px solid ${severityColor(c.severity)}40">${esc(c.severity)}</span></td>
      <td class="num">${c.cvssScore ? c.cvssScore.toFixed(1) : '—'}</td>
      <td class="summary">${esc(c.summary)}</td>
      <td class="date">${fmtDate(c.published)}</td>
    </tr>`).join('');

  // Script finding rows
  const scriptRows = findings.scripts.map((s) => `
    <div class="finding-item finding-${(s.severity || 'medium').toLowerCase()}">
      <span class="finding-type">${esc(s.type)}</span>
      <span class="finding-detail">${esc(s.detail)}</span>
    </div>`).join('');

  // Typosquat rows
  const typosquatRows = findings.typosquat.map((t) => `
    <div class="finding-item finding-high">
      <span class="finding-type">TYPOSQUAT</span>
      <span class="finding-detail">Similar to <strong>${esc(t.match)}</strong> (edit distance: ${t.distance})</span>
    </div>`).join('');

  // Maintainer rows
  const maintainerRows = findings.maintainer.map((m) => `
    <div class="finding-item finding-medium">
      <span class="finding-type">PROVENANCE</span>
      <span class="finding-detail">${esc(m)}</span>
    </div>`).join('');

  // License rows
  const licenseRows = licenseFindings.map((l) => `
    <div class="finding-item finding-${(l.severity || 'low').toLowerCase()}">
      <span class="finding-type">${esc(l.type)}</span>
      <span class="finding-detail">${esc(l.detail)}</span>
    </div>`).join('');

  // Script diff rows
  const diffRows = (findings.scriptDiff ?? []).map((d) => `
    <div class="finding-item finding-medium">
      <span class="finding-type">DIFF</span>
      <span class="finding-detail">${esc(d)}</span>
    </div>`).join('');

  // Popularity rows
  const popRows = (popularity.findings ?? []).map((f) => `
    <div class="finding-item finding-medium">
      <span class="finding-type">POPULARITY</span>
      <span class="finding-detail">${esc(f)}</span>
    </div>`).join('');

  const gh = popularity.data?.githubStats;
  const dl = popularity.data?.downloads;

  const totalFindings = findings.cve.length + findings.scripts.length +
    findings.typosquat.length + findings.maintainer.length + licenseFindings.length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>safe-npm: ${esc(pkg)}@${esc(version)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:         #0a0e1a;
      --surface:    #111827;
      --surface2:   #1a2035;
      --border:     #1f2937;
      --border2:    #374151;
      --text:       #f9fafb;
      --text2:      #9ca3af;
      --text3:      #6b7280;
      --accent:     #6366f1;
      --low:        #10b981;
      --medium:     #f59e0b;
      --high:       #ef4444;
      --critical:   #7c3aed;
      --radius:     12px;
      --radius-sm:  6px;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
    }

    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }

    /* ── Layout ── */
    .container { max-width: 1100px; margin: 0 auto; padding: 0 20px 60px; }

    /* ── Header ── */
    header {
      background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
      border-bottom: 1px solid var(--border);
      padding: 28px 0;
      margin-bottom: 32px;
    }
    .header-inner {
      max-width: 1100px;
      margin: 0 auto;
      padding: 0 20px;
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    .logo {
      font-size: 22px;
      font-weight: 700;
      color: var(--accent);
      white-space: nowrap;
    }
    .header-divider { color: var(--border2); font-size: 24px; }
    .pkg-title { flex: 1; }
    .pkg-title h1 { font-size: 26px; font-weight: 700; color: var(--text); }
    .pkg-title .desc { color: var(--text2); font-size: 14px; margin-top: 4px; }
    .scan-time { font-size: 13px; color: var(--text3); white-space: nowrap; }

    /* ── Risk Hero ── */
    .risk-hero {
      display: flex;
      align-items: center;
      gap: 40px;
      padding: 32px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 28px;
      flex-wrap: wrap;
    }
    .gauge-wrap { flex-shrink: 0; position: relative; width: 180px; height: 180px; }
    .gauge-wrap canvas { width: 180px !important; height: 180px !important; }
    .gauge-score {
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      pointer-events: none;
    }
    .gauge-score .score-num { font-size: 42px; font-weight: 800; color: var(--text); line-height: 1; }
    .gauge-score .score-den { font-size: 14px; color: var(--text3); }
    .risk-info { flex: 1; min-width: 220px; }
    .risk-level-badge {
      display: inline-block;
      padding: 6px 20px;
      border-radius: 999px;
      font-size: 20px;
      font-weight: 800;
      letter-spacing: 2px;
      margin-bottom: 12px;
      border: 2px solid;
    }
    .risk-desc { color: var(--text2); font-size: 15px; margin-bottom: 16px; }
    .risk-meta { display: flex; gap: 24px; flex-wrap: wrap; }
    .risk-meta-item { font-size: 13px; color: var(--text3); }
    .risk-meta-item strong { color: var(--text2); }

    /* ── Stats Grid ── */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 16px 18px;
    }
    .stat-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--text3); margin-bottom: 6px; }
    .stat-value { font-size: 22px; font-weight: 700; color: var(--text); }
    .stat-value.good  { color: var(--low); }
    .stat-value.warn  { color: var(--medium); }
    .stat-value.bad   { color: var(--high); }

    /* ── Section ── */
    .section { margin-bottom: 28px; }
    .section-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--text2);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .section-title::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }

    /* ── Chart card ── */
    .chart-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 24px;
    }
    .chart-card canvas { max-height: 260px; }

    /* ── Findings ── */
    .findings-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
      margin-bottom: 28px;
    }
    @media (max-width: 700px) { .findings-grid { grid-template-columns: 1fr; } }

    .findings-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
    }
    .findings-card-title {
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--text2);
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .count-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      font-size: 11px;
      font-weight: 700;
      background: var(--border2);
      color: var(--text);
    }
    .count-badge.has-findings { background: var(--high); color: white; }

    .finding-item {
      padding: 10px 12px;
      border-radius: var(--radius-sm);
      margin-bottom: 8px;
      font-size: 13px;
      display: flex;
      align-items: flex-start;
      gap: 8px;
    }
    .finding-item:last-child { margin-bottom: 0; }
    .finding-low      { background: rgba(16,185,129,0.08); border-left: 3px solid var(--low); }
    .finding-medium   { background: rgba(245,158,11,0.08); border-left: 3px solid var(--medium); }
    .finding-high     { background: rgba(239,68,68,0.08);  border-left: 3px solid var(--high); }
    .finding-critical { background: rgba(124,58,237,0.10); border-left: 3px solid var(--critical); }

    .finding-type {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.8px;
      color: var(--text3);
      white-space: nowrap;
      margin-top: 1px;
      min-width: 80px;
    }
    .finding-detail { color: var(--text2); word-break: break-word; }

    .empty-state { color: var(--text3); font-size: 13px; font-style: italic; padding: 8px 0; }

    /* ── CVE Table ── */
    .table-wrap {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    thead tr { background: var(--surface2); }
    th {
      padding: 10px 14px;
      text-align: left;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--text3);
    }
    td { padding: 10px 14px; border-top: 1px solid var(--border); color: var(--text2); }
    tr:hover td { background: var(--surface2); }
    .link { color: var(--accent); font-weight: 600; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
    }
    td.num { font-variant-numeric: tabular-nums; text-align: right; }
    td.date { white-space: nowrap; color: var(--text3); }
    td.summary { max-width: 320px; }

    /* ── Info Grid ── */
    .info-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 14px;
    }
    .info-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 18px;
    }
    .info-row { display: flex; justify-content: space-between; font-size: 13px; padding: 5px 0; border-bottom: 1px solid var(--border); }
    .info-row:last-child { border-bottom: none; }
    .info-key { color: var(--text3); }
    .info-val { color: var(--text2); font-weight: 500; text-align: right; max-width: 60%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    /* ── GitHub Stats ── */
    .gh-stats { display: flex; gap: 16px; flex-wrap: wrap; }
    .gh-stat { text-align: center; }
    .gh-stat-num { font-size: 20px; font-weight: 700; color: var(--text); }
    .gh-stat-label { font-size: 11px; color: var(--text3); }

    /* ── Footer ── */
    footer {
      border-top: 1px solid var(--border);
      padding: 20px 0;
      text-align: center;
      color: var(--text3);
      font-size: 13px;
    }
  </style>
</head>
<body>

<header>
  <div class="header-inner">
    <div class="logo">🔒 safe-npm</div>
    <div class="header-divider">/</div>
    <div class="pkg-title">
      <h1>${esc(pkg)}@${esc(version)}</h1>
      ${meta.description ? `<p class="desc">${esc(meta.description)}</p>` : ''}
    </div>
    <div class="scan-time">Scanned ${fmtDate(scannedAt)}</div>
  </div>
</header>

<div class="container">

  <!-- ── Risk Hero ─────────────────────────────────────────────────── -->
  <div class="risk-hero">
    <div class="gauge-wrap">
      <canvas id="gaugeChart"></canvas>
      <div class="gauge-score">
        <span class="score-num">${risk.score.toFixed(1)}</span>
        <span class="score-den">/ 10</span>
      </div>
    </div>
    <div class="risk-info">
      <div class="risk-level-badge" style="color:${lc};border-color:${lc};background:${lc}18">
        ${risk.level}
      </div>
      <p class="risk-desc">${esc(risk.description)}</p>
      <div class="risk-meta">
        <div class="risk-meta-item">License: <strong>${esc(meta.license || 'UNKNOWN')}</strong></div>
        <div class="risk-meta-item">Maintainers: <strong>${meta.maintainers.length}</strong></div>
        <div class="risk-meta-item">Dependencies: <strong>${meta.dependencies}</strong></div>
        <div class="risk-meta-item">Published: <strong>${fmtDate(meta.published)}</strong></div>
      </div>
    </div>
  </div>

  <!-- ── Stats Grid ────────────────────────────────────────────────── -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Risk Score</div>
      <div class="stat-value" style="color:${lc}">${risk.score.toFixed(2)}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">CVEs Found</div>
      <div class="stat-value ${findings.cve.length > 0 ? 'bad' : 'good'}">${findings.cve.length}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Script Warnings</div>
      <div class="stat-value ${findings.scripts.length > 0 ? 'warn' : 'good'}">${findings.scripts.length}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Weekly Downloads</div>
      <div class="stat-value ${dl === null ? '' : dl < 1000 ? 'warn' : 'good'}">
        ${dl !== null ? formatCount(dl) : '—'}
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-label">GitHub Stars</div>
      <div class="stat-value">${gh ? formatCount(gh.stars) : '—'}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Total Findings</div>
      <div class="stat-value ${totalFindings > 0 ? (risk.level === 'LOW' ? 'warn' : 'bad') : 'good'}">${totalFindings}</div>
    </div>
  </div>

  <!-- ── Score Breakdown Chart ─────────────────────────────────────── -->
  <div class="section">
    <div class="section-title">Score Breakdown</div>
    <div class="chart-card">
      <canvas id="breakdownChart"></canvas>
    </div>
  </div>

  <!-- ── CVE Findings ──────────────────────────────────────────────── -->
  <div class="section">
    <div class="section-title">Vulnerabilities (CVEs)</div>
    ${findings.cve.length > 0 ? `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>Summary</th>
            <th>Published</th>
          </tr>
        </thead>
        <tbody>
          ${cveRows}
        </tbody>
      </table>
    </div>` : `
    <div class="chart-card">
      <p class="empty-state">✓ No known CVEs found for this package version.</p>
    </div>`}
  </div>

  <!-- ── Other Findings ────────────────────────────────────────────── -->
  <div class="findings-grid">

    <div class="findings-card">
      <div class="findings-card-title">
        Script Analysis
        <span class="count-badge ${findings.scripts.length > 0 ? 'has-findings' : ''}">${findings.scripts.length}</span>
      </div>
      ${findings.scripts.length > 0 ? scriptRows : '<p class="empty-state">✓ No suspicious scripts detected.</p>'}
    </div>

    <div class="findings-card">
      <div class="findings-card-title">
        Typosquatting
        <span class="count-badge ${findings.typosquat.length > 0 ? 'has-findings' : ''}">${findings.typosquat.length}</span>
      </div>
      ${findings.typosquat.length > 0 ? typosquatRows : '<p class="empty-state">✓ No typosquatting matches found.</p>'}
    </div>

    <div class="findings-card">
      <div class="findings-card-title">
        Maintainer / Provenance
        <span class="count-badge ${findings.maintainer.length > 0 ? 'has-findings' : ''}">${findings.maintainer.length}</span>
      </div>
      ${findings.maintainer.length > 0 ? maintainerRows : '<p class="empty-state">✓ No maintainer risk signals detected.</p>'}
    </div>

    <div class="findings-card">
      <div class="findings-card-title">
        License
        <span class="count-badge ${licenseFindings.length > 0 ? 'has-findings' : ''}">${licenseFindings.length}</span>
      </div>
      ${licenseFindings.length > 0 ? licenseRows : `<p class="empty-state">✓ ${esc(meta.license || 'Unknown')} — permissive license.</p>`}
    </div>

    ${(findings.scriptDiff ?? []).length > 0 ? `
    <div class="findings-card">
      <div class="findings-card-title">
        Version Script Diff
        <span class="count-badge has-findings">${findings.scriptDiff.length}</span>
      </div>
      ${diffRows}
    </div>` : ''}

    ${(popularity.findings ?? []).length > 0 ? `
    <div class="findings-card">
      <div class="findings-card-title">
        Popularity Signals
        <span class="count-badge has-findings">${popularity.findings.length}</span>
      </div>
      ${popRows}
    </div>` : ''}

  </div>

  <!-- ── Package Info ───────────────────────────────────────────────── -->
  <div class="section">
    <div class="section-title">Package Information</div>
    <div class="info-grid">
      <div class="info-card">
        <div class="info-row"><span class="info-key">Name</span><span class="info-val">${esc(pkg)}</span></div>
        <div class="info-row"><span class="info-key">Version</span><span class="info-val">${esc(version)}</span></div>
        <div class="info-row"><span class="info-key">License</span><span class="info-val">${esc(meta.license || 'UNKNOWN')}</span></div>
        <div class="info-row"><span class="info-key">First Published</span><span class="info-val">${fmtDate(meta.created)}</span></div>
        <div class="info-row"><span class="info-key">Version Published</span><span class="info-val">${fmtDate(meta.published)}</span></div>
        <div class="info-row"><span class="info-key">Dependencies</span><span class="info-val">${meta.dependencies}</span></div>
        <div class="info-row"><span class="info-key">Dev Dependencies</span><span class="info-val">${meta.devDeps}</span></div>
        <div class="info-row"><span class="info-key">Maintainers</span><span class="info-val">${meta.maintainers.length}</span></div>
        ${meta.homepage ? `<div class="info-row"><span class="info-key">Homepage</span><span class="info-val"><a href="${esc(meta.homepage)}" target="_blank" rel="noopener" class="link">${esc(meta.homepage)}</a></span></div>` : ''}
      </div>

      ${gh ? `
      <div class="info-card">
        <div class="findings-card-title" style="margin-bottom:16px">GitHub Repository</div>
        <div class="gh-stats">
          <div class="gh-stat">
            <div class="gh-stat-num">⭐ ${formatCount(gh.stars)}</div>
            <div class="gh-stat-label">Stars</div>
          </div>
          <div class="gh-stat">
            <div class="gh-stat-num">🍴 ${formatCount(gh.forks)}</div>
            <div class="gh-stat-label">Forks</div>
          </div>
          <div class="gh-stat">
            <div class="gh-stat-num">🐛 ${formatCount(gh.openIssues)}</div>
            <div class="gh-stat-label">Open Issues</div>
          </div>
        </div>
        <div style="margin-top:16px">
          <div class="info-row"><span class="info-key">Last Push</span><span class="info-val">${gh.daysSinceLastPush !== null ? `${gh.daysSinceLastPush}d ago` : '—'}</span></div>
          <div class="info-row"><span class="info-key">Language</span><span class="info-val">${esc(gh.language || '—')}</span></div>
          <div class="info-row"><span class="info-key">Archived</span><span class="info-val" style="color:${gh.isArchived ? 'var(--high)' : 'var(--low)'}">${gh.isArchived ? 'Yes ⚠' : 'No'}</span></div>
          <div class="info-row"><span class="info-key">Repository</span><span class="info-val"><a href="https://github.com/${esc(gh.owner)}/${esc(gh.repo)}" target="_blank" rel="noopener" class="link">${esc(gh.owner)}/${esc(gh.repo)}</a></span></div>
        </div>
      </div>` : ''}

      ${dl !== null ? `
      <div class="info-card">
        <div class="findings-card-title" style="margin-bottom:16px">npm Downloads</div>
        <div style="text-align:center;padding:16px 0">
          <div style="font-size:36px;font-weight:800;color:var(--text)">${formatCount(dl)}</div>
          <div style="font-size:13px;color:var(--text3);margin-top:4px">downloads last week</div>
        </div>
      </div>` : ''}

    </div>
  </div>

</div><!-- /container -->

<footer>
  <p>Generated by <strong>safe-npm</strong> · ${fmtDate(scannedAt)} · Data from OSV.dev, npm Registry, GitHub API</p>
</footer>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<script>
(function() {
  const lc     = ${JSON.stringify(lc)};
  const score  = ${JSON.stringify(risk.score)};
  const labels = ${JSON.stringify(breakdownLabels)};
  const wt     = ${JSON.stringify(breakdownWeighted)};
  const raw    = ${JSON.stringify(breakdownRaw)};

  // ── Gauge (doughnut) ──
  new Chart(document.getElementById('gaugeChart'), {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [score, 10 - score],
        backgroundColor: [lc, '#1f2937'],
        borderWidth: 0,
        borderRadius: 4,
      }]
    },
    options: {
      cutout: '72%',
      rotation: -90,
      circumference: 180,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      animation: { animateRotate: true, duration: 800 },
    }
  });

  // ── Score Breakdown (horizontal bar) ──
  const colors = ['#ef4444','#f59e0b','#a78bfa','#60a5fa','#34d399'];
  new Chart(document.getElementById('breakdownChart'), {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Weighted Score',
          data: wt,
          backgroundColor: colors.map(c => c + 'cc'),
          borderColor: colors,
          borderWidth: 1,
          borderRadius: 4,
        },
        {
          label: 'Raw Score',
          data: raw,
          backgroundColor: colors.map(c => c + '30'),
          borderColor: colors.map(c => c + '60'),
          borderWidth: 1,
          borderRadius: 4,
        }
      ]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: {
        legend: { labels: { color: '#9ca3af', font: { size: 12 } } },
        tooltip: {
          callbacks: {
            label: (ctx) => ' ' + ctx.dataset.label + ': ' + ctx.parsed.x.toFixed(2)
          }
        }
      },
      scales: {
        x: {
          min: 0, max: 10,
          grid: { color: '#1f2937' },
          ticks: { color: '#6b7280' },
        },
        y: {
          grid: { color: '#1f2937' },
          ticks: { color: '#9ca3af', font: { size: 13, weight: '600' } }
        }
      }
    }
  });
})();
</script>
</body>
</html>`;
}

// ─── Write report to disk ──────────────────────────────────────────────────

/**
 * Generate and write an HTML report for a scan result.
 *
 * @param {object} result   ScanResult from scanner.js
 * @param {string} [outPath]  Output file path. Defaults to safe-npm-report-<pkg>-<ver>.html in cwd.
 * @returns {string}  Absolute path of the written file
 */
function writeReport(result, outPath) {
  if (!outPath) {
    const safeName = `${result.package.replace(/[^a-z0-9_@.-]/gi, '-')}-${result.version}`;
    outPath = path.join(process.cwd(), `safe-npm-report-${safeName}.html`);
  }

  const html = buildHtml(result);
  fs.writeFileSync(outPath, html, 'utf8');
  return path.resolve(outPath);
}

/**
 * Open a file in the system's default browser (cross-platform).
 * Non-blocking — fire and forget.
 *
 * @param {string} filePath
 */
function openInBrowser(filePath) {
  const { exec } = require('child_process');
  const p = process.platform;
  const url = filePath.startsWith('http') ? filePath : `file://${filePath.replace(/\\/g, '/')}`;

  if (p === 'win32')       exec(`start "" "${filePath}"`);
  else if (p === 'darwin') exec(`open "${filePath}"`);
  else                     exec(`xdg-open "${filePath}"`);
}

module.exports = { writeReport, openInBrowser, buildHtml };
