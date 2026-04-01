'use strict';

/**
 * checks/script_check.js
 *
 * Static analysis of npm lifecycle scripts (preinstall, postinstall, install)
 * to detect:
 *   - Shell command execution patterns
 *   - External network calls (curl, wget, fetch)
 *   - Obfuscated / base64-encoded payloads
 *   - Environment variable exfiltration
 *   - Reverse shell indicators
 */

const config = require('../config.json');
const logger = require('../utils/logger');

// ─── Pattern sets ─────────────────────────────────────────────────────────

/** High-risk: commands that pull remote code or open network connections */
const NETWORK_PATTERNS = [
  { pattern: /\bcurl\b/i,            label: 'curl (external download)' },
  { pattern: /\bwget\b/i,            label: 'wget (external download)' },
  { pattern: /\bnc\b|\bnetcat\b/i,   label: 'netcat (possible reverse shell)' },
  { pattern: /https?:\/\//i,         label: 'hardcoded URL / external call' },
  { pattern: /\bfetch\s*\(/i,        label: 'fetch() network call' },
  { pattern: /\brequire\s*\(\s*['"]https?['"]\)/i, label: 'Node https module call' },
  { pattern: /new\s+XMLHttpRequest/i, label: 'XMLHttpRequest network call' },
];

/** High-risk: shell / process execution */
const EXEC_PATTERNS = [
  { pattern: /\bexecSync\s*\(/i,     label: 'execSync (sync shell execution)' },
  { pattern: /\bexecFile\s*\(/i,     label: 'execFile (file execution)' },
  { pattern: /\bexec\s*\(/i,         label: 'exec() (shell execution)' },
  { pattern: /\bspawn\s*\(/i,        label: 'spawn (child process)' },
  { pattern: /child_process/i,       label: 'child_process module' },
  { pattern: /\bsh\s+-c\b/i,         label: 'sh -c (inline shell)' },
  { pattern: /\bbash\s+-c\b/i,       label: 'bash -c (inline shell)' },
  { pattern: /\/bin\/sh\b/,          label: '/bin/sh (shell invocation)' },
  { pattern: /\/bin\/bash\b/,        label: '/bin/bash (shell invocation)' },
  { pattern: /\bpowershell\b/i,      label: 'PowerShell execution' },
  { pattern: /\bcmd\.exe\b/i,        label: 'cmd.exe invocation' },
  { pattern: /\beval\s*\(/i,         label: 'eval() (dynamic code execution)' },
  { pattern: /\bnew\s+Function\s*\(/i, label: 'new Function() (dynamic code)' },
];

/** Medium-risk: obfuscation and encoding tricks */
const OBFUSCATION_PATTERNS = [
  { pattern: /Buffer\.from\s*\(.*base64/i,        label: 'base64 decode via Buffer' },
  { pattern: /atob\s*\(/i,                         label: 'atob() base64 decode' },
  { pattern: /String\.fromCharCode\s*\(/i,         label: 'String.fromCharCode() obfuscation' },
  { pattern: /\\x[0-9a-fA-F]{2}/,                 label: 'hex-escaped characters' },
  { pattern: /\\u[0-9a-fA-F]{4}/,                 label: 'unicode-escaped characters' },
  { pattern: /[A-Za-z0-9+/=]{80,}/,               label: 'long base64-like string' },
  { pattern: /\[(['"])\w+\1\]\s*\[(['"])\w+\2\]/, label: 'bracket notation chaining (obfuscation)' },
  { pattern: /\w+\s*=\s*\w+\['\w+'\]\s*\.\s*bind/i, label: 'method binding (potential obfuscation)' },
];

/** Medium-risk: environment variable access / data exfiltration */
const ENV_PATTERNS = [
  { pattern: /process\.env\./i,       label: 'process.env access (env var read)' },
  { pattern: /\$\{[A-Z_]+\}/,         label: 'shell env var interpolation' },
  { pattern: /\$[A-Z_]{3,}/,          label: 'shell env var reference' },
  { pattern: /os\.environ/i,           label: 'os.environ access' },
  { pattern: /HOME|USER|PATH|SECRET|TOKEN|KEY|PASSWORD|PASS|AWS|GITHUB/i,
    label: 'sensitive environment variable name' },
];

/** The lifecycle hooks that run automatically during install */
const AUTO_EXEC_HOOKS = ['preinstall', 'install', 'postinstall', 'prepack', 'prepare'];

// ─── Analysis helpers ──────────────────────────────────────────────────────

/**
 * Classify all matched patterns as findings with severity levels.
 *
 * @param {string} scriptContent
 * @param {string} hookName
 * @returns {Array<{ type: string, hook: string, detail: string, severity: string }>}
 */
function analyzeScriptContent(scriptContent, hookName) {
  const findings = [];

  for (const { pattern, label } of NETWORK_PATTERNS) {
    if (pattern.test(scriptContent)) {
      findings.push({ type: 'network', hook: hookName, detail: label, severity: 'HIGH' });
    }
  }

  for (const { pattern, label } of EXEC_PATTERNS) {
    if (pattern.test(scriptContent)) {
      findings.push({ type: 'shell-exec', hook: hookName, detail: label, severity: 'HIGH' });
    }
  }

  for (const { pattern, label } of OBFUSCATION_PATTERNS) {
    if (pattern.test(scriptContent)) {
      findings.push({ type: 'obfuscation', hook: hookName, detail: label, severity: 'MEDIUM' });
    }
  }

  for (const { pattern, label } of ENV_PATTERNS) {
    if (pattern.test(scriptContent)) {
      findings.push({ type: 'env-access', hook: hookName, detail: label, severity: 'MEDIUM' });
    }
  }

  return findings;
}

/**
 * Compute script risk score (0–10).
 * - Presence of any auto-exec hook: +3
 * - Each HIGH finding: +2 (cap at 10)
 * - Each MEDIUM finding: +1 (cap at 10)
 *
 * @param {object} scripts    Package scripts object { hookName: scriptContent }
 * @param {Array}  findings   Output of analyzeScriptContent
 * @returns {number}
 */
function computeScriptScore(scripts, findings) {
  let score = 0;

  // Having any auto-exec hook at all is worth flagging
  const autoExecHooks = AUTO_EXEC_HOOKS.filter((h) => scripts[h]);
  if (autoExecHooks.length > 0) score += 3;

  for (const f of findings) {
    if (f.severity === 'HIGH')   score += 2;
    if (f.severity === 'MEDIUM') score += 1;
  }

  return Math.min(score, 10);
}

// ─── Main checker ───────────────────────────────────────────────────────────

/**
 * Run the script analysis check.
 *
 * @param {object} scripts  The `scripts` field from package.json
 * @returns {{ findings: Array, riskScore: number, hooks: string[] }}
 */
function runScriptCheck(scripts = {}) {
  logger.debug(`Script check: analyzing ${Object.keys(scripts).length} scripts`);

  const allFindings = [];
  const detectedHooks = [];

  for (const [hookName, scriptContent] of Object.entries(scripts)) {
    if (!scriptContent || typeof scriptContent !== 'string') continue;

    if (AUTO_EXEC_HOOKS.includes(hookName)) {
      detectedHooks.push(hookName);
      logger.debug(`Found auto-exec hook: ${hookName} → ${scriptContent.slice(0, 80)}`);
    }

    const findings = analyzeScriptContent(scriptContent, hookName);
    allFindings.push(...findings);
  }

  // Deduplicate findings by (type + detail)
  const seen = new Set();
  const uniqueFindings = allFindings.filter((f) => {
    const key = `${f.type}:${f.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const riskScore = computeScriptScore(scripts, uniqueFindings);

  logger.debug(
    `Script check: ${uniqueFindings.length} findings, ${detectedHooks.length} auto-exec hooks (risk: ${riskScore})`
  );

  return {
    findings: uniqueFindings,
    riskScore,
    hooks: detectedHooks,
  };
}

module.exports = { runScriptCheck, analyzeScriptContent, AUTO_EXEC_HOOKS };
