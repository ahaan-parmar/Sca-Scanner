'use strict';

const chalk = require('chalk');

// ─── Log level constants ───────────────────────────────────────────────────
const LEVELS = {
  DEBUG: 0,
  INFO:  1,
  WARN:  2,
  ERROR: 3,
  SILENT: 99,
};

let currentLevel = LEVELS.INFO;
let jsonMode = false;

// ─── Public API ────────────────────────────────────────────────────────────

function setLevel(level) {
  currentLevel = LEVELS[level.toUpperCase()] ?? LEVELS.INFO;
}

function setJsonMode(enabled) {
  jsonMode = enabled;
}

function debug(...args) {
  if (jsonMode || currentLevel > LEVELS.DEBUG) return;
  console.error(chalk.gray('[DEBUG]'), ...args);
}

function info(...args) {
  if (jsonMode || currentLevel > LEVELS.INFO) return;
  console.log(chalk.cyan('[INFO]'), ...args);
}

function warn(...args) {
  if (jsonMode || currentLevel > LEVELS.WARN) return;
  console.warn(chalk.yellow('[WARN]'), ...args);
}

function error(...args) {
  if (jsonMode || currentLevel > LEVELS.ERROR) return;
  console.error(chalk.red('[ERROR]'), ...args);
}

function success(...args) {
  if (jsonMode) return;
  console.log(chalk.green('[OK]'), ...args);
}

function separator() {
  if (jsonMode) return;
  console.log(chalk.gray('─'.repeat(64)));
}

function doubleSeparator() {
  if (jsonMode) return;
  console.log(chalk.cyan('═'.repeat(64)));
}

// ─── Badges ────────────────────────────────────────────────────────────────

function riskBadge(level) {
  const map = {
    LOW:      chalk.green.bold('[LOW]'),
    MEDIUM:   chalk.yellow.bold('[MEDIUM]'),
    HIGH:     chalk.red.bold('[HIGH]'),
    CRITICAL: chalk.bgRed.white.bold('[CRITICAL]'),
  };
  return map[level] ?? chalk.gray(`[${level}]`);
}

function severityBadge(severity) {
  const s = severity?.toUpperCase() ?? 'UNKNOWN';
  const map = {
    LOW:      chalk.green(`[${s}]`),
    MEDIUM:   chalk.yellow(`[${s}]`),
    HIGH:     chalk.red(`[${s}]`),
    CRITICAL: chalk.bgRed.white(`[${s}]`),
    UNKNOWN:  chalk.gray(`[${s}]`),
  };
  return map[s] ?? chalk.gray(`[${s}]`);
}

// ─── Header ────────────────────────────────────────────────────────────────

function printHeader(packageSpec) {
  if (jsonMode) return;
  const label = `safe-npm  —  Security Scan: ${packageSpec}`;
  const padded = label.padEnd(60);
  console.log('');
  console.log(chalk.bold.cyan('╔══════════════════════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan(`║  ${padded}  ║`));
  console.log(chalk.bold.cyan('╚══════════════════════════════════════════════════════════════╝'));
  console.log('');
}

// ─── Summary block ─────────────────────────────────────────────────────────

function printSummary(result) {
  if (jsonMode) return;

  const { package: pkg, version, risk, findings } = result;
  const badge = riskBadge(risk.level);

  separator();
  console.log(chalk.bold('Package : ') + chalk.white(`${pkg}@${version}`));
  console.log(chalk.bold('Risk    : ') + badge + chalk.gray(` (score: ${risk.score.toFixed(2)}/10)`));
  console.log('');

  if (findings.cve.length > 0) {
    console.log(chalk.bold.red('  Vulnerabilities (CVE):'));
    for (const cve of findings.cve) {
      console.log(
        `    ${severityBadge(cve.severity)} ${chalk.bold(cve.id)} — ${chalk.gray(cve.summary)}`
      );
      if (cve.url) {
        console.log(`        ${chalk.gray('↳')} ${chalk.underline.gray(cve.url)}`);
      }
    }
    console.log('');
  }

  if (findings.scripts.length > 0) {
    console.log(chalk.bold.yellow('  Suspicious Scripts:'));
    for (const s of findings.scripts) {
      const icon = s.severity === 'HIGH' ? chalk.red('✘') : chalk.yellow('⚠');
      console.log(`    ${icon} ${chalk.bold(s.type)}: ${chalk.gray(s.detail)}`);
    }
    console.log('');
  }

  if (findings.typosquat.length > 0) {
    console.log(chalk.bold.magenta('  Possible Typosquatting:'));
    for (const t of findings.typosquat) {
      console.log(
        `    ${chalk.magenta('⚠')} Very similar to ${chalk.bold('"' + t.match + '"')} ` +
        chalk.gray(`(edit distance: ${t.distance})`)
      );
    }
    console.log('');
  }

  if (findings.maintainer.length > 0) {
    console.log(chalk.bold.yellow('  Maintainer / Provenance Risks:'));
    for (const m of findings.maintainer) {
      console.log(`    ${chalk.yellow('⚠')} ${chalk.gray(m)}`);
    }
    console.log('');
  }

  separator();
}

module.exports = {
  debug,
  info,
  warn,
  error,
  success,
  separator,
  doubleSeparator,
  riskBadge,
  severityBadge,
  printHeader,
  printSummary,
  setLevel,
  setJsonMode,
};
