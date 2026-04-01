#!/usr/bin/env node
'use strict';

/**
 * cli.js — safe-npm entry point
 *
 * Commands:
 *   safe-npm install <package[@version]> [npm-flags...]
 *   safe-npm scan    <package[@version]> [--json] [--strict] [--report] [--open]
 *   safe-npm scan    <package.json>      [--fail-on <level>] [--json] [--report]
 *   safe-npm cache   clear|status
 */

const { Command } = require('commander');
const chalk     = require('chalk');
const ora       = require('ora');
const inquirer  = require('inquirer');
const path      = require('path');

const scanner    = require('./core/scanner');
const installer  = require('./core/installer');
const fetcher    = require('./core/fetcher');
const riskEngine = require('./core/risk_engine');
const logger     = require('./utils/logger');
const reporter   = require('./core/reporter');
const { formatCount } = require('./checks/popularity_check');
const { classifyLicense, CATEGORY_DESC } = require('./checks/license_check');

const pkg = require('./package.json');

// ─── CLI Setup ──────────────────────────────────────────────────────────────

const program = new Command();

program
  .name('safe-npm')
  .description(chalk.cyan('Secure npm install wrapper — scans packages for security risks before installation'))
  .version(pkg.version, '-v, --version');

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * Parse a package spec like "axios@0.21.1" or "axios" into { name, version }.
 * Handles scoped packages: "@scope/pkg@1.0.0"
 */
function parsePackageSpec(spec) {
  if (spec.startsWith('@')) {
    const atIdx = spec.indexOf('@', 1);
    if (atIdx === -1) return { name: spec, version: 'latest' };
    return { name: spec.slice(0, atIdx), version: spec.slice(atIdx + 1) };
  }
  const atIdx = spec.indexOf('@');
  if (atIdx === -1) return { name: spec, version: 'latest' };
  return { name: spec.slice(0, atIdx), version: spec.slice(atIdx + 1) };
}

function printJson(data) {
  console.log(JSON.stringify(data, null, 2));
}

function riskBanner(level) {
  const banners = {
    LOW:      chalk.green.bold('  ✔  Risk Level: LOW'),
    MEDIUM:   chalk.yellow.bold('  ⚠  Risk Level: MEDIUM'),
    HIGH:     chalk.red.bold('  ✘  Risk Level: HIGH'),
    CRITICAL: chalk.bgRed.white.bold('  ✘  Risk Level: CRITICAL'),
  };
  return banners[level] ?? chalk.gray(`  Risk Level: ${level}`);
}

/**
 * ASCII bar chart for score display.
 * @param {number} value  current value
 * @param {number} max    maximum possible value (for scaling)
 */
function bar(value, max) {
  const pct    = Math.min(value / max, 1);
  const filled = Math.round(pct * 14);
  const color  = pct >= 0.75 ? chalk.red : pct >= 0.4 ? chalk.yellow : chalk.green;
  return color('█'.repeat(filled) + '░'.repeat(14 - filled));
}

function licenseColor(license) {
  const cat = classifyLicense(license);
  if (cat === 'NO_LICENSE' || cat === 'RESTRICTIVE') return chalk.red(license || 'NONE');
  if (cat === 'COPYLEFT')      return chalk.yellow(license);
  if (cat === 'WEAK_COPYLEFT') return chalk.cyan(license);
  if (cat === 'UNKNOWN')       return chalk.gray(license);
  return chalk.green(license); // PERMISSIVE
}

// ─── Main scan result renderer ─────────────────────────────────────────────

function renderScanResult(result) {
  const { risk, findings, meta } = result;
  const popularity = result.popularity ?? { data: {}, findings: [] };
  const gh  = popularity.data?.githubStats;
  const dl  = popularity.data?.downloads;

  logger.printHeader(`${result.package}@${result.version}`);
  logger.printSummary(result);

  // ── Package metadata line ───────────────────────────────────────────────
  const licStr   = licenseColor(meta.license);
  const dlStr    = dl !== null ? chalk.cyan(formatCount(dl) + '/wk') : chalk.gray('N/A');
  const starsStr = gh ? chalk.yellow('★ ' + formatCount(gh.stars)) : chalk.gray('no GitHub');

  console.log(
    chalk.gray('  License: ') + licStr + chalk.gray('  |  ') +
    chalk.gray('Deps: ') + chalk.white(meta.dependencies) + chalk.gray('  |  ') +
    chalk.gray('Maintainers: ') + chalk.white(meta.maintainers.length) + chalk.gray('  |  ') +
    chalk.gray('Downloads: ') + dlStr + chalk.gray('  |  ') +
    starsStr
  );
  if (meta.description) {
    console.log(chalk.gray(`  ${meta.description}`));
  }
  if (meta.homepage) {
    console.log(chalk.gray(`  ${meta.homepage}`));
  }
  console.log('');

  // ── Risk banner ────────────────────────────────────────────────────────
  console.log(riskBanner(risk.level));
  console.log(chalk.gray(`  ${risk.description}`));
  console.log('');

  // ── Score breakdown ────────────────────────────────────────────────────
  const b = risk.breakdown;
  console.log(chalk.bold('  Score breakdown:'));
  console.log(`    CVE        ${bar(b.cve.weighted, 4.5)}  ${b.cve.raw.toFixed(1)} raw → ${chalk.bold(b.cve.weighted.toFixed(2))} weighted`);
  console.log(`    Scripts    ${bar(b.script.weighted, 2)}  ${b.script.raw.toFixed(1)} raw → ${chalk.bold(b.script.weighted.toFixed(2))} weighted`);
  console.log(`    Typosquat  ${bar(b.typosquat.weighted, 1.5)}  ${b.typosquat.raw.toFixed(1)} raw → ${chalk.bold(b.typosquat.weighted.toFixed(2))} weighted`);
  console.log(`    Maintainer ${bar(b.maintainer.weighted, 1)}  ${b.maintainer.raw.toFixed(1)} raw → ${chalk.bold(b.maintainer.weighted.toFixed(2))} weighted`);
  console.log(`    License    ${bar(b.license?.weighted ?? 0, 1)}  ${(b.license?.raw ?? 0).toFixed(1)} raw → ${chalk.bold((b.license?.weighted ?? 0).toFixed(2))} weighted`);
  console.log(chalk.bold(`\n    Total      ${bar(risk.score, 10)}  ${chalk.white.bold(risk.score.toFixed(2))} / 10.00`));
  console.log('');

  // ── GitHub stats if available ──────────────────────────────────────────
  if (gh) {
    const archived  = gh.isArchived ? chalk.red(' [ARCHIVED]') : '';
    const lastPush  = gh.daysSinceLastPush !== null ? chalk.gray(`  last push: ${gh.daysSinceLastPush}d ago`) : '';
    console.log(
      chalk.bold.gray('  GitHub: ') +
      chalk.white(`${gh.owner}/${gh.repo}`) +
      archived + lastPush
    );
    console.log(
      chalk.gray(`    Stars: ${chalk.yellow('★ ' + formatCount(gh.stars))}`) +
      chalk.gray(`  Forks: ${chalk.cyan(formatCount(gh.forks))}`) +
      chalk.gray(`  Open Issues: ${gh.openIssues > 50 ? chalk.red(gh.openIssues) : chalk.white(gh.openIssues)}`)
    );
    console.log('');
  }

  // ── License finding (if any) ───────────────────────────────────────────
  if (findings.license?.length > 0) {
    console.log(chalk.bold.red('  License Issues:'));
    for (const l of findings.license) {
      const sev = l.severity === 'HIGH' ? chalk.red('✘') : l.severity === 'MEDIUM' ? chalk.yellow('⚠') : chalk.cyan('ℹ');
      console.log(`    ${sev} ${chalk.gray(l.detail)}`);
    }
    console.log('');
  }

  // ── Version script diff ────────────────────────────────────────────────
  if (findings.scriptDiff?.length > 0) {
    console.log(chalk.bold.cyan('  Version diff (script changes):'));
    for (const d of findings.scriptDiff) {
      console.log(`    ${chalk.cyan('→')} ${d}`);
    }
    console.log('');
  }

  // ── Popularity signals (if any) ────────────────────────────────────────
  if (popularity.findings?.length > 0) {
    console.log(chalk.bold.gray('  Popularity signals:'));
    for (const f of popularity.findings) {
      console.log(`    ${chalk.gray('ℹ')} ${f}`);
    }
    console.log('');
  }
}

// ─── Report helper ─────────────────────────────────────────────────────────

function maybeWriteReport(result, opts) {
  if (!opts.report) return;

  const filePath = reporter.writeReport(result);
  logger.success(`HTML report written: ${filePath}`);

  if (opts.open) {
    reporter.openInBrowser(filePath);
    logger.info('Opening report in browser...');
  } else {
    logger.info(`Open in browser: file://${filePath.replace(/\\/g, '/')}`);
  }
}

// ─── install command ───────────────────────────────────────────────────────

program
  .command('install <package> [extra-npm-flags...]')
  .description('Scan a package for security risks, then optionally install it')
  .option('--strict',   'Block installation if risk level is HIGH or CRITICAL')
  .option('--json',     'Output scan results as JSON (suppresses interactive prompts)')
  .option('--no-diff',  'Skip version diff analysis')
  .option('--report',   'Generate an HTML security report after scanning')
  .option('--open',     'Auto-open the HTML report in your browser (requires --report)')
  .option('--debug',    'Enable debug logging')
  .allowUnknownOption(true)
  .action(async (packageSpec, extraFlags, opts) => {
    if (opts.debug) logger.setLevel('debug');
    if (opts.json)  logger.setJsonMode(true);

    const { name, version } = parsePackageSpec(packageSpec);
    const resolvedSpec = version === 'latest' ? name : `${name}@${version}`;

    const spinner = opts.json ? null : ora(`Scanning ${chalk.cyan(resolvedSpec)}...`).start();

    let result;
    try {
      result = await scanner.scan(name, version, { diffMode: !opts.noDiff });
      spinner?.succeed(`Scan complete — ${chalk.bold(result.risk.level)} (${result.risk.score}/10)`);
    } catch (err) {
      spinner?.fail(`Scan failed: ${err.message}`);
      logger.error(err.message);
      process.exit(1);
    }

    if (opts.json) {
      printJson(result);
    } else {
      renderScanResult(result);
      maybeWriteReport(result, opts);
    }

    if (opts.strict && riskEngine.shouldBlock(result.risk.level)) {
      console.log('');
      logger.error(`Installation BLOCKED in --strict mode (risk: ${result.risk.level})`);
      process.exit(2);
    }

    if (opts.json) {
      process.exit(riskEngine.shouldBlock(result.risk.level) ? 2 : 0);
    }

    const defaultProceed = !riskEngine.shouldBlock(result.risk.level);
    const promptMessage  = defaultProceed
      ? `Proceed with installation of ${resolvedSpec}?`
      : chalk.red(`${resolvedSpec} has ${result.risk.level} risk. Proceed anyway?`);

    console.log('');
    const { proceed } = await inquirer.prompt([{
      type: 'confirm',
      name: 'proceed',
      message: promptMessage,
      default: defaultProceed,
    }]);

    if (!proceed) {
      logger.warn('Installation cancelled by user.');
      process.exit(0);
    }

    console.log('');
    const { exitCode } = await installer.installPackage(resolvedSpec, extraFlags);

    if (exitCode !== 0) {
      logger.error(`npm install exited with code ${exitCode}`);
    } else {
      logger.success(`${resolvedSpec} installed successfully.`);
    }

    process.exit(exitCode);
  });

// ─── scan command ──────────────────────────────────────────────────────────

program
  .command('scan <target>')
  .description('Scan a package (name[@version]) or a package.json file without installing')
  .option('--json',              'Output results as JSON')
  .option('--strict',            'Exit with code 2 if risk is HIGH or CRITICAL')
  .option('--fail-on <level>',   'Exit with code 2 if risk meets or exceeds level (LOW|MEDIUM|HIGH|CRITICAL)', 'HIGH')
  .option('--no-diff',           'Skip version diff analysis')
  .option('--report',            'Generate an HTML security report')
  .option('--open',              'Auto-open the HTML report in your browser (requires --report)')
  .option('--debug',             'Enable debug logging')
  .action(async (target, opts) => {
    if (opts.debug) logger.setLevel('debug');
    if (opts.json)  logger.setJsonMode(true);

    const isPackageFile = target.endsWith('.json');

    if (isPackageFile) {
      // ── Batch mode: package.json ─────────────────────────────────────────
      const spinner = opts.json ? null : ora(`Scanning packages in ${chalk.cyan(target)}...`).start();

      let batchResult;
      try {
        batchResult = await scanner.scanPackageFile(target, { diffMode: !opts.noDiff });
        spinner?.succeed(`Scanned ${batchResult.summary.total} packages`);
      } catch (err) {
        spinner?.fail(err.message);
        logger.error(err.message);
        process.exit(1);
      }

      if (opts.json) {
        printJson(batchResult);
      } else {
        renderBatchResults(batchResult, opts.failOn);

        if (opts.report) {
          // Write one report per package in batch
          for (const r of batchResult.results) {
            const fp = reporter.writeReport(r);
            logger.success(`Report: ${fp}`);
          }
          if (opts.open && batchResult.results.length > 0) {
            reporter.openInBrowser(reporter.writeReport(batchResult.results[0]));
          }
        }
      }

      const failLevel = (opts.failOn ?? 'HIGH').toUpperCase();
      const levels    = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const failIdx   = levels.indexOf(failLevel);
      const hasViolation = batchResult.results.some(
        (r) => levels.indexOf(r.risk.level) >= failIdx
      );

      process.exit(hasViolation ? 2 : 0);

    } else {
      // ── Single package scan ──────────────────────────────────────────────
      const { name, version } = parsePackageSpec(target);
      const resolvedSpec = version === 'latest' ? name : `${name}@${version}`;

      const spinner = opts.json ? null : ora(`Scanning ${chalk.cyan(resolvedSpec)}...`).start();

      let result;
      try {
        result = await scanner.scan(name, version, { diffMode: !opts.noDiff });
        spinner?.succeed(`Scan complete — ${chalk.bold(result.risk.level)} (${result.risk.score}/10)`);
      } catch (err) {
        spinner?.fail(err.message);
        logger.error(err.message);
        process.exit(1);
      }

      if (opts.json) {
        printJson(result);
      } else {
        renderScanResult(result);
        maybeWriteReport(result, opts);
      }

      if (opts.strict && riskEngine.shouldBlock(result.risk.level)) {
        process.exit(2);
      }
      process.exit(0);
    }
  });

// ─── cache command ─────────────────────────────────────────────────────────

program
  .command('cache <action>')
  .description('Manage the local metadata cache (action: clear|status)')
  .action((action) => {
    if (action === 'clear') {
      const ok = fetcher.clearCache();
      if (ok) {
        logger.success('Cache cleared.');
      } else {
        logger.error('Failed to clear cache.');
        process.exit(1);
      }
    } else if (action === 'status') {
      const os     = require('os');
      const fs     = require('fs');
      const config = require('./config.json');
      const cacheDir = path.join(os.homedir(), config.cache.dir);
      if (fs.existsSync(cacheDir)) {
        const files = fs.readdirSync(cacheDir);
        logger.info(`Cache directory : ${cacheDir}`);
        logger.info(`Cached entries  : ${files.length}`);
        logger.info(`TTL             : ${config.cache.ttl_seconds}s`);
      } else {
        logger.info('Cache is empty (directory does not exist yet).');
      }
    } else {
      logger.error(`Unknown cache action: "${action}". Use clear or status.`);
      process.exit(1);
    }
  });

// ─── Batch result renderer ────────────────────────────────────────────────

function renderBatchResults(batchResult, failOn = 'HIGH') {
  const { results, errors, summary } = batchResult;
  const levels  = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const failIdx = levels.indexOf(failOn.toUpperCase());

  logger.separator();
  console.log(chalk.bold.cyan('  Batch Scan Results'));
  logger.separator();

  for (const r of results) {
    const badge  = logger.riskBadge(r.risk.level);
    const failed = levels.indexOf(r.risk.level) >= failIdx ? chalk.red(' ✘') : '';
    const dl     = r.popularity?.data?.downloads;
    const dlStr  = dl !== null && dl !== undefined ? chalk.gray(` (${formatCount(dl)}/wk)`) : '';
    console.log(`  ${badge} ${r.package}@${r.version}${failed}${dlStr}`);

    if (r.findings.cve.length > 0) {
      for (const cve of r.findings.cve.slice(0, 2)) {
        console.log(`         ${logger.severityBadge(cve.severity)} ${cve.id} — ${cve.summary}`);
      }
    }
    if (r.findings.license?.length > 0) {
      const lf = r.findings.license[0];
      console.log(`         ${chalk.yellow('⚠ LICENSE')} ${lf.detail}`);
    }
  }

  if (errors?.length > 0) {
    console.log('');
    console.log(chalk.gray(`  Errors (${errors.length} packages skipped):`));
    for (const e of errors) {
      console.log(chalk.gray(`    • ${e.package}: ${e.error}`));
    }
  }

  logger.separator();
  console.log(chalk.bold(`\n  Summary: ${summary.total} scanned`));
  console.log(
    `    ${chalk.green('LOW: '    + (summary.byLevel.LOW      ?? 0))}  ` +
    `${chalk.yellow('MEDIUM: '   + (summary.byLevel.MEDIUM   ?? 0))}  ` +
    `${chalk.red('HIGH: '        + (summary.byLevel.HIGH     ?? 0))}  ` +
    `${chalk.bgRed.white('CRITICAL: ' + (summary.byLevel.CRITICAL ?? 0))}`
  );
  console.log('');
}

// ─── Error handling & parse ────────────────────────────────────────────────

program.on('command:*', () => {
  logger.error(`Unknown command: "${program.args.join(' ')}"`);
  console.log('');
  program.help();
});

process.on('unhandledRejection', (reason) => {
  logger.error(`Unhandled error: ${reason?.message ?? reason}`);
  process.exit(1);
});

program.parse(process.argv);

if (process.argv.length < 3) {
  program.help();
}
