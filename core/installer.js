'use strict';

/**
 * core/installer.js
 *
 * Wrapper around `npm install` that preserves all original npm flags
 * and passes through stdout/stderr transparently.
 *
 * Spawns npm as a child process so signals (Ctrl+C) propagate correctly.
 */

const { spawn } = require('child_process');
const os = require('os');
const logger = require('../utils/logger');

/**
 * Detect the npm executable name for the current OS.
 * On Windows, npm is `npm.cmd` when invoked via spawn.
 */
const NPM_CMD = os.platform() === 'win32' ? 'npm.cmd' : 'npm';

/**
 * Run npm install with the given arguments.
 * All stdout/stderr is piped through to the terminal.
 *
 * @param {string[]} args  Arguments to pass to npm (e.g. ['install', 'axios', '--save'])
 * @returns {Promise<{ exitCode: number }>}
 */
function runNpmInstall(args) {
  return new Promise((resolve, reject) => {
    logger.info(`Running: npm ${args.join(' ')}`);

    const child = spawn(NPM_CMD, args, {
      stdio: 'inherit',   // pass through all I/O
      shell: false,       // avoid shell injection
      env: process.env,   // inherit parent env
    });

    child.on('error', (err) => {
      reject(new Error(`Failed to launch npm: ${err.message}`));
    });

    child.on('close', (code) => {
      resolve({ exitCode: code ?? 1 });
    });

    // Forward termination signals so npm gets Ctrl+C properly
    for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
      process.on(sig, () => {
        child.kill(sig);
      });
    }
  });
}

/**
 * Convenience: install a single package by name + optional version.
 *
 * @param {string}   packageSpec   e.g. 'axios' or 'axios@0.21.1'
 * @param {string[]} [extraFlags]  e.g. ['--save-dev', '--legacy-peer-deps']
 * @returns {Promise<{ exitCode: number }>}
 */
async function installPackage(packageSpec, extraFlags = []) {
  const args = ['install', packageSpec, ...extraFlags];
  return runNpmInstall(args);
}

module.exports = { installPackage, runNpmInstall };
