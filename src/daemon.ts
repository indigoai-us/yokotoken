/**
 * Daemon mode for hq-vault — manages the vault server as a background process.
 *
 * US-009: Daemon mode with auto-start
 *
 * Features:
 * - `hq-vault serve --daemon` starts the server as a background process
 * - PID file stored at ~/.hq-vault/vault.pid
 * - Logs written to ~/.hq-vault/vault.log (rotated, max 10MB)
 * - `hq-vault serve --stop` gracefully stops the daemon
 * - `hq-vault serve --restart` restarts the daemon
 * - Cross-platform: Windows (taskkill), macOS/Linux (SIGTERM)
 */

import { spawn, execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isServerRunning, getVaultDir, readServerPort } from './server.js';
import { readTokenFile } from './auth.js';
import { request } from './client.js';

/** Maximum log file size before rotation (10 MB). */
export const MAX_LOG_SIZE = 10 * 1024 * 1024;

/** Default log file path. */
export function getDefaultLogFile(): string {
  return path.join(getVaultDir(), 'vault.log');
}

/**
 * Rotate the log file if it exceeds MAX_LOG_SIZE.
 * Renames vault.log to vault.log.1 (overwriting any existing .1 file).
 */
export function rotateLogIfNeeded(logFile: string): void {
  if (!fs.existsSync(logFile)) return;

  try {
    const stats = fs.statSync(logFile);
    if (stats.size >= MAX_LOG_SIZE) {
      const rotatedFile = logFile + '.1';
      // Remove old rotated file if it exists
      if (fs.existsSync(rotatedFile)) {
        fs.unlinkSync(rotatedFile);
      }
      fs.renameSync(logFile, rotatedFile);
    }
  } catch {
    // If we can't stat or rotate, just continue — don't block the daemon
  }
}

export interface DaemonStartOptions {
  port?: number;
  vaultPath?: string;
  idleTimeout?: string;
  insecure?: boolean;
  /** Override the log file path (for testing). */
  logFile?: string;
  /** Override the PID file path (for testing). */
  pidFile?: string;
  /** Override the node executable path (for testing). */
  nodePath?: string;
  /** Override the CLI script path (for testing). */
  cliPath?: string;
}

export interface DaemonStartResult {
  success: boolean;
  pid?: number;
  port?: number;
  logFile?: string;
  error?: string;
}

export interface DaemonStopResult {
  success: boolean;
  pid?: number;
  error?: string;
}

/**
 * Start the vault server as a background daemon process.
 *
 * Spawns a detached child process running `node <cli.js> serve` with
 * stdout/stderr redirected to the log file.
 *
 * Cross-platform:
 * - On Windows: uses `detached: true` with `shell: true` — the spawned
 *   process outlives the parent.
 * - On macOS/Linux: uses `detached: true` — the process is session leader.
 *
 * After spawning, waits briefly for the PID file to appear, confirming
 * the daemon started successfully.
 */
export async function startDaemon(opts: DaemonStartOptions = {}): Promise<DaemonStartResult> {
  const vaultDir = getVaultDir();
  const pidFile = opts.pidFile || path.join(vaultDir, 'vault.pid');

  // Check if already running
  const { running, pid: existingPid } = isServerRunning(pidFile);
  if (running) {
    return {
      success: false,
      pid: existingPid,
      error: `Vault server is already running (PID ${existingPid})`,
    };
  }

  // Ensure vault directory exists
  if (!fs.existsSync(vaultDir)) {
    fs.mkdirSync(vaultDir, { recursive: true });
  }

  // Rotate log if needed
  const logFile = opts.logFile || getDefaultLogFile();
  rotateLogIfNeeded(logFile);

  // Open log file for appending
  const logFd = fs.openSync(logFile, 'a');

  // Build the CLI command arguments
  const cliScript = opts.cliPath || path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    'cli.js',
  );
  const args = ['serve'];
  if (opts.port !== undefined) args.push('--port', String(opts.port));
  if (opts.vaultPath) args.push('--vault-path', opts.vaultPath);
  if (opts.idleTimeout) args.push('--idle-timeout', opts.idleTimeout);
  if (opts.insecure) args.push('--insecure');

  const nodePath = opts.nodePath || process.execPath;

  // Build environment for the child process.
  // If the pidFile lives outside the default vault directory, pass
  // HQ_VAULT_DIR so the child process uses the same directory for
  // PID, port, token, and cert files.
  const childEnv = { ...process.env };
  if (opts.pidFile) {
    childEnv.HQ_VAULT_DIR = path.dirname(opts.pidFile);
  }

  // Spawn the daemon process.
  // `detached: true` makes the child a process group leader so it
  // survives the parent exiting. On Windows, Node handles this via
  // CREATE_NEW_PROCESS_GROUP. No `shell: true` — it breaks fd inheritance.
  const child = spawn(nodePath, [cliScript, ...args], {
    detached: true,
    stdio: ['ignore', logFd, logFd],
    env: childEnv,
    windowsHide: true,
  });

  // Unref so the parent can exit
  child.unref();

  // Close the log file descriptor in the parent process
  fs.closeSync(logFd);

  // Wait for the PID file to appear (daemon writes it on successful listen)
  const startTime = Date.now();
  const timeout = 10000; // 10 seconds
  const pollInterval = 200;

  while (Date.now() - startTime < timeout) {
    await new Promise((resolve) => setTimeout(resolve, pollInterval));

    if (fs.existsSync(pidFile)) {
      const pidStr = fs.readFileSync(pidFile, 'utf-8').trim();
      const daemonPid = parseInt(pidStr, 10);
      if (!isNaN(daemonPid)) {
        // Read port from port file
        const portFile = path.join(vaultDir, 'vault.port');
        let port: number | undefined;
        if (fs.existsSync(portFile)) {
          const portStr = fs.readFileSync(portFile, 'utf-8').trim();
          port = parseInt(portStr, 10);
          if (isNaN(port)) port = undefined;
        }

        return {
          success: true,
          pid: daemonPid,
          port,
          logFile,
        };
      }
    }
  }

  // If we get here, the daemon didn't start in time
  // Try to read any error from the log file
  let error = 'Daemon failed to start within 10 seconds';
  try {
    if (fs.existsSync(logFile)) {
      const logContent = fs.readFileSync(logFile, 'utf-8');
      const lastLines = logContent.trim().split('\n').slice(-5).join('\n');
      if (lastLines) {
        error += `. Check log: ${logFile}\nLast log output:\n${lastLines}`;
      }
    }
  } catch {
    // Ignore read errors
  }

  return { success: false, error };
}

/**
 * Stop the vault daemon gracefully.
 *
 * First tries to use the HTTP shutdown endpoint (POST /v1/shutdown),
 * which allows the server to clean up properly. If that fails (e.g.,
 * server is hung), falls back to OS-level process termination:
 * - On Windows: `taskkill /PID <pid> /F`
 * - On macOS/Linux: `process.kill(pid, SIGTERM)`
 */
export async function stopDaemon(opts: {
  pidFile?: string;
  portFile?: string;
  tokenFile?: string;
} = {}): Promise<DaemonStopResult> {
  const vaultDir = getVaultDir();
  const pidFile = opts.pidFile || path.join(vaultDir, 'vault.pid');

  const { running, pid } = isServerRunning(pidFile);
  if (!running || !pid) {
    return {
      success: false,
      error: 'Vault server is not running',
    };
  }

  // Try graceful shutdown via HTTP endpoint first
  const portFile = opts.portFile || path.join(vaultDir, 'vault.port');
  const tokenFile = opts.tokenFile || path.join(vaultDir, 'token');
  const port = readServerPort(portFile);
  const token = readTokenFile(tokenFile);

  if (port && token) {
    try {
      // Try both insecure and secure connections
      try {
        await request(
          { port, host: '127.0.0.1', token, insecure: true },
          'POST',
          '/v1/shutdown',
        );
      } catch {
        // Try HTTPS if HTTP fails
        try {
          await request(
            { port, host: '127.0.0.1', token, rejectUnauthorized: false },
            'POST',
            '/v1/shutdown',
          );
        } catch {
          // Fall through to force kill
        }
      }

      // Wait for process to exit
      const exitTimeout = 5000;
      const exitStart = Date.now();
      while (Date.now() - exitStart < exitTimeout) {
        try {
          process.kill(pid, 0);
          await new Promise((resolve) => setTimeout(resolve, 200));
        } catch {
          // Process is gone — success
          cleanupFiles(pidFile, portFile);
          return { success: true, pid };
        }
      }
    } catch {
      // HTTP shutdown failed, fall through to force kill
    }
  }

  // Force kill the process
  try {
    killProcess(pid);
  } catch (err) {
    return {
      success: false,
      pid,
      error: `Failed to stop daemon (PID ${pid}): ${err instanceof Error ? err.message : err}`,
    };
  }

  // Wait for the process to exit
  const killTimeout = 5000;
  const killStart = Date.now();
  while (Date.now() - killStart < killTimeout) {
    try {
      process.kill(pid, 0);
      await new Promise((resolve) => setTimeout(resolve, 200));
    } catch {
      // Process is gone — success
      cleanupFiles(pidFile, portFile);
      return { success: true, pid };
    }
  }

  // If still running after timeout, report failure
  return {
    success: false,
    pid,
    error: `Daemon (PID ${pid}) did not stop within 5 seconds`,
  };
}

/**
 * Restart the vault daemon: stop, then start.
 */
export async function restartDaemon(opts: DaemonStartOptions = {}): Promise<DaemonStartResult> {
  // Stop first (ignore errors if not running)
  const stopResult = await stopDaemon({
    pidFile: opts.pidFile,
  });

  // If it was running and we failed to stop, report the error
  if (!stopResult.success && stopResult.pid) {
    return {
      success: false,
      error: `Failed to stop existing daemon: ${stopResult.error}`,
    };
  }

  // Brief pause to allow port to be released
  await new Promise((resolve) => setTimeout(resolve, 500));

  // Start fresh
  return startDaemon(opts);
}

/**
 * Kill a process by PID.
 * On Windows, uses taskkill. On Unix, uses SIGTERM.
 */
function killProcess(pid: number): void {
  if (process.platform === 'win32') {
    // On Windows, use taskkill to force-kill the process tree
    try {
      execSync(`taskkill /PID ${pid} /F /T`, { stdio: 'ignore' });
    } catch {
      // Process may already be gone
    }
  } else {
    process.kill(pid, 'SIGTERM');
  }
}

/**
 * Clean up PID and port files after daemon stops.
 */
function cleanupFiles(pidFile: string, portFile: string): void {
  try {
    if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile);
  } catch { /* ok */ }
  try {
    if (fs.existsSync(portFile)) fs.unlinkSync(portFile);
  } catch { /* ok */ }
}
