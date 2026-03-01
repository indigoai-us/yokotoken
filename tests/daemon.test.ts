/**
 * Tests for daemon mode — US-009: Daemon mode with auto-start.
 *
 * Covers:
 * - Log rotation (rotateLogIfNeeded)
 * - Starting a daemon process (writes PID file, starts background server)
 * - Stopping a daemon (graceful shutdown, PID cleanup)
 * - Restarting a daemon
 * - Error cases: already running, not running for stop, stale PID file
 * - Cross-platform PID checking
 * - Clear error message when server not running (SDK/CLI)
 *
 * IMPORTANT: Integration tests require compiled JS. Run `npx tsc` before
 * running these tests. The daemon spawns `node dist/cli.js serve` as a
 * background process.
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import {
  rotateLogIfNeeded,
  getDefaultLogFile,
  MAX_LOG_SIZE,
  startDaemon,
  stopDaemon,
  restartDaemon,
} from '../src/daemon.js';
import { isServerRunning } from '../src/server.js';
import { VaultEngine } from '../src/vault.js';
import { request } from '../src/client.js';
import { readTokenFile } from '../src/auth.js';
import { VaultSdkError, getSecret } from '../src/sdk.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-daemon-passphrase-2026';

// Path to the compiled CLI script — the daemon spawns `node <cliPath> serve`
const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');

// ─── Log rotation ────────────────────────────────────────────────────

describe('Daemon — log rotation', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-daemon-log-'));
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should not rotate a log file that does not exist', () => {
    const logFile = path.join(tmpDir, 'vault.log');
    // Should not throw
    rotateLogIfNeeded(logFile);
    expect(fs.existsSync(logFile)).toBe(false);
  });

  it('should not rotate a small log file', () => {
    const logFile = path.join(tmpDir, 'vault.log');
    fs.writeFileSync(logFile, 'small log content\n');

    rotateLogIfNeeded(logFile);

    // Original file should still exist
    expect(fs.existsSync(logFile)).toBe(true);
    // No rotated file
    expect(fs.existsSync(logFile + '.1')).toBe(false);
  });

  it('should rotate a log file that exceeds MAX_LOG_SIZE', () => {
    const logFile = path.join(tmpDir, 'vault.log');
    // Create a file just over MAX_LOG_SIZE
    const bigContent = Buffer.alloc(MAX_LOG_SIZE + 1, 'A');
    fs.writeFileSync(logFile, bigContent);

    rotateLogIfNeeded(logFile);

    // Original should be gone (renamed)
    expect(fs.existsSync(logFile)).toBe(false);
    // Rotated file should exist
    expect(fs.existsSync(logFile + '.1')).toBe(true);
    const rotatedSize = fs.statSync(logFile + '.1').size;
    expect(rotatedSize).toBe(MAX_LOG_SIZE + 1);
  });

  it('should overwrite existing rotated file on rotation', () => {
    const logFile = path.join(tmpDir, 'vault.log');
    const rotatedFile = logFile + '.1';

    // Create an old rotated file
    fs.writeFileSync(rotatedFile, 'old rotated content');

    // Create a new oversized log file
    const bigContent = Buffer.alloc(MAX_LOG_SIZE + 100, 'B');
    fs.writeFileSync(logFile, bigContent);

    rotateLogIfNeeded(logFile);

    // Rotated file should be the new content
    expect(fs.existsSync(rotatedFile)).toBe(true);
    const rotatedSize = fs.statSync(rotatedFile).size;
    expect(rotatedSize).toBe(MAX_LOG_SIZE + 100);
  });

  it('should rotate a file at exactly MAX_LOG_SIZE (>= boundary)', () => {
    const logFile = path.join(tmpDir, 'vault.log');
    const content = Buffer.alloc(MAX_LOG_SIZE, 'C');
    fs.writeFileSync(logFile, content);

    rotateLogIfNeeded(logFile);

    // Our implementation uses >= so this WILL rotate
    expect(fs.existsSync(logFile + '.1')).toBe(true);
  });
});

// ─── getDefaultLogFile ───────────────────────────────────────────────

describe('Daemon — getDefaultLogFile', () => {
  it('should return a path ending with vault.log', () => {
    const logFile = getDefaultLogFile();
    expect(logFile).toMatch(/vault\.log$/);
  });
});

// ─── MAX_LOG_SIZE constant ───────────────────────────────────────────

describe('Daemon — constants', () => {
  it('should define MAX_LOG_SIZE as 10 MB', () => {
    expect(MAX_LOG_SIZE).toBe(10 * 1024 * 1024);
  });
});

// ─── Daemon lifecycle integration tests ──────────────────────────────
// These tests spawn actual background processes via the compiled CLI.
// They use HQ_VAULT_DIR (via pidFile path) to isolate from real vault.

describe('Daemon — start/stop lifecycle', () => {
  let tmpDir: string;
  let vaultPath: string;
  let pidFile: string;
  let portFile: string;
  let tokenFile: string;
  let logFile: string;

  beforeAll(() => {
    // Verify compiled CLI exists
    if (!fs.existsSync(CLI_PATH)) {
      throw new Error(
        `Compiled CLI not found at ${CLI_PATH}. Run "npx tsc" before running daemon tests.`
      );
    }

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-daemon-'));
    vaultPath = path.join(tmpDir, 'vault.db');
    pidFile = path.join(tmpDir, 'vault.pid');
    portFile = path.join(tmpDir, 'vault.port');
    tokenFile = path.join(tmpDir, 'token');
    logFile = path.join(tmpDir, 'vault.log');

    // Pre-initialize a vault
    const vault = new VaultEngine(vaultPath);
    vault.init(PASSPHRASE);
    vault.close();
  });

  afterAll(async () => {
    // Make sure daemon is stopped
    try {
      await stopDaemon({ pidFile, portFile, tokenFile });
    } catch { /* ok */ }
    // Wait a moment for cleanup
    await new Promise((resolve) => setTimeout(resolve, 1000));
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should start a daemon process and write PID file', async () => {
    const result = await startDaemon({
      vaultPath,
      insecure: true,
      port: 0,
      logFile,
      pidFile,
      cliPath: CLI_PATH,
    });

    expect(result.success).toBe(true);
    expect(typeof result.pid).toBe('number');
    expect(result.pid).toBeGreaterThan(0);
    expect(result.logFile).toBe(logFile);

    // PID file should exist
    expect(fs.existsSync(pidFile)).toBe(true);
    const writtenPid = parseInt(fs.readFileSync(pidFile, 'utf-8').trim(), 10);
    expect(writtenPid).toBe(result.pid);
  }, 15000);

  it('should report the daemon as running via isServerRunning', () => {
    const { running, pid } = isServerRunning(pidFile);
    expect(running).toBe(true);
    expect(typeof pid).toBe('number');
  });

  it('should be reachable via HTTP after daemon start', async () => {
    // Read port and token from files
    expect(fs.existsSync(portFile)).toBe(true);
    const port = parseInt(fs.readFileSync(portFile, 'utf-8').trim(), 10);
    expect(port).toBeGreaterThan(0);

    expect(fs.existsSync(tokenFile)).toBe(true);
    const token = readTokenFile(tokenFile);
    expect(token).toBeTruthy();

    // Make a request to the daemon
    const res = await request(
      { port, host: '127.0.0.1', token: token!, insecure: true },
      'GET',
      '/v1/status',
    );

    expect(res.statusCode).toBe(200);
    expect(res.body.serverRunning).toBe(true);
    expect(res.body.locked).toBe(true);
  }, 10000);

  it('should refuse to start a second daemon', async () => {
    const result = await startDaemon({
      vaultPath,
      insecure: true,
      port: 0,
      logFile,
      pidFile,
      cliPath: CLI_PATH,
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('already running');
  });

  it('should have written logs to the log file', async () => {
    expect(fs.existsSync(logFile)).toBe(true);
    // On Windows, log file writes may be buffered. Give a moment for flush.
    let content = fs.readFileSync(logFile, 'utf-8');
    if (content.length === 0) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      content = fs.readFileSync(logFile, 'utf-8');
    }
    expect(content.length).toBeGreaterThan(0);
    // Should contain server startup messages
    expect(content).toContain('hq-vault server listening');
  }, 5000);

  it('should stop the daemon gracefully', async () => {
    const result = await stopDaemon({ pidFile, portFile, tokenFile });

    expect(result.success).toBe(true);
    expect(typeof result.pid).toBe('number');

    // PID file should be cleaned up
    expect(fs.existsSync(pidFile)).toBe(false);
  }, 15000);

  it('should report not running after stop', () => {
    const { running } = isServerRunning(pidFile);
    expect(running).toBe(false);
  });

  it('should fail to stop when not running', async () => {
    const result = await stopDaemon({ pidFile, portFile, tokenFile });
    expect(result.success).toBe(false);
    expect(result.error).toContain('not running');
  });
});

// ─── Restart ─────────────────────────────────────────────────────────

describe('Daemon — restart', () => {
  let tmpDir: string;
  let vaultPath: string;
  let pidFile: string;
  let portFile: string;
  let tokenFile: string;
  let logFile: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-daemon-restart-'));
    vaultPath = path.join(tmpDir, 'vault.db');
    pidFile = path.join(tmpDir, 'vault.pid');
    portFile = path.join(tmpDir, 'vault.port');
    tokenFile = path.join(tmpDir, 'token');
    logFile = path.join(tmpDir, 'vault.log');

    // Pre-initialize a vault
    const vault = new VaultEngine(vaultPath);
    vault.init(PASSPHRASE);
    vault.close();
  });

  afterAll(async () => {
    try {
      await stopDaemon({ pidFile, portFile, tokenFile });
    } catch { /* ok */ }
    await new Promise((resolve) => setTimeout(resolve, 1000));
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should restart even when nothing is running (start fresh)', async () => {
    const result = await restartDaemon({
      vaultPath,
      insecure: true,
      port: 0,
      logFile,
      pidFile,
      cliPath: CLI_PATH,
    });

    expect(result.success).toBe(true);
    expect(typeof result.pid).toBe('number');
    expect(result.pid).toBeGreaterThan(0);
  }, 20000);

  it('should restart a running daemon with a new PID', async () => {
    // Read current PID
    const oldPid = parseInt(fs.readFileSync(pidFile, 'utf-8').trim(), 10);

    const result = await restartDaemon({
      vaultPath,
      insecure: true,
      port: 0,
      logFile,
      pidFile,
      cliPath: CLI_PATH,
    });

    expect(result.success).toBe(true);
    expect(typeof result.pid).toBe('number');
    // New PID should be different from old one
    expect(result.pid).not.toBe(oldPid);
  }, 25000);

  it('should be reachable after restart', async () => {
    expect(fs.existsSync(portFile)).toBe(true);
    const port = parseInt(fs.readFileSync(portFile, 'utf-8').trim(), 10);
    const token = readTokenFile(tokenFile);

    const res = await request(
      { port, host: '127.0.0.1', token: token!, insecure: true },
      'GET',
      '/v1/status',
    );

    expect(res.statusCode).toBe(200);
    expect(res.body.serverRunning).toBe(true);
  }, 10000);
});

// ─── Stale PID file ──────────────────────────────────────────────────

describe('Daemon — stale PID file handling', () => {
  let tmpDir: string;
  let pidFile: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-daemon-stale-'));
    pidFile = path.join(tmpDir, 'vault.pid');
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should detect stale PID file (process does not exist)', () => {
    // Write a PID that doesn't exist (use a very high PID)
    fs.writeFileSync(pidFile, '999999999', 'utf-8');

    const { running } = isServerRunning(pidFile);
    expect(running).toBe(false);

    // Stale PID file should be cleaned up
    expect(fs.existsSync(pidFile)).toBe(false);
  });

  it('should handle non-numeric PID file content', () => {
    fs.writeFileSync(pidFile, 'not-a-number', 'utf-8');

    const { running } = isServerRunning(pidFile);
    expect(running).toBe(false);
  });

  it('should handle empty PID file', () => {
    fs.writeFileSync(pidFile, '', 'utf-8');

    const { running } = isServerRunning(pidFile);
    expect(running).toBe(false);
  });
});

// ─── SDK error when server not running ───────────────────────────────

describe('Daemon — SDK error when server is not running', () => {
  it('should throw VaultSdkError with CONNECTION_REFUSED code', async () => {
    try {
      await getSecret('test/path', {
        url: 'http://127.0.0.1:19999',
        token: 'fake-token',
      });
      // Should not reach here
      expect.unreachable('Expected VaultSdkError');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      const sdkErr = err as VaultSdkError;
      expect(sdkErr.code).toBe('CONNECTION_REFUSED');
      expect(sdkErr.message).toContain('hq-vault serve');
    }
  });
});

// ─── isServerRunning contract ────────────────────────────────────────

describe('Daemon — isServerRunning contract', () => {
  it('should return running=false when no PID file exists', () => {
    const { running } = isServerRunning('/tmp/nonexistent-pid-file-12345');
    expect(running).toBe(false);
  });
});
