/**
 * Tests for the vault server — US-002: CLI init, lock, unlock, status.
 *
 * These tests exercise the HTTP server that holds the master key in memory,
 * covering:
 * - POST /v1/init: vault initialization with passphrase
 * - POST /v1/unlock: unlock with correct/wrong passphrase
 * - POST /v1/lock: wipe decryption key from memory
 * - GET /v1/status: vault status reporting
 * - Auto-lock after idle timeout
 * - --force flag for reinitializing existing vault
 * - Error handling for uninitialized/already-initialized vaults
 *
 * Tests use the server's HTTP API directly via the client module,
 * avoiding stdin passphrase prompts (which are tested separately).
 *
 * US-004: Tests use insecure mode (plain HTTP) with a known token
 * for simplicity. Auth and TLS are tested in auth.test.ts and tls.test.ts.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { VaultEngine } from '../src/vault.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-server-passphrase-2026';
const WRONG_PASSPHRASE = 'wrong-passphrase-totally-wrong';
const TEST_TOKEN = 'test-server-token-for-testing';

/**
 * Helper: create a temporary directory and server config.
 */
function createTmpConfig(overrides?: Partial<ServerConfig>): {
  tmpDir: string;
  config: ServerConfig;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-server-'));
  const config: ServerConfig = {
    vaultPath: path.join(tmpDir, 'vault.db'),
    port: 0, // Let the OS pick a free port
    idleTimeoutMs: 0, // No auto-lock by default (tests control timing)
    pidFile: path.join(tmpDir, 'vault.pid'),
    portFile: path.join(tmpDir, 'vault.port'),
    tokenFile: path.join(tmpDir, 'token'),
    insecure: true, // Use plain HTTP for tests
    token: TEST_TOKEN,
    ...overrides,
  };
  return { tmpDir, config };
}

/**
 * Helper: get the actual port the server is listening on.
 */
function getPort(server: http.Server): number {
  const addr = server.address();
  if (typeof addr === 'object' && addr) {
    return addr.port;
  }
  throw new Error('Server has no address');
}

/**
 * Helper: create a client config from a running server (with auth token).
 */
function clientFor(server: http.Server): ClientConfig {
  return { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true };
}

// ─── init via server ────────────────────────────────────────────────
describe('Server — POST /v1/init', () => {
  let server: http.Server;
  let tmpDir: string;
  let config: ServerConfig;

  beforeAll(async () => {
    ({ tmpDir, config } = createTmpConfig());
    // For init tests, we do NOT pre-initialize the vault
    server = await createVaultServer(config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should initialize a new vault via the server', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/init', {
      passphrase: PASSPHRASE,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.message).toContain('initialized');
    expect(fs.existsSync(config.vaultPath)).toBe(true);
  });

  it('should reject double init without --force', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/init', {
      passphrase: PASSPHRASE,
    });

    expect(res.statusCode).toBe(409);
    expect(res.body.error).toContain('already initialized');
  });

  it('should reject init without passphrase', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/init', {});

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('Passphrase is required');
  });
});

// ─── init with --force ──────────────────────────────────────────────
describe('Server — POST /v1/init with force', () => {
  let server: http.Server;
  let tmpDir: string;
  let config: ServerConfig;

  beforeAll(async () => {
    ({ tmpDir, config } = createTmpConfig());
    // Pre-initialize with a vault
    const vault = new VaultEngine(config.vaultPath);
    vault.init(PASSPHRASE);
    vault.store('old/secret', 'should-be-gone');
    vault.close();

    server = await createVaultServer(config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should reinitialize vault with force flag', async () => {
    const client = clientFor(server);
    const newPassphrase = 'brand-new-passphrase-2026';

    const res = await request(client, 'POST', '/v1/init', {
      passphrase: newPassphrase,
      force: true,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);

    // Verify the vault is unlocked with the NEW passphrase and old secret is gone
    const statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(false);
    expect(statusRes.body.secretCount).toBe(0);
  });
});

// ─── unlock / lock ──────────────────────────────────────────────────
describe('Server — POST /v1/unlock and /v1/lock', () => {
  let server: http.Server;
  let tmpDir: string;
  let config: ServerConfig;

  beforeAll(async () => {
    ({ tmpDir, config } = createTmpConfig());
    // Pre-initialize the vault
    const vault = new VaultEngine(config.vaultPath);
    vault.init(PASSPHRASE);
    vault.store('test/secret', 'my-value');
    vault.close();

    server = await createVaultServer(config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should start in locked state', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(200);
    expect(res.body.locked).toBe(true);
  });

  it('should reject unlock with wrong passphrase', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/unlock', {
      passphrase: WRONG_PASSPHRASE,
    });

    expect(res.statusCode).toBe(401);
    expect(res.body.error).toContain('Invalid passphrase');

    // Still locked after failed attempt
    const statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(true);
  });

  it('should reject unlock without passphrase', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/unlock', {});
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('Passphrase is required');
  });

  it('should unlock with correct passphrase', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/unlock', {
      passphrase: PASSPHRASE,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.message).toContain('unlocked');

    // Verify unlocked status
    const statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(false);
    expect(statusRes.body.secretCount).toBe(1);
  });

  it('should handle unlock when already unlocked', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/unlock', {
      passphrase: PASSPHRASE,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.message).toContain('already unlocked');
  });

  it('should lock the vault and wipe the key', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/lock');

    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);

    // Verify locked
    const statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(true);
  });

  it('should be able to unlock again after locking', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/unlock', {
      passphrase: PASSPHRASE,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);

    const statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(false);
  });
});

// ─── status ─────────────────────────────────────────────────────────
describe('Server — GET /v1/status', () => {
  let server: http.Server;
  let tmpDir: string;
  let config: ServerConfig;

  beforeAll(async () => {
    ({ tmpDir, config } = createTmpConfig());
    const vault = new VaultEngine(config.vaultPath);
    vault.init(PASSPHRASE);
    vault.store('aws/key', 'AKIA-1234');
    vault.store('slack/token', 'xoxb-5678');
    vault.store('github/pat', 'ghp_abcd');
    vault.close();

    server = await createVaultServer(config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should report vault path', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/status');

    expect(res.statusCode).toBe(200);
    expect(res.body.vaultPath).toBe(config.vaultPath);
  });

  it('should report locked/unlocked state', async () => {
    const client = clientFor(server);

    // Initially locked
    let res = await request(client, 'GET', '/v1/status');
    expect(res.body.locked).toBe(true);

    // Unlock
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
    res = await request(client, 'GET', '/v1/status');
    expect(res.body.locked).toBe(false);
  });

  it('should report correct secret count', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/status');
    expect(res.body.secretCount).toBe(3);
  });

  it('should report server is running', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/status');
    expect(res.body.serverRunning).toBe(true);
    expect(typeof res.body.port).toBe('number');
  });

  it('should report idle timeout setting', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/status');
    expect(res.body.idleTimeoutMs).toBe(0);
  });
});

// ─── uninitialized vault ────────────────────────────────────────────
describe('Server — uninitialized vault', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;
    // Do NOT pre-initialize — just create an empty server
    server = await createVaultServer(result.config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should reject unlock on uninitialized vault', async () => {
    const client = clientFor(server);
    const res = await request(client, 'POST', '/v1/unlock', {
      passphrase: PASSPHRASE,
    });

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('not initialized');
  });

  it('should report not initialized in status', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/status');
    expect(res.body.initialized).toBe(false);
    expect(res.body.locked).toBe(true);
    expect(res.body.secretCount).toBe(0);
  });
});

// ─── auto-lock ──────────────────────────────────────────────────────
describe('Server — auto-lock after idle timeout', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig({
      idleTimeoutMs: 500, // 500ms for fast testing
    });
    tmpDir = result.tmpDir;

    // Pre-initialize
    const vault = new VaultEngine(result.config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();

    server = await createVaultServer(result.config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should auto-lock after idle timeout', async () => {
    const client = clientFor(server);

    // Unlock
    const unlockRes = await request(client, 'POST', '/v1/unlock', {
      passphrase: PASSPHRASE,
    });
    expect(unlockRes.body.ok).toBe(true);

    // Verify unlocked
    let statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(false);

    // Wait for idle timeout (500ms + buffer)
    await new Promise((resolve) => setTimeout(resolve, 800));

    // Should now be locked
    statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(true);
  });

  it('should reset idle timer on activity', async () => {
    const client = clientFor(server);

    // Unlock
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });

    // Make activity within the timeout window
    await new Promise((resolve) => setTimeout(resolve, 300));
    let statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(false); // Activity resets timer

    await new Promise((resolve) => setTimeout(resolve, 300));
    statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(false); // Still alive because of activity

    // Now wait the full timeout without activity
    await new Promise((resolve) => setTimeout(resolve, 800));
    statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(true); // Auto-locked
  });
});

// ─── 404 for unknown endpoints ──────────────────────────────────────
describe('Server — error handling', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;
    server = await createVaultServer(result.config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should return 404 for unknown endpoints', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/nonexistent');
    expect(res.statusCode).toBe(404);
  });

  it('should return 404 for wrong methods', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/lock');
    expect(res.statusCode).toBe(404);
  });
});

// ─── PID and port files ─────────────────────────────────────────────
describe('Server — PID and port files', () => {
  let server: http.Server;
  let tmpDir: string;
  let config: ServerConfig;

  beforeAll(async () => {
    ({ tmpDir, config } = createTmpConfig());
    server = await createVaultServer(config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should write a PID file when started', () => {
    expect(fs.existsSync(config.pidFile)).toBe(true);
    const pid = parseInt(fs.readFileSync(config.pidFile, 'utf-8').trim(), 10);
    expect(pid).toBe(process.pid);
  });

  it('should write a port file when started', () => {
    expect(fs.existsSync(config.portFile)).toBe(true);
    const port = parseInt(fs.readFileSync(config.portFile, 'utf-8').trim(), 10);
    expect(port).toBe(getPort(server));
  });

  it('should write a token file when started', () => {
    const tokenFile = config.tokenFile!;
    expect(fs.existsSync(tokenFile)).toBe(true);
    const token = fs.readFileSync(tokenFile, 'utf-8').trim();
    expect(token).toBe(TEST_TOKEN);
  });
});

// ─── passphrase security ────────────────────────────────────────────
describe('Server — passphrase security', () => {
  let server: http.Server;
  let tmpDir: string;
  let config: ServerConfig;

  beforeAll(async () => {
    ({ tmpDir, config } = createTmpConfig());
    const vault = new VaultEngine(config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();
    server = await createVaultServer(config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should not expose passphrase in any response', async () => {
    const client = clientFor(server);

    // Unlock
    const unlockRes = await request(client, 'POST', '/v1/unlock', {
      passphrase: PASSPHRASE,
    });
    const unlockBody = JSON.stringify(unlockRes.body);
    expect(unlockBody).not.toContain(PASSPHRASE);

    // Status
    const statusRes = await request(client, 'GET', '/v1/status');
    const statusBody = JSON.stringify(statusRes.body);
    expect(statusBody).not.toContain(PASSPHRASE);

    // Lock
    const lockRes = await request(client, 'POST', '/v1/lock');
    const lockBody = JSON.stringify(lockRes.body);
    expect(lockBody).not.toContain(PASSPHRASE);

    // Failed unlock
    const failRes = await request(client, 'POST', '/v1/unlock', {
      passphrase: WRONG_PASSPHRASE,
    });
    const failBody = JSON.stringify(failRes.body);
    expect(failBody).not.toContain(WRONG_PASSPHRASE);
    expect(failBody).not.toContain(PASSPHRASE);
  });
});
