/**
 * Tests for audit logging — US-010.
 *
 * Covers:
 * - AuditLogger: append-only file writes, JSONL format
 * - Audit logging on secret operations (get, store, delete, list)
 * - Audit logging on failed auth attempts
 * - Secret values are NEVER logged
 * - readAuditLog: reading, parsing, and filtering
 * - tailAuditLog: real-time following
 * - CLI audit command filtering (--path, --token, --since)
 * - Audit log immutability (no API endpoint to modify it)
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { VaultEngine } from '../src/vault.js';
import {
  AuditLogger,
  readAuditLog,
  tailAuditLog,
  getDefaultAuditLogPath,
  type AuditEntry,
} from '../src/audit.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-audit-passphrase-2026';
const TEST_TOKEN = 'test-audit-token-for-testing';

/**
 * Helper: create a temporary directory and server config with audit log.
 */
function createTmpConfig(overrides?: Partial<ServerConfig>): {
  tmpDir: string;
  config: ServerConfig;
  auditLogPath: string;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-audit-'));
  const auditLogPath = path.join(tmpDir, 'audit.log');
  const config: ServerConfig = {
    vaultPath: path.join(tmpDir, 'vault.db'),
    port: 0,
    idleTimeoutMs: 0,
    pidFile: path.join(tmpDir, 'vault.pid'),
    portFile: path.join(tmpDir, 'vault.port'),
    tokenFile: path.join(tmpDir, 'token'),
    insecure: true,
    token: TEST_TOKEN,
    auditLogPath,
    ...overrides,
  };
  return { tmpDir, config, auditLogPath };
}

function getPort(server: http.Server): number {
  const addr = server.address();
  if (typeof addr === 'object' && addr) return addr.port;
  throw new Error('Server has no address');
}

function clientFor(server: http.Server): ClientConfig {
  return { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true };
}

// ─── AuditLogger unit tests ─────────────────────────────────────────

describe('AuditLogger — unit', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-audit-unit-'));
    logPath = path.join(tmpDir, 'audit.log');
  });

  it('should create audit log file on first write', () => {
    const logger = new AuditLogger(logPath);
    expect(fs.existsSync(logPath)).toBe(false);

    logger.logAccess('secret.get', {
      tokenName: 'test-token',
      secretPath: 'aws/key',
      ip: '127.0.0.1',
    });

    expect(fs.existsSync(logPath)).toBe(true);
    logger.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should write JSONL format (one JSON object per line)', () => {
    const logger = new AuditLogger(logPath);

    logger.logAccess('secret.get', {
      tokenName: 'admin',
      secretPath: 'aws/key',
      ip: '127.0.0.1',
    });

    logger.logAccess('secret.store', {
      tokenName: 'admin',
      secretPath: 'slack/token',
      ip: '127.0.0.1',
    });

    logger.close();

    const content = fs.readFileSync(logPath, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(2);

    const entry1 = JSON.parse(lines[0]) as AuditEntry;
    expect(entry1.operation).toBe('secret.get');
    expect(entry1.secretPath).toBe('aws/key');
    expect(entry1.tokenName).toBe('admin');
    expect(entry1.ip).toBe('127.0.0.1');
    expect(entry1.timestamp).toBeTruthy();

    const entry2 = JSON.parse(lines[1]) as AuditEntry;
    expect(entry2.operation).toBe('secret.store');
    expect(entry2.secretPath).toBe('slack/token');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should log auth failures with reason', () => {
    const logger = new AuditLogger(logPath);

    logger.logAuthFailure('192.168.1.100', 'invalid token');

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);
    expect(entries[0].operation).toBe('auth.failure');
    expect(entries[0].tokenName).toBeNull();
    expect(entries[0].ip).toBe('192.168.1.100');
    expect(entries[0].detail).toBe('invalid token');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should append (never overwrite) existing entries', () => {
    const logger = new AuditLogger(logPath);

    logger.logAccess('secret.get', {
      tokenName: 'a',
      secretPath: 'path/1',
      ip: '127.0.0.1',
    });
    logger.close();

    // Re-open the same log path
    const logger2 = new AuditLogger(logPath);
    logger2.logAccess('secret.store', {
      tokenName: 'b',
      secretPath: 'path/2',
      ip: '127.0.0.1',
    });
    logger2.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(2);
    expect(entries[0].operation).toBe('secret.get');
    expect(entries[1].operation).toBe('secret.store');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should include detail field when provided', () => {
    const logger = new AuditLogger(logPath);

    logger.logAccess('secret.list', {
      tokenName: 'admin',
      ip: '127.0.0.1',
      detail: 'prefix=aws/',
    });
    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries[0].detail).toBe('prefix=aws/');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should set detail to null when not provided', () => {
    const logger = new AuditLogger(logPath);

    logger.logAccess('secret.get', {
      tokenName: 'admin',
      secretPath: 'test/secret',
      ip: '127.0.0.1',
    });
    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries[0].detail).toBeNull();

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should report log path via getLogPath()', () => {
    const logger = new AuditLogger(logPath);
    expect(logger.getLogPath()).toBe(logPath);
    logger.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ─── readAuditLog — filtering ────────────────────────────────────────

describe('readAuditLog — filtering', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-audit-filter-'));
    logPath = path.join(tmpDir, 'audit.log');
  });

  function seedLog(): void {
    const logger = new AuditLogger(logPath);

    // Seed with diverse entries
    logger.logAccess('secret.get', {
      tokenName: 'admin',
      secretPath: 'aws/access-key',
      ip: '127.0.0.1',
    });
    logger.logAccess('secret.store', {
      tokenName: 'ci-bot',
      secretPath: 'github/pat',
      ip: '127.0.0.1',
    });
    logger.logAccess('secret.list', {
      tokenName: 'admin',
      ip: '127.0.0.1',
      detail: 'prefix=aws/',
    });
    logger.logAccess('secret.delete', {
      tokenName: 'ci-bot',
      secretPath: 'old/secret',
      ip: '127.0.0.1',
    });
    logger.logAuthFailure('10.0.0.1', 'invalid token');
    logger.logAccess('secret.get', {
      tokenName: 'admin',
      secretPath: 'aws/secret-key',
      ip: '127.0.0.1',
    });

    logger.close();
  }

  it('should return all entries when no filters', () => {
    seedLog();
    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(6);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should filter by path (substring match)', () => {
    seedLog();
    const entries = readAuditLog(logPath, { path: 'aws/' });
    expect(entries).toHaveLength(2);
    expect(entries.every((e) => e.secretPath?.includes('aws/'))).toBe(true);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should filter by token name (exact match)', () => {
    seedLog();
    const entries = readAuditLog(logPath, { token: 'ci-bot' });
    expect(entries).toHaveLength(2);
    expect(entries.every((e) => e.tokenName === 'ci-bot')).toBe(true);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should filter by since timestamp', () => {
    // Create entries with controlled timestamps
    const logger = new AuditLogger(logPath);
    logger.logAccess('secret.get', {
      tokenName: 'admin',
      secretPath: 'a',
      ip: '127.0.0.1',
    });
    logger.close();

    // Read all entries
    const allEntries = readAuditLog(logPath);
    expect(allEntries.length).toBeGreaterThanOrEqual(1);

    // Filter since a time in the past should return all
    const pastEntries = readAuditLog(logPath, { since: '2020-01-01T00:00:00Z' });
    expect(pastEntries.length).toBe(allEntries.length);

    // Filter since a time in the future should return none
    const futureEntries = readAuditLog(logPath, { since: '2099-01-01T00:00:00Z' });
    expect(futureEntries).toHaveLength(0);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should apply limit (returns most recent N entries)', () => {
    seedLog();
    const entries = readAuditLog(logPath, { limit: 2 });
    expect(entries).toHaveLength(2);
    // Should be the last 2 entries (most recent)
    expect(entries[0].operation).toBe('auth.failure');
    expect(entries[1].operation).toBe('secret.get');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should combine multiple filters', () => {
    seedLog();
    const entries = readAuditLog(logPath, { token: 'admin', path: 'aws/' });
    expect(entries).toHaveLength(2);
    expect(entries.every((e) => e.tokenName === 'admin')).toBe(true);
    expect(entries.every((e) => e.secretPath?.includes('aws/'))).toBe(true);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should return empty array when log file does not exist', () => {
    const entries = readAuditLog(path.join(tmpDir, 'nonexistent.log'));
    expect(entries).toHaveLength(0);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should skip malformed JSON lines gracefully', () => {
    // Write some valid and some invalid lines
    fs.writeFileSync(logPath, [
      JSON.stringify({ timestamp: '2026-01-01T00:00:00Z', operation: 'secret.get', tokenName: 'a', secretPath: 'x', ip: '1', detail: null }),
      'this is not json',
      JSON.stringify({ timestamp: '2026-01-02T00:00:00Z', operation: 'secret.store', tokenName: 'b', secretPath: 'y', ip: '2', detail: null }),
    ].join('\n') + '\n');

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(2);
    expect(entries[0].operation).toBe('secret.get');
    expect(entries[1].operation).toBe('secret.store');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ─── tailAuditLog ────────────────────────────────────────────────────

describe('tailAuditLog — real-time following', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-audit-tail-'));
    logPath = path.join(tmpDir, 'audit.log');
  });

  it('should receive new entries appended to the log', async () => {
    const received: AuditEntry[] = [];

    const stop = tailAuditLog(logPath, (entry) => {
      received.push(entry);
    });

    // Write entries after tailing started
    const logger = new AuditLogger(logPath);
    logger.logAccess('secret.get', {
      tokenName: 'admin',
      secretPath: 'test/path',
      ip: '127.0.0.1',
    });
    logger.logAccess('secret.store', {
      tokenName: 'admin',
      secretPath: 'test/path2',
      ip: '127.0.0.1',
    });
    logger.close();

    // Wait for poll interval (200ms) + some buffer
    await new Promise((resolve) => setTimeout(resolve, 500));

    stop();

    expect(received).toHaveLength(2);
    expect(received[0].operation).toBe('secret.get');
    expect(received[1].operation).toBe('secret.store');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should handle stop being called immediately', () => {
    const stop = tailAuditLog(logPath, () => {});
    stop(); // Should not throw
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ─── Server integration — audit logging on secret operations ─────────

describe('Server audit — secret operations', () => {
  let server: http.Server;
  let tmpDir: string;
  let config: ServerConfig;
  let auditLogPath: string;

  beforeAll(async () => {
    ({ tmpDir, config, auditLogPath } = createTmpConfig());
    const vault = await VaultEngine.open(config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('existing/secret', 'value-123');
    await vault.close();

    server = await createVaultServer(config) as http.Server;

    // Unlock the vault
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should audit log a secret store operation', async () => {
    const client = clientFor(server);

    const res = await request(client, 'PUT', '/v1/secrets/test%2Faudit-store', {
      value: 'super-secret-value-DO-NOT-LOG',
      type: 'api-key',
    });
    expect(res.statusCode).toBe(200);

    const entries = readAuditLog(auditLogPath);
    const storeEntries = entries.filter((e) => e.operation === 'secret.store');
    expect(storeEntries.length).toBeGreaterThanOrEqual(1);

    const last = storeEntries[storeEntries.length - 1];
    expect(last.secretPath).toBe('test/audit-store');
    expect(last.tokenName).toBe('bootstrap');
    expect(last.ip).toBeTruthy();
  });

  it('should audit log a secret get operation', async () => {
    const client = clientFor(server);

    const res = await request(client, 'GET', '/v1/secrets/existing%2Fsecret');
    expect(res.statusCode).toBe(200);

    const entries = readAuditLog(auditLogPath);
    const getEntries = entries.filter((e) => e.operation === 'secret.get');
    expect(getEntries.length).toBeGreaterThanOrEqual(1);

    const last = getEntries[getEntries.length - 1];
    expect(last.secretPath).toBe('existing/secret');
    expect(last.tokenName).toBe('bootstrap');
  });

  it('should audit log a secret list operation', async () => {
    const client = clientFor(server);

    const res = await request(client, 'GET', '/v1/secrets?prefix=existing');
    expect(res.statusCode).toBe(200);

    const entries = readAuditLog(auditLogPath);
    const listEntries = entries.filter((e) => e.operation === 'secret.list');
    expect(listEntries.length).toBeGreaterThanOrEqual(1);

    const last = listEntries[listEntries.length - 1];
    expect(last.detail).toBe('prefix=existing');
    expect(last.tokenName).toBe('bootstrap');
  });

  it('should audit log a secret delete operation', async () => {
    const client = clientFor(server);

    // First store a secret to delete
    await request(client, 'PUT', '/v1/secrets/to-delete', {
      value: 'temp-value',
    });

    const res = await request(client, 'DELETE', '/v1/secrets/to-delete');
    expect(res.statusCode).toBe(200);

    const entries = readAuditLog(auditLogPath);
    const deleteEntries = entries.filter((e) => e.operation === 'secret.delete');
    expect(deleteEntries.length).toBeGreaterThanOrEqual(1);

    const last = deleteEntries[deleteEntries.length - 1];
    expect(last.secretPath).toBe('to-delete');
    expect(last.tokenName).toBe('bootstrap');
  });

  it('should NEVER log secret values in the audit log', async () => {
    const client = clientFor(server);
    const secretValue = 'SUPER-SECRET-VALUE-SHOULD-NOT-APPEAR-IN-LOG';

    // Store a secret with a unique value
    await request(client, 'PUT', '/v1/secrets/sensitive/cred', {
      value: secretValue,
    });

    // Get the secret
    await request(client, 'GET', '/v1/secrets/sensitive%2Fcred');

    // Read the raw audit log content and verify value is NOT present
    const rawContent = fs.readFileSync(auditLogPath, 'utf-8');
    expect(rawContent).not.toContain(secretValue);

    // Also verify no entry has a field containing the value
    const entries = readAuditLog(auditLogPath);
    for (const entry of entries) {
      const entryStr = JSON.stringify(entry);
      expect(entryStr).not.toContain(secretValue);
    }
  });

  it('should not audit log non-secret operations (status, lock, unlock)', async () => {
    const client = clientFor(server);

    // Count current entries
    const beforeEntries = readAuditLog(auditLogPath);

    // Make non-secret API calls
    await request(client, 'GET', '/v1/status');
    await request(client, 'POST', '/v1/lock');
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });

    const afterEntries = readAuditLog(auditLogPath);

    // The count should not have increased (no audit for status/lock/unlock)
    expect(afterEntries.length).toBe(beforeEntries.length);
  });
});

// ─── Server integration — auth failure logging ──────────────────────

describe('Server audit — auth failures', () => {
  let server: http.Server;
  let tmpDir: string;
  let auditLogPath: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;
    auditLogPath = result.auditLogPath;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should audit log failed auth attempts (invalid token)', async () => {
    const badClient: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      token: 'totally-wrong-token',
      insecure: true,
    };

    const res = await request(badClient, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);

    const entries = readAuditLog(auditLogPath);
    const authFailures = entries.filter((e) => e.operation === 'auth.failure');
    expect(authFailures.length).toBeGreaterThanOrEqual(1);

    const last = authFailures[authFailures.length - 1];
    expect(last.detail).toBe('invalid token');
    expect(last.ip).toBeTruthy();
    expect(last.tokenName).toBeNull();
  });

  it('should audit log failed auth attempts (no token)', async () => {
    const noTokenClient: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      insecure: true,
    };

    const res = await request(noTokenClient, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);

    const entries = readAuditLog(auditLogPath);
    const authFailures = entries.filter((e) => e.operation === 'auth.failure');
    expect(authFailures.length).toBeGreaterThanOrEqual(2);
  });

  it('should include IP address in auth failure logs', async () => {
    const entries = readAuditLog(auditLogPath);
    const authFailures = entries.filter((e) => e.operation === 'auth.failure');

    for (const failure of authFailures) {
      expect(failure.ip).toBeTruthy();
      // Should be localhost since tests connect locally
      expect(['127.0.0.1', '::1', '::ffff:127.0.0.1']).toContain(failure.ip);
    }
  });
});

// ─── Audit log immutability ──────────────────────────────────────────

describe('Server audit — immutability', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should not expose any API endpoint to modify the audit log', async () => {
    const client = clientFor(server);

    // Try various methods on /v1/audit — all should 404
    const getRes = await request(client, 'GET', '/v1/audit');
    expect(getRes.statusCode).toBe(404);

    const postRes = await request(client, 'POST', '/v1/audit');
    expect(postRes.statusCode).toBe(404);

    const deleteRes = await request(client, 'DELETE', '/v1/audit');
    expect(deleteRes.statusCode).toBe(404);

    const putRes = await request(client, 'PUT', '/v1/audit');
    expect(putRes.statusCode).toBe(404);
  });
});

// ─── getDefaultAuditLogPath ──────────────────────────────────────────

describe('getDefaultAuditLogPath', () => {
  it('should return a path ending in audit.log', () => {
    const logPath = getDefaultAuditLogPath();
    expect(logPath.endsWith('audit.log')).toBe(true);
  });

  it('should respect HQ_VAULT_DIR environment variable', () => {
    const original = process.env.HQ_VAULT_DIR;
    try {
      process.env.HQ_VAULT_DIR = '/custom/vault/dir';
      const logPath = getDefaultAuditLogPath();
      // Normalize path separators for cross-platform
      expect(logPath.replace(/\\/g, '/')).toBe('/custom/vault/dir/audit.log');
    } finally {
      if (original !== undefined) {
        process.env.HQ_VAULT_DIR = original;
      } else {
        delete process.env.HQ_VAULT_DIR;
      }
    }
  });
});

// ─── Audit with managed tokens (token name tracking) ─────────────────

describe('Server audit — managed token name tracking', () => {
  let server: http.Server;
  let tmpDir: string;
  let auditLogPath: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;
    auditLogPath = result.auditLogPath;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('test/secret', 'value');
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;

    // Unlock vault
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should log bootstrap token name for admin token', async () => {
    const client = clientFor(server);

    await request(client, 'GET', '/v1/secrets/test%2Fsecret');

    const entries = readAuditLog(auditLogPath);
    const getEntries = entries.filter((e) => e.operation === 'secret.get');
    expect(getEntries.length).toBeGreaterThanOrEqual(1);

    const last = getEntries[getEntries.length - 1];
    expect(last.tokenName).toBe('bootstrap');
  });

  it('should log managed token name for managed tokens', async () => {
    const client = clientFor(server);

    // Create a managed token
    const createRes = await request(client, 'POST', '/v1/tokens', {
      name: 'ci-pipeline',
    });
    expect(createRes.statusCode).toBe(201);
    const managedToken = createRes.body.token as string;

    // Use the managed token to access a secret
    const managedClient: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      token: managedToken,
      insecure: true,
    };

    await request(managedClient, 'GET', '/v1/secrets/test%2Fsecret');

    const entries = readAuditLog(auditLogPath);
    const getEntries = entries.filter((e) => e.operation === 'secret.get');
    const last = getEntries[getEntries.length - 1];
    expect(last.tokenName).toBe('ci-pipeline');
  });
});
