/**
 * Tests for secret management — US-003: store, get, list, and delete secrets.
 *
 * These tests exercise the HTTP server endpoints for secret CRUD operations:
 * - PUT /v1/secrets/:path — Store a secret
 * - GET /v1/secrets/:path — Get a decrypted secret
 * - GET /v1/secrets?prefix= — List secrets by prefix
 * - DELETE /v1/secrets/:path — Delete a secret
 *
 * Also verifies:
 * - All operations fail when vault is locked
 * - Metadata support (type, description)
 * - Path prefix filtering
 * - Nonexistent secret handling
 * - Path encoding for special characters
 *
 * US-004: Tests use insecure mode (plain HTTP) with a known token.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { VaultEngine } from '../src/vault.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-secrets-passphrase-2026';
const TEST_TOKEN = 'test-secrets-token-for-testing';

/**
 * Helper: create a temporary directory and server config.
 */
function createTmpConfig(overrides?: Partial<ServerConfig>): {
  tmpDir: string;
  config: ServerConfig;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-secrets-'));
  const config: ServerConfig = {
    vaultPath: path.join(tmpDir, 'vault.db'),
    port: 0,
    idleTimeoutMs: 0,
    pidFile: path.join(tmpDir, 'vault.pid'),
    portFile: path.join(tmpDir, 'vault.port'),
    tokenFile: path.join(tmpDir, 'token'),
    insecure: true,
    token: TEST_TOKEN,
    ...overrides,
  };
  return { tmpDir, config };
}

function getPort(server: http.Server): number {
  const addr = server.address();
  if (typeof addr === 'object' && addr) return addr.port;
  throw new Error('Server has no address');
}

function clientFor(server: http.Server): ClientConfig {
  return { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true };
}

// ─── locked vault rejection ──────────────────────────────────────────
describe('Secrets — locked vault rejects all operations', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    // Pre-initialize but leave locked
    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should reject PUT /v1/secrets/:path when locked', async () => {
    const client = clientFor(server);
    const res = await request(client, 'PUT', '/v1/secrets/test/key', {
      value: 'my-secret',
    });
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toContain('locked');
  });

  it('should reject GET /v1/secrets/:path when locked', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/secrets/test/key');
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toContain('locked');
  });

  it('should reject GET /v1/secrets (list) when locked', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/secrets');
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toContain('locked');
  });

  it('should reject DELETE /v1/secrets/:path when locked', async () => {
    const client = clientFor(server);
    const res = await request(client, 'DELETE', '/v1/secrets/test/key');
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toContain('locked');
  });
});

// ─── store secrets ───────────────────────────────────────────────────
describe('Secrets — PUT /v1/secrets/:path (store)', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;

    // Unlock the vault
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should store a simple secret', async () => {
    const client = clientFor(server);
    const res = await request(client, 'PUT', '/v1/secrets/api/key', {
      value: 'sk-1234567890',
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.path).toBe('api/key');
    expect(res.body.bytes).toBe(Buffer.byteLength('sk-1234567890', 'utf-8'));
  });

  it('should store a secret with metadata', async () => {
    const client = clientFor(server);
    const res = await request(client, 'PUT', '/v1/secrets/slack/token', {
      value: 'xoxb-1234-5678',
      type: 'oauth-token',
      description: 'Slack bot token for Indigo workspace',
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.metadata).toEqual({
      type: 'oauth-token',
      description: 'Slack bot token for Indigo workspace',
    });
  });

  it('should overwrite an existing secret', async () => {
    const client = clientFor(server);

    // Store initial
    await request(client, 'PUT', '/v1/secrets/mutable/key', {
      value: 'version-1',
    });

    // Overwrite
    const res = await request(client, 'PUT', '/v1/secrets/mutable/key', {
      value: 'version-2',
    });
    expect(res.statusCode).toBe(200);

    // Verify overwritten
    const getRes = await request(client, 'GET', '/v1/secrets/mutable/key');
    expect(getRes.body.value).toBe('version-2');
  });

  it('should reject store without value', async () => {
    const client = clientFor(server);
    const res = await request(client, 'PUT', '/v1/secrets/no/value', {});
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('value is required');
  });

  it('should reject invalid paths', async () => {
    const client = clientFor(server);

    const res = await request(client, 'PUT', '/v1/secrets/__vault_test', {
      value: 'trying-to-access-reserved',
    });
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('reserved');
  });

  it('should handle multi-line and special character values', async () => {
    const client = clientFor(server);

    const multiline = '-----BEGIN RSA KEY-----\nMIIE...\n-----END RSA KEY-----';
    const res = await request(client, 'PUT', '/v1/secrets/certs/rsa-key', {
      value: multiline,
      type: 'certificate',
    });
    expect(res.statusCode).toBe(200);

    const getRes = await request(client, 'GET', '/v1/secrets/certs/rsa-key');
    expect(getRes.body.value).toBe(multiline);
  });
});

// ─── get secrets ─────────────────────────────────────────────────────
describe('Secrets — GET /v1/secrets/:path (get)', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('aws/access-key', 'AKIA-1234', { type: 'api-key', description: 'AWS dev key' });
    await vault.store('aws/secret-key', 'wJalr-5678', { type: 'api-key' });
    await vault.store('github/pat', 'ghp_abcdef', { type: 'api-key', description: 'GitHub PAT' });
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should return decrypted secret with metadata', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/secrets/aws/access-key');

    expect(res.statusCode).toBe(200);
    expect(res.body.path).toBe('aws/access-key');
    expect(res.body.value).toBe('AKIA-1234');
    expect(res.body.metadata).toEqual({
      type: 'api-key',
      description: 'AWS dev key',
    });
    expect(res.body.createdAt).toBeTruthy();
    expect(res.body.updatedAt).toBeTruthy();
  });

  it('should return 404 for nonexistent secret', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/secrets/does/not/exist');

    expect(res.statusCode).toBe(404);
    expect(res.body.error).toContain('not found');
  });

  it('should handle URL-encoded paths', async () => {
    const client = clientFor(server);

    // Store with a path that needs encoding
    await request(client, 'PUT', `/v1/secrets/${encodeURIComponent('special/path with spaces')}`, {
      value: 'encoded-value',
    });

    // Retrieve it
    const res = await request(client, 'GET', `/v1/secrets/${encodeURIComponent('special/path with spaces')}`);
    expect(res.statusCode).toBe(200);
    expect(res.body.value).toBe('encoded-value');
  });
});

// ─── list secrets ────────────────────────────────────────────────────
describe('Secrets — GET /v1/secrets (list)', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('aws/dev/access-key', 'AKIA-dev', { type: 'api-key' });
    await vault.store('aws/dev/secret-key', 'secret-dev', { type: 'api-key' });
    await vault.store('aws/prod/access-key', 'AKIA-prod', { type: 'api-key' });
    await vault.store('slack/token', 'xoxb-1234', { type: 'oauth-token', description: 'Bot token' });
    await vault.store('github/pat', 'ghp_xxx', { type: 'api-key' });
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should list all secrets without values', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/secrets');

    expect(res.statusCode).toBe(200);
    const entries = res.body.entries as Array<Record<string, unknown>>;
    expect(entries.length).toBe(5);

    // Should NOT include __vault_verify__
    const paths = entries.map(e => e.path);
    expect(paths).not.toContain('__vault_verify__');

    // Should NOT include decrypted values
    for (const entry of entries) {
      expect(entry).not.toHaveProperty('value');
    }
  });

  it('should include metadata and timestamps in list', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/secrets');

    const entries = res.body.entries as Array<Record<string, unknown>>;
    const slackEntry = entries.find(e => e.path === 'slack/token');
    expect(slackEntry).toBeTruthy();
    expect((slackEntry as any).metadata.type).toBe('oauth-token');
    expect((slackEntry as any).metadata.description).toBe('Bot token');
    expect(slackEntry).toHaveProperty('createdAt');
    expect(slackEntry).toHaveProperty('updatedAt');
  });

  it('should filter by prefix', async () => {
    const client = clientFor(server);

    // aws/dev/ prefix
    let res = await request(client, 'GET', '/v1/secrets?prefix=aws/dev/');
    let entries = res.body.entries as Array<Record<string, unknown>>;
    expect(entries.length).toBe(2);
    expect(entries.map(e => e.path)).toContain('aws/dev/access-key');
    expect(entries.map(e => e.path)).toContain('aws/dev/secret-key');

    // aws/ prefix (broader)
    res = await request(client, 'GET', '/v1/secrets?prefix=aws/');
    entries = res.body.entries as Array<Record<string, unknown>>;
    expect(entries.length).toBe(3);

    // slack/ prefix
    res = await request(client, 'GET', '/v1/secrets?prefix=slack/');
    entries = res.body.entries as Array<Record<string, unknown>>;
    expect(entries.length).toBe(1);
  });

  it('should return empty array for non-matching prefix', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/secrets?prefix=nonexistent/');
    const entries = res.body.entries as Array<Record<string, unknown>>;
    expect(entries.length).toBe(0);
  });
});

// ─── delete secrets ──────────────────────────────────────────────────
describe('Secrets — DELETE /v1/secrets/:path (delete)', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('to-delete/key1', 'value1');
    await vault.store('to-delete/key2', 'value2');
    await vault.store('keep/this', 'important');
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should delete an existing secret', async () => {
    const client = clientFor(server);
    const res = await request(client, 'DELETE', '/v1/secrets/to-delete/key1');

    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.path).toBe('to-delete/key1');

    // Verify it's gone
    const getRes = await request(client, 'GET', '/v1/secrets/to-delete/key1');
    expect(getRes.statusCode).toBe(404);
  });

  it('should return 404 for nonexistent secret on delete', async () => {
    const client = clientFor(server);
    const res = await request(client, 'DELETE', '/v1/secrets/does/not/exist');
    expect(res.statusCode).toBe(404);
    expect(res.body.error).toContain('not found');
  });

  it('should not affect other secrets when deleting', async () => {
    const client = clientFor(server);

    // Delete key2
    await request(client, 'DELETE', '/v1/secrets/to-delete/key2');

    // Keep secret should still exist
    const res = await request(client, 'GET', '/v1/secrets/keep/this');
    expect(res.statusCode).toBe(200);
    expect(res.body.value).toBe('important');
  });

  it('should reject deleting reserved paths', async () => {
    const client = clientFor(server);
    const res = await request(client, 'DELETE', '/v1/secrets/__vault_verify__');
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('reserved');
  });

  it('should update secret count after deletion', async () => {
    const client = clientFor(server);
    const statusRes = await request(client, 'GET', '/v1/status');
    // Started with 3, deleted 2
    expect(statusRes.body.secretCount).toBe(1);
  });
});

// ─── store-then-lock-then-get scenario ───────────────────────────────
describe('Secrets — lock/unlock persistence', () => {
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

  it('should persist secrets across lock/unlock cycles', async () => {
    const client = clientFor(server);

    // Unlock
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });

    // Store
    await request(client, 'PUT', '/v1/secrets/persistent/secret', {
      value: 'survive-lock-cycle',
      type: 'password',
      description: 'Test persistence',
    });

    // Lock
    await request(client, 'POST', '/v1/lock');

    // Verify locked
    const lockedRes = await request(client, 'GET', '/v1/secrets/persistent/secret');
    expect(lockedRes.statusCode).toBe(403);

    // Unlock again
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });

    // Retrieve — should still be there
    const getRes = await request(client, 'GET', '/v1/secrets/persistent/secret');
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.value).toBe('survive-lock-cycle');
    expect(getRes.body.metadata.type).toBe('password');
    expect(getRes.body.metadata.description).toBe('Test persistence');
  });
});

// ─── secret values never leak in non-value responses ─────────────────
describe('Secrets — value security', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('secret/key', 'super-secret-value-12345', { type: 'api-key' });
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should not expose secret values in list endpoint', async () => {
    const client = clientFor(server);
    const res = await request(client, 'GET', '/v1/secrets');
    const body = JSON.stringify(res.body);
    expect(body).not.toContain('super-secret-value-12345');
  });

  it('should not expose secret values in store response', async () => {
    const client = clientFor(server);
    const res = await request(client, 'PUT', '/v1/secrets/another/key', {
      value: 'another-secret-value-99999',
    });
    const body = JSON.stringify(res.body);
    expect(body).not.toContain('another-secret-value-99999');
  });

  it('should not expose secret values in delete response', async () => {
    const client = clientFor(server);

    // Store one to delete
    await request(client, 'PUT', '/v1/secrets/temp/to-delete', {
      value: 'delete-me-secret-77777',
    });

    const res = await request(client, 'DELETE', '/v1/secrets/temp/to-delete');
    const body = JSON.stringify(res.body);
    expect(body).not.toContain('delete-me-secret-77777');
  });
});
