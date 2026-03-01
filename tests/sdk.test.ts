/**
 * Tests for the Worker SDK — US-008: seamless credential access for workers/agents.
 *
 * Verifies:
 * - getSecret(): retrieves decrypted secret values
 * - storeSecret(): stores secrets with optional metadata
 * - listSecrets(): lists secrets with optional prefix filter
 * - Auto-discovery from HQ_VAULT_URL and HQ_VAULT_TOKEN env vars
 * - Config overrides take precedence over env vars
 * - VaultSdkError with proper codes for all failure scenarios
 * - Connection error handling with clear messages
 * - 401/403/404 status code handling
 *
 * Tests run against an actual vault server (insecure mode, ephemeral port)
 * to verify end-to-end behavior.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request } from '../src/client.js';
import {
  getSecret,
  storeSecret,
  listSecrets,
  VaultSdkError,
} from '../src/sdk.js';
import type { VaultSdkConfig } from '../src/sdk.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-sdk-passphrase-2026';
const TEST_TOKEN = 'test-sdk-token-for-testing';

/**
 * Helper: create a temporary directory and server config.
 */
function createTmpConfig(overrides?: Partial<ServerConfig>): {
  tmpDir: string;
  config: ServerConfig;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-sdk-'));
  const config: ServerConfig = {
    vaultPath: path.join(tmpDir, 'vault.db'),
    port: 0, // Let the OS pick a free port
    idleTimeoutMs: 0,
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
 * Helper: initialize and unlock a vault via the server API.
 */
async function initAndUnlock(server: http.Server): Promise<void> {
  const port = getPort(server);
  await request(
    { port, host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
    'POST',
    '/v1/init',
    { passphrase: PASSPHRASE },
  );
  await request(
    { port, host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
    'POST',
    '/v1/unlock',
    { passphrase: PASSPHRASE },
  );
}

/**
 * Helper: build an SDK config pointing at a test server.
 */
function sdkConfigFor(server: http.Server): VaultSdkConfig {
  return {
    url: `http://127.0.0.1:${getPort(server)}`,
    token: TEST_TOKEN,
  };
}

// ─── getSecret ────────────────────────────────────────────────────────
describe('SDK — getSecret', () => {
  let server: http.Server;
  let tmpDir: string;
  let sdkConfig: VaultSdkConfig;

  beforeAll(async () => {
    const { tmpDir: td, config } = createTmpConfig();
    tmpDir = td;
    server = (await createVaultServer(config)) as http.Server;
    await initAndUnlock(server);
    sdkConfig = sdkConfigFor(server);

    // Pre-populate some secrets
    await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'PUT',
      '/v1/secrets/aws%2Faccess-key',
      { value: 'AKIAIOSFODNN7EXAMPLE', type: 'api-key' },
    );
    await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'PUT',
      '/v1/secrets/aws%2Fsecret-key',
      { value: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', type: 'api-key', description: 'AWS secret access key' },
    );
    await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'PUT',
      '/v1/secrets/slack%2Findigo%2Fbot-token',
      { value: 'xoxb-1234-5678-abc', type: 'oauth-token' },
    );
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should retrieve a decrypted secret by path', async () => {
    const value = await getSecret('aws/access-key', sdkConfig);
    expect(value).toBe('AKIAIOSFODNN7EXAMPLE');
  });

  it('should retrieve secrets with nested paths', async () => {
    const value = await getSecret('slack/indigo/bot-token', sdkConfig);
    expect(value).toBe('xoxb-1234-5678-abc');
  });

  it('should throw NOT_FOUND for missing secrets', async () => {
    try {
      await getSecret('does/not/exist', sdkConfig);
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      const sdkErr = err as VaultSdkError;
      expect(sdkErr.code).toBe('NOT_FOUND');
      expect(sdkErr.statusCode).toBe(404);
      expect(sdkErr.message).toContain('does/not/exist');
    }
  });

  it('should throw UNAUTHORIZED with bad token', async () => {
    try {
      await getSecret('aws/access-key', {
        ...sdkConfig,
        token: 'bad-token',
      });
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      const sdkErr = err as VaultSdkError;
      expect(sdkErr.code).toBe('UNAUTHORIZED');
      expect(sdkErr.statusCode).toBe(401);
    }
  });

  it('should throw VAULT_LOCKED when vault is locked', async () => {
    // Lock the vault
    await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'POST',
      '/v1/lock',
    );

    try {
      await getSecret('aws/access-key', sdkConfig);
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      const sdkErr = err as VaultSdkError;
      expect(sdkErr.code).toBe('VAULT_LOCKED');
      expect(sdkErr.statusCode).toBe(403);
    }

    // Unlock again for subsequent tests
    await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'POST',
      '/v1/unlock',
      { passphrase: PASSPHRASE },
    );
  });
});

// ─── storeSecret ──────────────────────────────────────────────────────
describe('SDK — storeSecret', () => {
  let server: http.Server;
  let tmpDir: string;
  let sdkConfig: VaultSdkConfig;

  beforeAll(async () => {
    const { tmpDir: td, config } = createTmpConfig();
    tmpDir = td;
    server = (await createVaultServer(config)) as http.Server;
    await initAndUnlock(server);
    sdkConfig = sdkConfigFor(server);
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should store a secret and verify retrieval', async () => {
    await storeSecret('test/api-key', 'sk-abc123', undefined, sdkConfig);
    const value = await getSecret('test/api-key', sdkConfig);
    expect(value).toBe('sk-abc123');
  });

  it('should store a secret with metadata', async () => {
    await storeSecret(
      'test/oauth-token',
      'xoxb-token-value',
      { type: 'oauth-token', description: 'Slack bot token' },
      sdkConfig,
    );

    // Verify via raw API that metadata was stored
    const res = await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'GET',
      '/v1/secrets/test%2Foauth-token',
    );
    expect(res.statusCode).toBe(200);
    expect(res.body.value).toBe('xoxb-token-value');
    expect(res.body.metadata).toEqual(
      expect.objectContaining({ type: 'oauth-token', description: 'Slack bot token' }),
    );
  });

  it('should overwrite an existing secret', async () => {
    await storeSecret('test/overwrite', 'value-v1', undefined, sdkConfig);
    await storeSecret('test/overwrite', 'value-v2', undefined, sdkConfig);
    const value = await getSecret('test/overwrite', sdkConfig);
    expect(value).toBe('value-v2');
  });

  it('should throw UNAUTHORIZED with bad token', async () => {
    try {
      await storeSecret('test/fail', 'value', undefined, {
        ...sdkConfig,
        token: 'wrong-token',
      });
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      expect((err as VaultSdkError).code).toBe('UNAUTHORIZED');
    }
  });

  it('should throw VAULT_LOCKED when vault is locked', async () => {
    await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'POST',
      '/v1/lock',
    );

    try {
      await storeSecret('test/locked', 'value', undefined, sdkConfig);
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      expect((err as VaultSdkError).code).toBe('VAULT_LOCKED');
    }

    await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'POST',
      '/v1/unlock',
      { passphrase: PASSPHRASE },
    );
  });
});

// ─── listSecrets ──────────────────────────────────────────────────────
describe('SDK — listSecrets', () => {
  let server: http.Server;
  let tmpDir: string;
  let sdkConfig: VaultSdkConfig;

  beforeAll(async () => {
    const { tmpDir: td, config } = createTmpConfig();
    tmpDir = td;
    server = (await createVaultServer(config)) as http.Server;
    await initAndUnlock(server);
    sdkConfig = sdkConfigFor(server);

    // Pre-populate secrets
    const clientCfg = { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true };
    await request(clientCfg, 'PUT', '/v1/secrets/app%2Fdb-host', { value: 'localhost' });
    await request(clientCfg, 'PUT', '/v1/secrets/app%2Fdb-port', { value: '5432' });
    await request(clientCfg, 'PUT', '/v1/secrets/app%2Fdb-password', {
      value: 'secret123',
      type: 'password',
      description: 'Database password',
    });
    await request(clientCfg, 'PUT', '/v1/secrets/other%2Fapi-key', { value: 'key-abc' });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should list all secrets when no prefix given', async () => {
    const entries = await listSecrets(undefined, sdkConfig);
    expect(entries.length).toBe(4);
    expect(entries.map((e) => e.path)).toContain('app/db-host');
    expect(entries.map((e) => e.path)).toContain('other/api-key');
  });

  it('should filter by prefix', async () => {
    const entries = await listSecrets('app/', sdkConfig);
    expect(entries.length).toBe(3);
    expect(entries.every((e) => e.path.startsWith('app/'))).toBe(true);
  });

  it('should return empty array for non-matching prefix', async () => {
    const entries = await listSecrets('nonexistent/', sdkConfig);
    expect(entries).toEqual([]);
  });

  it('should include metadata in entries', async () => {
    const entries = await listSecrets('app/db-password', sdkConfig);
    // The prefix filter matches exact or prefix, so we need to find the specific entry
    const dbPwd = entries.find((e) => e.path === 'app/db-password');
    expect(dbPwd).toBeDefined();
    expect(dbPwd!.metadata.type).toBe('password');
    expect(dbPwd!.metadata.description).toBe('Database password');
  });

  it('should include timestamps in entries', async () => {
    const entries = await listSecrets('app/', sdkConfig);
    for (const entry of entries) {
      expect(entry.createdAt).toBeDefined();
      expect(entry.updatedAt).toBeDefined();
      expect(typeof entry.createdAt).toBe('string');
      expect(typeof entry.updatedAt).toBe('string');
    }
  });

  it('should NOT include secret values in entries', async () => {
    const entries = await listSecrets(undefined, sdkConfig);
    for (const entry of entries) {
      expect((entry as Record<string, unknown>).value).toBeUndefined();
    }
  });

  it('should throw UNAUTHORIZED with bad token', async () => {
    try {
      await listSecrets(undefined, { ...sdkConfig, token: 'bad-token' });
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      expect((err as VaultSdkError).code).toBe('UNAUTHORIZED');
    }
  });
});

// ─── Environment variable auto-discovery ──────────────────────────────
describe('SDK — environment variable auto-discovery', () => {
  let server: http.Server;
  let tmpDir: string;
  const savedEnv: Record<string, string | undefined> = {};

  beforeAll(async () => {
    const { tmpDir: td, config } = createTmpConfig();
    tmpDir = td;
    server = (await createVaultServer(config)) as http.Server;
    await initAndUnlock(server);

    // Store a test secret
    await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'PUT',
      '/v1/secrets/env-test%2Fkey',
      { value: 'env-test-value' },
    );
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  beforeEach(() => {
    savedEnv.HQ_VAULT_URL = process.env.HQ_VAULT_URL;
    savedEnv.HQ_VAULT_TOKEN = process.env.HQ_VAULT_TOKEN;
  });

  afterEach(() => {
    if (savedEnv.HQ_VAULT_URL === undefined) {
      delete process.env.HQ_VAULT_URL;
    } else {
      process.env.HQ_VAULT_URL = savedEnv.HQ_VAULT_URL;
    }
    if (savedEnv.HQ_VAULT_TOKEN === undefined) {
      delete process.env.HQ_VAULT_TOKEN;
    } else {
      process.env.HQ_VAULT_TOKEN = savedEnv.HQ_VAULT_TOKEN;
    }
  });

  it('should auto-discover vault URL and token from env vars', async () => {
    process.env.HQ_VAULT_URL = `http://127.0.0.1:${getPort(server)}`;
    process.env.HQ_VAULT_TOKEN = TEST_TOKEN;

    // Call without any config overrides
    const value = await getSecret('env-test/key');
    expect(value).toBe('env-test-value');
  });

  it('should use default URL (https://localhost:13100) when HQ_VAULT_URL is not set', async () => {
    delete process.env.HQ_VAULT_URL;
    process.env.HQ_VAULT_TOKEN = TEST_TOKEN;

    // This should try to connect to https://localhost:13100 and fail with connection error
    try {
      await getSecret('env-test/key');
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      // Should be a connection error, not a config error (URL is valid, just not running there)
      expect((err as VaultSdkError).code).toMatch(/CONNECTION_REFUSED|CONNECTION_ERROR|TIMEOUT/);
    }
  });

  it('should throw NO_TOKEN when HQ_VAULT_TOKEN is not set', async () => {
    process.env.HQ_VAULT_URL = `http://127.0.0.1:${getPort(server)}`;
    delete process.env.HQ_VAULT_TOKEN;

    try {
      await getSecret('env-test/key');
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      expect((err as VaultSdkError).code).toBe('NO_TOKEN');
      expect((err as VaultSdkError).message).toContain('HQ_VAULT_TOKEN');
    }
  });

  it('should prefer config overrides over env vars', async () => {
    // Set env vars to wrong values
    process.env.HQ_VAULT_URL = 'http://127.0.0.1:99999';
    process.env.HQ_VAULT_TOKEN = 'wrong-token';

    // Override with correct values
    const value = await getSecret('env-test/key', {
      url: `http://127.0.0.1:${getPort(server)}`,
      token: TEST_TOKEN,
    });
    expect(value).toBe('env-test-value');
  });
});

// ─── Connection error handling ────────────────────────────────────────
describe('SDK — connection error handling', () => {
  it('should throw CONNECTION_REFUSED when server is not running', async () => {
    try {
      await getSecret('test/key', {
        url: 'http://127.0.0.1:19998',
        token: 'some-token',
      });
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      const sdkErr = err as VaultSdkError;
      expect(sdkErr.code).toBe('CONNECTION_REFUSED');
      expect(sdkErr.message).toContain('hq-vault serve');
    }
  });

  it('should throw INVALID_URL for malformed URLs', async () => {
    try {
      await getSecret('test/key', {
        url: 'not-a-url',
        token: 'some-token',
      });
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      expect((err as VaultSdkError).code).toBe('INVALID_URL');
    }
  });
});

// ─── VaultSdkError ────────────────────────────────────────────────────
describe('SDK — VaultSdkError', () => {
  it('should have name, code, statusCode, and message', () => {
    const err = new VaultSdkError('test message', 'TEST_CODE', 418);
    expect(err.name).toBe('VaultSdkError');
    expect(err.message).toBe('test message');
    expect(err.code).toBe('TEST_CODE');
    expect(err.statusCode).toBe(418);
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(VaultSdkError);
  });

  it('should work without statusCode', () => {
    const err = new VaultSdkError('no status', 'NO_STATUS');
    expect(err.statusCode).toBeUndefined();
    expect(err.code).toBe('NO_STATUS');
  });
});

// ─── End-to-end SDK workflow ──────────────────────────────────────────
describe('SDK — end-to-end workflow', () => {
  let server: http.Server;
  let tmpDir: string;
  let sdkConfig: VaultSdkConfig;

  beforeAll(async () => {
    const { tmpDir: td, config } = createTmpConfig();
    tmpDir = td;
    server = (await createVaultServer(config)) as http.Server;
    await initAndUnlock(server);
    sdkConfig = sdkConfigFor(server);
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should support a full store → list → get → overwrite → get cycle', async () => {
    // Store multiple secrets
    await storeSecret('myapp/db-url', 'postgres://localhost:5432/mydb', { type: 'password' }, sdkConfig);
    await storeSecret('myapp/api-key', 'sk-live-abc123', { type: 'api-key', description: 'Production API key' }, sdkConfig);
    await storeSecret('myapp/jwt-secret', 'super-secret-jwt', undefined, sdkConfig);

    // List all
    const allEntries = await listSecrets(undefined, sdkConfig);
    expect(allEntries.length).toBe(3);

    // List with prefix
    const myAppEntries = await listSecrets('myapp/', sdkConfig);
    expect(myAppEntries.length).toBe(3);

    // Get specific secrets
    const dbUrl = await getSecret('myapp/db-url', sdkConfig);
    expect(dbUrl).toBe('postgres://localhost:5432/mydb');

    const apiKey = await getSecret('myapp/api-key', sdkConfig);
    expect(apiKey).toBe('sk-live-abc123');

    // Overwrite a secret
    await storeSecret('myapp/db-url', 'postgres://prod-host:5432/mydb', { type: 'password' }, sdkConfig);
    const updatedDbUrl = await getSecret('myapp/db-url', sdkConfig);
    expect(updatedDbUrl).toBe('postgres://prod-host:5432/mydb');

    // Verify list still shows all 3
    const finalEntries = await listSecrets('myapp/', sdkConfig);
    expect(finalEntries.length).toBe(3);
  });
});
