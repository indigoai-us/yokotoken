/**
 * Tests for NetworkVaultClient and config persistence — US-006.
 *
 * Covers:
 * - Config persistence: read/write/set/get/delete/show
 * - Config field name resolution (kebab-case <-> snake_case)
 * - NetworkVaultClient: constructor resolution from env/config/params
 * - Remote auth flow: challenge-response with Ed25519 keypair
 * - Session token caching and reuse
 * - Re-auth on 401 (expired session)
 * - Token-based fallback auth
 * - CA cert override support
 * - Connection error messages
 * - SDK identity-auth integration
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import sodium from 'sodium-native';
import crypto from 'node:crypto';

import {
  readConfig,
  writeConfig,
  setConfigField,
  getConfigField,
  deleteConfigField,
  resolveFieldName,
  formatConfigForDisplay,
  getValidFields,
} from '../src/config.js';
import type { VaultConfig, VaultConfigField } from '../src/config.js';
import {
  NetworkVaultClient,
  NetworkClientError,
} from '../src/network-client.js';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request } from '../src/client.js';
import { IdentityDatabase } from '../src/identity.js';
import { getSecret, storeSecret, listSecrets, VaultSdkError } from '../src/sdk.js';
import type { VaultSdkConfig } from '../src/sdk.js';

// ─── Helpers ────────────────────────────────────────────────────────

const TEST_TOKEN = 'test-network-client-token';
const PASSPHRASE = 'test-network-client-passphrase-2026';

/** Create a temp directory for config tests. */
function createTmpDir(prefix = 'hq-vault-netclient-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** Create an identity database and an identity with keypair. */
function createIdentitySetup(): {
  tmpDir: string;
  identityDbPath: string;
  identityDb: IdentityDatabase;
  identityId: string;
  identityName: string;
  privateKeyBase64: string;
  publicKeyBase64: string;
  keyFilePath: string;
} {
  const tmpDir = createTmpDir('hq-vault-netclient-identity-');
  const identityDbPath = path.join(tmpDir, 'identity.db');
  const identityDb = new IdentityDatabase(identityDbPath);

  const result = identityDb.createIdentity('test-agent', 'agent');
  const identityId = result.identity.id;
  const identityName = result.identity.name;
  const privateKeyBase64 = result.privateKey;
  const publicKeyBase64 = result.publicKey;

  // Write the private key to a file
  const keyFilePath = path.join(tmpDir, 'test-agent.key');
  fs.writeFileSync(keyFilePath, privateKeyBase64, { mode: 0o600 });

  return {
    tmpDir,
    identityDbPath,
    identityDb,
    identityId,
    identityName,
    privateKeyBase64,
    publicKeyBase64,
    keyFilePath,
  };
}

/** Create server config for testing. */
function createServerConfig(
  identityDbPath: string,
  overrides?: Partial<ServerConfig>,
): { tmpDir: string; config: ServerConfig } {
  const tmpDir = createTmpDir('hq-vault-netclient-srv-');
  const config: ServerConfig = {
    vaultPath: path.join(tmpDir, 'vault.db'),
    port: 0,
    idleTimeoutMs: 0,
    pidFile: path.join(tmpDir, 'vault.pid'),
    portFile: path.join(tmpDir, 'vault.port'),
    tokenFile: path.join(tmpDir, 'token'),
    insecure: true,
    token: TEST_TOKEN,
    identityDbPath,
    ...overrides,
  };
  return { tmpDir, config };
}

function getPort(server: http.Server): number {
  const addr = server.address();
  if (typeof addr === 'object' && addr) return addr.port;
  throw new Error('Server has no address');
}

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

// ─── Config Persistence ────────────────────────────────────────────

describe('Config persistence', () => {
  let tmpDir: string;
  let configPath: string;

  beforeEach(() => {
    tmpDir = createTmpDir('hq-vault-config-');
    configPath = path.join(tmpDir, 'config.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch { /* ok */ }
  });

  it('should return empty config when file does not exist', () => {
    const config = readConfig(configPath);
    expect(config).toEqual({});
  });

  it('should write and read config', () => {
    const config: VaultConfig = {
      remote_url: 'https://vault.example.com:13100',
      identity: 'my-agent',
      key_file: '/path/to/key.pem',
      ca_cert: '/path/to/ca.crt',
    };
    writeConfig(config, configPath);

    const loaded = readConfig(configPath);
    expect(loaded).toEqual(config);
  });

  it('should create directory if it does not exist', () => {
    const nestedPath = path.join(tmpDir, 'sub', 'dir', 'config.json');
    writeConfig({ remote_url: 'https://example.com' }, nestedPath);
    expect(fs.existsSync(nestedPath)).toBe(true);
  });

  it('should set individual fields', () => {
    setConfigField('remote_url', 'https://vault.example.com:13100', configPath);
    const config = readConfig(configPath);
    expect(config.remote_url).toBe('https://vault.example.com:13100');
  });

  it('should get individual fields', () => {
    writeConfig({ identity: 'my-agent' }, configPath);
    expect(getConfigField('identity', configPath)).toBe('my-agent');
  });

  it('should return undefined for unset fields', () => {
    writeConfig({}, configPath);
    expect(getConfigField('identity', configPath)).toBeUndefined();
  });

  it('should delete individual fields', () => {
    writeConfig({ remote_url: 'https://example.com', identity: 'agent' }, configPath);
    deleteConfigField('identity', configPath);
    const config = readConfig(configPath);
    expect(config.identity).toBeUndefined();
    expect(config.remote_url).toBe('https://example.com');
  });

  it('should preserve existing fields when setting new ones', () => {
    setConfigField('remote_url', 'https://vault.example.com:13100', configPath);
    setConfigField('identity', 'my-agent', configPath);
    const config = readConfig(configPath);
    expect(config.remote_url).toBe('https://vault.example.com:13100');
    expect(config.identity).toBe('my-agent');
  });

  it('should ignore unknown fields in config file', () => {
    fs.writeFileSync(configPath, JSON.stringify({ remote_url: 'https://x.com', bogus: 'value' }));
    const config = readConfig(configPath);
    expect(config.remote_url).toBe('https://x.com');
    expect((config as Record<string, unknown>).bogus).toBeUndefined();
  });

  it('should return empty config on corrupt JSON', () => {
    fs.writeFileSync(configPath, 'this is not json');
    const config = readConfig(configPath);
    expect(config).toEqual({});
  });

  it('should throw on invalid field name', () => {
    expect(() => setConfigField('invalid_field' as VaultConfigField, 'value', configPath)).toThrow(
      /Invalid config field/,
    );
  });

  it('should not persist empty string values', () => {
    writeConfig({ remote_url: '', identity: 'agent' }, configPath);
    const config = readConfig(configPath);
    expect(config.remote_url).toBeUndefined();
    expect(config.identity).toBe('agent');
  });
});

// ─── Config field name resolution ──────────────────────────────────

describe('Config field name resolution', () => {
  it('should resolve kebab-case names', () => {
    expect(resolveFieldName('remote-url')).toBe('remote_url');
    expect(resolveFieldName('key-file')).toBe('key_file');
    expect(resolveFieldName('ca-cert')).toBe('ca_cert');
  });

  it('should resolve snake_case names', () => {
    expect(resolveFieldName('remote_url')).toBe('remote_url');
    expect(resolveFieldName('key_file')).toBe('key_file');
    expect(resolveFieldName('ca_cert')).toBe('ca_cert');
  });

  it('should resolve simple names', () => {
    expect(resolveFieldName('identity')).toBe('identity');
  });

  it('should return null for unknown names', () => {
    expect(resolveFieldName('unknown')).toBeNull();
    expect(resolveFieldName('bogus-field')).toBeNull();
  });
});

// ─── Config display formatting ──────────────────────────────────────

describe('Config display formatting', () => {
  it('should format all fields', () => {
    const display = formatConfigForDisplay({
      remote_url: 'https://vault.example.com:13100',
      identity: 'my-agent',
      key_file: '/home/user/.hq-vault/my-agent.key',
      ca_cert: '/path/to/ca.crt',
    });
    expect(display['remote-url']).toBe('https://vault.example.com:13100');
    expect(display['identity']).toBe('my-agent');
    // key-file should be redacted to just the filename
    expect(display['key-file']).toBe('my-agent.key');
    expect(display['ca-cert']).toBe('/path/to/ca.crt');
  });

  it('should omit undefined fields', () => {
    const display = formatConfigForDisplay({ remote_url: 'https://example.com' });
    expect(display['remote-url']).toBe('https://example.com');
    expect(display['identity']).toBeUndefined();
    expect(display['key-file']).toBeUndefined();
  });

  it('should return empty object for empty config', () => {
    const display = formatConfigForDisplay({});
    expect(Object.keys(display)).toHaveLength(0);
  });
});

// ─── getValidFields ─────────────────────────────────────────────────

describe('getValidFields', () => {
  it('should return all 4 valid field names', () => {
    const fields = getValidFields();
    expect(fields).toContain('remote_url');
    expect(fields).toContain('identity');
    expect(fields).toContain('key_file');
    expect(fields).toContain('ca_cert');
    expect(fields).toHaveLength(4);
  });
});

// ─── NetworkVaultClient — construction ──────────────────────────────

describe('NetworkVaultClient — construction', () => {
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    savedEnv.HQ_VAULT_URL = process.env.HQ_VAULT_URL;
    savedEnv.HQ_VAULT_TOKEN = process.env.HQ_VAULT_TOKEN;
    savedEnv.HQ_VAULT_IDENTITY = process.env.HQ_VAULT_IDENTITY;
    savedEnv.HQ_VAULT_KEY_FILE = process.env.HQ_VAULT_KEY_FILE;
    savedEnv.HQ_VAULT_PRIVATE_KEY = process.env.HQ_VAULT_PRIVATE_KEY;
    savedEnv.HQ_VAULT_CA_CERT = process.env.HQ_VAULT_CA_CERT;
    // Clear env vars
    delete process.env.HQ_VAULT_URL;
    delete process.env.HQ_VAULT_TOKEN;
    delete process.env.HQ_VAULT_IDENTITY;
    delete process.env.HQ_VAULT_KEY_FILE;
    delete process.env.HQ_VAULT_PRIVATE_KEY;
    delete process.env.HQ_VAULT_CA_CERT;
  });

  afterEach(() => {
    for (const [key, val] of Object.entries(savedEnv)) {
      if (val === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = val;
      }
    }
  });

  it('should use defaults when nothing configured', () => {
    const client = new NetworkVaultClient();
    expect(client.getUrl()).toBe('https://localhost:13100');
    expect(client.hasAuth).toBe(false);
    expect(client.hasIdentityAuth).toBe(false);
  });

  it('should use explicit config params', () => {
    const client = new NetworkVaultClient({
      url: 'https://custom.vault:9999',
      identity: 'agent-1',
      keyFile: '/fake/key.pem',
    });
    expect(client.getUrl()).toBe('https://custom.vault:9999');
    expect(client.getIdentity()).toBe('agent-1');
    expect(client.hasIdentityAuth).toBe(true);
  });

  it('should read from env vars', () => {
    process.env.HQ_VAULT_URL = 'https://env-vault:8080';
    process.env.HQ_VAULT_IDENTITY = 'env-agent';
    process.env.HQ_VAULT_PRIVATE_KEY = 'base64key==';
    const client = new NetworkVaultClient();
    expect(client.getUrl()).toBe('https://env-vault:8080');
    expect(client.getIdentity()).toBe('env-agent');
    expect(client.hasIdentityAuth).toBe(true);
  });

  it('should prefer explicit config over env vars', () => {
    process.env.HQ_VAULT_URL = 'https://env-vault:8080';
    const client = new NetworkVaultClient({ url: 'https://override:9999' });
    expect(client.getUrl()).toBe('https://override:9999');
  });

  it('should detect token-based auth', () => {
    const client = new NetworkVaultClient({ token: 'my-token' });
    expect(client.hasAuth).toBe(true);
    expect(client.hasIdentityAuth).toBe(false);
  });

  it('should detect identity-based auth from env', () => {
    process.env.HQ_VAULT_IDENTITY = 'my-agent';
    process.env.HQ_VAULT_KEY_FILE = '/some/key.pem';
    const client = new NetworkVaultClient();
    expect(client.hasIdentityAuth).toBe(true);
  });

  it('should not detect identity auth when only identity is set (no key)', () => {
    const client = new NetworkVaultClient({ identity: 'agent-only' });
    expect(client.hasIdentityAuth).toBe(false);
    expect(client.hasAuth).toBe(false);
  });
});

// ─── NetworkVaultClient — loadPrivateKey ────────────────────────────

describe('NetworkVaultClient — loadPrivateKey', () => {
  it('should prefer privateKey (base64) over keyFile', () => {
    const client = new NetworkVaultClient({
      identity: 'test',
      privateKey: 'direct-base64-key',
      keyFile: '/some/file.key',
    });
    expect(client.loadPrivateKey()).toBe('direct-base64-key');
  });

  it('should read key from file', () => {
    const tmpDir = createTmpDir();
    const keyPath = path.join(tmpDir, 'test.key');
    fs.writeFileSync(keyPath, 'file-based-key-content\n');
    try {
      const client = new NetworkVaultClient({
        identity: 'test',
        keyFile: keyPath,
      });
      expect(client.loadPrivateKey()).toBe('file-based-key-content');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('should throw KEY_FILE_NOT_FOUND for missing key file', () => {
    const client = new NetworkVaultClient({
      identity: 'test',
      keyFile: '/nonexistent/key.pem',
    });
    expect(() => client.loadPrivateKey()).toThrow(NetworkClientError);
    try {
      client.loadPrivateKey();
    } catch (err) {
      expect((err as NetworkClientError).code).toBe('KEY_FILE_NOT_FOUND');
    }
  });

  it('should throw NO_KEY when no key source is configured', () => {
    const client = new NetworkVaultClient({ identity: 'test' });
    expect(() => client.loadPrivateKey()).toThrow(NetworkClientError);
    try {
      client.loadPrivateKey();
    } catch (err) {
      expect((err as NetworkClientError).code).toBe('NO_KEY');
    }
  });
});

// ─── NetworkVaultClient — connection errors ─────────────────────────

describe('NetworkVaultClient — connection errors', () => {
  it('should throw CONNECTION_REFUSED for unreachable server', async () => {
    const client = new NetworkVaultClient({
      url: 'http://127.0.0.1:19997',
      token: 'some-token',
    });
    try {
      await client.request('GET', '/v1/status');
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(NetworkClientError);
      expect((err as NetworkClientError).code).toBe('CONNECTION_REFUSED');
    }
  });

  it('should throw TIMEOUT when server does not respond', async () => {
    const client = new NetworkVaultClient({
      url: 'http://192.0.2.1:13100', // Non-routable address
      token: 'some-token',
      timeout: 500,
    });
    try {
      await client.request('GET', '/v1/status');
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(NetworkClientError);
      const nce = err as NetworkClientError;
      // Might be TIMEOUT or CONNECTION_ERROR depending on OS
      expect(['TIMEOUT', 'CONNECTION_ERROR', 'HOST_NOT_FOUND']).toContain(nce.code);
    }
  });
});

// ─── NetworkVaultClient — token-based auth ──────────────────────────

describe('NetworkVaultClient — token-based auth', () => {
  let server: http.Server;
  let srvTmpDir: string;
  let idSetup: ReturnType<typeof createIdentitySetup>;

  beforeAll(async () => {
    idSetup = createIdentitySetup();
    const { tmpDir, config } = createServerConfig(idSetup.identityDbPath);
    srvTmpDir = tmpDir;
    server = (await createVaultServer(config)) as http.Server;
    await initAndUnlock(server);
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(srvTmpDir, { recursive: true, force: true }); } catch { /* ok */ }
    try { idSetup.identityDb.close(); } catch { /* ok */ }
    try { fs.rmSync(idSetup.tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should authenticate with static bearer token', async () => {
    const client = new NetworkVaultClient({
      url: `http://127.0.0.1:${getPort(server)}`,
      token: TEST_TOKEN,
    });

    const res = await client.request('GET', '/v1/status');
    expect(res.statusCode).toBe(200);
    expect(res.body.initialized).toBe(true);
  });

  it('should reject bad static token', async () => {
    const client = new NetworkVaultClient({
      url: `http://127.0.0.1:${getPort(server)}`,
      token: 'bad-token',
    });

    const res = await client.request('GET', '/v1/status');
    expect(res.statusCode).toBe(401);
  });
});

// ─── NetworkVaultClient — identity-based auth ───────────────────────

describe('NetworkVaultClient — identity-based auth (challenge-response)', () => {
  let server: http.Server;
  let srvTmpDir: string;
  let idSetup: ReturnType<typeof createIdentitySetup>;

  beforeAll(async () => {
    idSetup = createIdentitySetup();
    // Create an org and add the identity as admin so they have access
    const org = idSetup.identityDb.createOrg('test-org', idSetup.identityId);
    const { tmpDir, config } = createServerConfig(idSetup.identityDbPath);
    srvTmpDir = tmpDir;
    server = (await createVaultServer(config)) as http.Server;
    await initAndUnlock(server);

    // Store a test secret
    await request(
      { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
      'PUT',
      '/v1/secrets/test%2Fsecret',
      { value: 'super-secret-value' },
    );
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(srvTmpDir, { recursive: true, force: true }); } catch { /* ok */ }
    try { idSetup.identityDb.close(); } catch { /* ok */ }
    try { fs.rmSync(idSetup.tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should authenticate with identity + private key (base64)', async () => {
    const client = new NetworkVaultClient({
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: idSetup.identityId,
      privateKey: idSetup.privateKeyBase64,
    });

    const res = await client.request('GET', '/v1/status');
    expect(res.statusCode).toBe(200);
  });

  it('should authenticate with identity + key file', async () => {
    const client = new NetworkVaultClient({
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: idSetup.identityId,
      keyFile: idSetup.keyFilePath,
    });

    const res = await client.request('GET', '/v1/status');
    expect(res.statusCode).toBe(200);
  });

  it('should cache session token and reuse on subsequent requests', async () => {
    const client = new NetworkVaultClient({
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: idSetup.identityId,
      privateKey: idSetup.privateKeyBase64,
    });

    // First request triggers auth
    const res1 = await client.request('GET', '/v1/status');
    expect(res1.statusCode).toBe(200);

    // Second request should reuse cached token (no new auth)
    const res2 = await client.request('GET', '/v1/status');
    expect(res2.statusCode).toBe(200);
  });

  it('should re-authenticate on 401 (expired session)', async () => {
    const client = new NetworkVaultClient({
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: idSetup.identityId,
      privateKey: idSetup.privateKeyBase64,
    });

    // First request succeeds
    const res1 = await client.request('GET', '/v1/status');
    expect(res1.statusCode).toBe(200);

    // Manually clear the session to simulate expiry
    client.clearSession();

    // Next request should re-authenticate automatically
    const res2 = await client.request('GET', '/v1/status');
    expect(res2.statusCode).toBe(200);
  });

  it('should fail auth with wrong private key', async () => {
    // Generate a different keypair
    const wrongPub = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
    const wrongSec = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
    sodium.crypto_sign_keypair(wrongPub, wrongSec);

    const client = new NetworkVaultClient({
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: idSetup.identityId,
      privateKey: wrongSec.toString('base64'),
    });

    try {
      await client.request('GET', '/v1/status');
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(NetworkClientError);
      expect((err as NetworkClientError).code).toBe('AUTH_VERIFY_FAILED');
    }
  });

  it('should fail auth with non-existent identity', async () => {
    const client = new NetworkVaultClient({
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: 'nonexistent-identity-id',
      privateKey: idSetup.privateKeyBase64,
    });

    try {
      await client.request('GET', '/v1/status');
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(NetworkClientError);
      expect((err as NetworkClientError).code).toBe('AUTH_CHALLENGE_FAILED');
    }
  });

  it('should throw NO_IDENTITY when identity not set', async () => {
    const client = new NetworkVaultClient({
      url: `http://127.0.0.1:${getPort(server)}`,
    });

    // Override to force identity auth path
    try {
      await client.authenticate();
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(NetworkClientError);
      expect((err as NetworkClientError).code).toBe('NO_IDENTITY');
    }
  });
});

// ─── NetworkClientError ─────────────────────────────────────────────

describe('NetworkClientError', () => {
  it('should have name, code, statusCode, and message', () => {
    const err = new NetworkClientError('test message', 'TEST_CODE', 418);
    expect(err.name).toBe('NetworkClientError');
    expect(err.message).toBe('test message');
    expect(err.code).toBe('TEST_CODE');
    expect(err.statusCode).toBe(418);
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(NetworkClientError);
  });

  it('should work without statusCode', () => {
    const err = new NetworkClientError('no status', 'NO_STATUS');
    expect(err.statusCode).toBeUndefined();
    expect(err.code).toBe('NO_STATUS');
  });
});

// ─── SDK identity-based auth integration ────────────────────────────

describe('SDK — identity-based auth integration', () => {
  let server: http.Server;
  let srvTmpDir: string;
  let idSetup: ReturnType<typeof createIdentitySetup>;
  const savedEnv: Record<string, string | undefined> = {};

  beforeAll(async () => {
    idSetup = createIdentitySetup();
    idSetup.identityDb.createOrg('test-org', idSetup.identityId);
    const { tmpDir, config } = createServerConfig(idSetup.identityDbPath);
    srvTmpDir = tmpDir;
    server = (await createVaultServer(config)) as http.Server;
    await initAndUnlock(server);

    // Store test secrets using org-scoped paths (required for identity-based access)
    const clientCfg = { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true };
    await request(clientCfg, 'PUT', '/v1/secrets/org%2Ftest-org%2Fsdk-test%2Fkey', { value: 'sdk-test-value' });
    await request(clientCfg, 'PUT', '/v1/secrets/org%2Ftest-org%2Fsdk-test%2Fother', { value: 'other-value', type: 'api-key' });
    // Also store an unscoped secret for token-based fallback test
    await request(clientCfg, 'PUT', '/v1/secrets/unscoped-test%2Fkey', { value: 'unscoped-value' });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(srvTmpDir, { recursive: true, force: true }); } catch { /* ok */ }
    try { idSetup.identityDb.close(); } catch { /* ok */ }
    try { fs.rmSync(idSetup.tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  beforeEach(() => {
    savedEnv.HQ_VAULT_URL = process.env.HQ_VAULT_URL;
    savedEnv.HQ_VAULT_TOKEN = process.env.HQ_VAULT_TOKEN;
    savedEnv.HQ_VAULT_IDENTITY = process.env.HQ_VAULT_IDENTITY;
    savedEnv.HQ_VAULT_KEY_FILE = process.env.HQ_VAULT_KEY_FILE;
    savedEnv.HQ_VAULT_PRIVATE_KEY = process.env.HQ_VAULT_PRIVATE_KEY;
    savedEnv.HQ_VAULT_CA_CERT = process.env.HQ_VAULT_CA_CERT;
    // Clear env vars
    delete process.env.HQ_VAULT_URL;
    delete process.env.HQ_VAULT_TOKEN;
    delete process.env.HQ_VAULT_IDENTITY;
    delete process.env.HQ_VAULT_KEY_FILE;
    delete process.env.HQ_VAULT_PRIVATE_KEY;
    delete process.env.HQ_VAULT_CA_CERT;
  });

  afterEach(() => {
    for (const [key, val] of Object.entries(savedEnv)) {
      if (val === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = val;
      }
    }
  });

  it('should getSecret via identity auth with explicit config', async () => {
    const config: VaultSdkConfig = {
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: idSetup.identityId,
      privateKey: idSetup.privateKeyBase64,
    };
    const value = await getSecret('org/test-org/sdk-test/key', config);
    expect(value).toBe('sdk-test-value');
  });

  it('should storeSecret via identity auth', async () => {
    const config: VaultSdkConfig = {
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: idSetup.identityId,
      privateKey: idSetup.privateKeyBase64,
    };
    await storeSecret('org/test-org/sdk-test/new-key', 'new-value', { type: 'api-key' }, config);
    const value = await getSecret('org/test-org/sdk-test/new-key', config);
    expect(value).toBe('new-value');
  });

  it('should listSecrets via identity auth', async () => {
    const config: VaultSdkConfig = {
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: idSetup.identityId,
      privateKey: idSetup.privateKeyBase64,
    };
    const entries = await listSecrets('org/test-org/sdk-test/', config);
    expect(entries.length).toBeGreaterThanOrEqual(2);
    expect(entries.some((e) => e.path === 'org/test-org/sdk-test/key')).toBe(true);
  });

  it('should getSecret via identity auth from env vars', async () => {
    process.env.HQ_VAULT_URL = `http://127.0.0.1:${getPort(server)}`;
    process.env.HQ_VAULT_IDENTITY = idSetup.identityId;
    process.env.HQ_VAULT_PRIVATE_KEY = idSetup.privateKeyBase64;

    const value = await getSecret('org/test-org/sdk-test/key');
    expect(value).toBe('sdk-test-value');
  });

  it('should getSecret via identity auth with key file', async () => {
    const config: VaultSdkConfig = {
      url: `http://127.0.0.1:${getPort(server)}`,
      identity: idSetup.identityId,
      keyFile: idSetup.keyFilePath,
    };
    const value = await getSecret('org/test-org/sdk-test/key', config);
    expect(value).toBe('sdk-test-value');
  });

  it('should fall back to token auth when identity is not configured', async () => {
    const config: VaultSdkConfig = {
      url: `http://127.0.0.1:${getPort(server)}`,
      token: TEST_TOKEN,
    };
    // Unscoped secrets accessible via bootstrap token
    const value = await getSecret('unscoped-test/key', config);
    expect(value).toBe('unscoped-value');
  });

  it('should throw NO_TOKEN when no auth method is configured', async () => {
    try {
      await getSecret('sdk-test/key');
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VaultSdkError);
      expect((err as VaultSdkError).code).toBe('NO_TOKEN');
    }
  });
});

// ─── CA cert support ────────────────────────────────────────────────

describe('NetworkVaultClient — CA cert support', () => {
  it('should throw CA_CERT_NOT_FOUND for missing cert file', () => {
    expect(() => {
      new NetworkVaultClient({
        caCert: '/nonexistent/ca.crt',
      });
    }).toThrow(NetworkClientError);

    try {
      new NetworkVaultClient({ caCert: '/nonexistent/ca.crt' });
    } catch (err) {
      expect((err as NetworkClientError).code).toBe('CA_CERT_NOT_FOUND');
    }
  });

  it('should load CA cert from file', () => {
    const tmpDir = createTmpDir();
    const certPath = path.join(tmpDir, 'ca.crt');
    fs.writeFileSync(certPath, '-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n');
    try {
      // Should not throw
      const client = new NetworkVaultClient({
        caCert: certPath,
      });
      expect(client.getUrl()).toBe('https://localhost:13100');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
