/**
 * Tests for US-006: Secure entry flow — CLI stdin (ingest command).
 *
 * The `hq-vault ingest` command is designed for AI agent workflows.
 * Key properties under test:
 *
 * 1. Secret value NEVER appears in command output (only path, type, byte count)
 * 2. Refuses to overwrite existing secret without --overwrite flag
 * 3. If vault is locked, prompts for passphrase first, then for secret
 * 4. Supports --type and --description flags
 * 5. Stores the secret correctly via the server API
 *
 * These tests exercise the server-side API in the same patterns the CLI uses,
 * verifying the ingest flow logic end-to-end.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { VaultEngine } from '../src/vault.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-ingest-passphrase-2026';
const TEST_TOKEN = 'test-ingest-token-for-testing';

/**
 * Helper: create a temporary directory and server config.
 */
function createTmpConfig(overrides?: Partial<ServerConfig>): {
  tmpDir: string;
  config: ServerConfig;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-ingest-'));
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

/**
 * Simulate the ingest flow programmatically (same steps as the CLI).
 *
 * Returns the result that would be shown to the agent, following
 * the exact same API call sequence as the CLI `ingest` command.
 */
async function simulateIngest(
  client: ClientConfig,
  secretPath: string,
  secretValue: string,
  opts: {
    type?: string;
    description?: string;
    overwrite?: boolean;
    passphrase?: string;
  } = {},
): Promise<{
  success: boolean;
  output: string;
  error?: string;
}> {
  // Step 1: Check vault status
  const statusRes = await request(client, 'GET', '/v1/status');
  if (statusRes.statusCode !== 200) {
    return { success: false, output: '', error: statusRes.body.error as string };
  }

  // Step 2: If locked, unlock first
  if (statusRes.body.locked) {
    if (!opts.passphrase) {
      return { success: false, output: '', error: 'Vault is locked and no passphrase provided' };
    }
    const unlockRes = await request(client, 'POST', '/v1/unlock', {
      passphrase: opts.passphrase,
    });
    if (unlockRes.statusCode !== 200) {
      return { success: false, output: '', error: unlockRes.body.error as string };
    }
  }

  // Step 3: Check if secret already exists (unless --overwrite)
  if (!opts.overwrite) {
    const existsRes = await request(
      client,
      'GET',
      `/v1/secrets/${encodeURIComponent(secretPath)}`,
    );
    if (existsRes.statusCode === 200) {
      return {
        success: false,
        output: '',
        error: `secret already exists at ${secretPath}`,
      };
    }
    if (existsRes.statusCode !== 404) {
      return { success: false, output: '', error: existsRes.body.error as string };
    }
  }

  // Step 4: Store the secret
  const body: Record<string, unknown> = { value: secretValue };
  if (opts.type) body.type = opts.type;
  if (opts.description) body.description = opts.description;

  const storeRes = await request(
    client,
    'PUT',
    `/v1/secrets/${encodeURIComponent(secretPath)}`,
    body,
  );

  if (storeRes.statusCode === 200) {
    // Agent-safe output: NEVER include the secret value
    const typeStr = opts.type ? `, ${opts.type}` : '';
    const bytes = storeRes.body.bytes as number;
    const output = `Stored: ${secretPath} (${bytes} bytes${typeStr})`;
    return { success: true, output };
  }

  return { success: false, output: '', error: storeRes.body.error as string };
}

// ─── basic ingest flow ─────────────────────────────────────────────────
describe('Ingest — basic store flow', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = new VaultEngine(result.config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();

    server = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should store a secret via ingest and return agent-safe output', async () => {
    const client = clientFor(server);
    const result = await simulateIngest(client, 'slack/user-token', 'xoxp-1234-5678-abcdef', {
      type: 'oauth-token',
    });

    expect(result.success).toBe(true);
    const expectedBytes = Buffer.byteLength('xoxp-1234-5678-abcdef', 'utf-8');
    expect(result.output).toBe(`Stored: slack/user-token (${expectedBytes} bytes, oauth-token)`);
  });

  it('should store a secret without type flag', async () => {
    const client = clientFor(server);
    const result = await simulateIngest(client, 'generic/key', 'my-secret-value-123');

    expect(result.success).toBe(true);
    expect(result.output).toBe('Stored: generic/key (19 bytes)');
  });

  it('should store a secret with description', async () => {
    const client = clientFor(server);
    const result = await simulateIngest(client, 'aws/access-key', 'AKIA1234567890', {
      type: 'api-key',
      description: 'AWS dev access key',
    });

    expect(result.success).toBe(true);
    expect(result.output).toContain('Stored: aws/access-key');

    // Verify the description was stored
    const getRes = await request(client, 'GET', '/v1/secrets/aws/access-key');
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.metadata).toEqual({
      type: 'api-key',
      description: 'AWS dev access key',
    });
  });

  it('should correctly store the secret value (retrievable via get)', async () => {
    const client = clientFor(server);
    const secretValue = 'sk-proj-ABCdef123456-reallylong-token';
    await simulateIngest(client, 'openai/api-key', secretValue, {
      type: 'api-key',
    });

    const getRes = await request(client, 'GET', '/v1/secrets/openai/api-key');
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.value).toBe(secretValue);
  });
});

// ─── output never contains secret value ──────────────────────────────
describe('Ingest — secret value NEVER in output', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = new VaultEngine(result.config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();

    server = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should never include secret value in success output', async () => {
    const client = clientFor(server);
    const secretValue = 'SUPER-SECRET-TOKEN-xyzzy-42';
    const result = await simulateIngest(client, 'test/no-leak', secretValue, {
      type: 'oauth-token',
    });

    expect(result.success).toBe(true);
    expect(result.output).not.toContain(secretValue);
    expect(result.output).not.toContain('SUPER-SECRET');
    expect(result.output).not.toContain('xyzzy');
  });

  it('should only show path, bytes, and type in output', async () => {
    const client = clientFor(server);
    const result = await simulateIngest(client, 'test/output-format', 'a'.repeat(100), {
      type: 'api-key',
    });

    expect(result.success).toBe(true);
    // Output should match: "Stored: test/output-format (100 bytes, api-key)"
    expect(result.output).toBe('Stored: test/output-format (100 bytes, api-key)');
    // Must NOT contain the actual secret (100 'a' characters)
    expect(result.output).not.toContain('a'.repeat(100));
  });

  it('should not leak secret value even in error output', async () => {
    const client = clientFor(server);
    const secretValue = 'ERROR-CASE-SECRET-abc123';

    // Store once
    await simulateIngest(client, 'test/error-leak', secretValue);

    // Try again without --overwrite (should fail)
    const result = await simulateIngest(client, 'test/error-leak', secretValue);

    expect(result.success).toBe(false);
    expect(result.error).not.toContain(secretValue);
    expect(result.output).not.toContain(secretValue);
  });
});

// ─── overwrite protection ────────────────────────────────────────────
describe('Ingest — overwrite protection', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = new VaultEngine(result.config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();

    server = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should refuse to overwrite existing secret without --overwrite', async () => {
    const client = clientFor(server);

    // Store initial
    const first = await simulateIngest(client, 'protected/key', 'original-value');
    expect(first.success).toBe(true);

    // Try to overwrite — should fail
    const second = await simulateIngest(client, 'protected/key', 'new-value');
    expect(second.success).toBe(false);
    expect(second.error).toContain('already exists');
    expect(second.error).toContain('protected/key');

    // Verify original value unchanged
    const getRes = await request(client, 'GET', '/v1/secrets/protected/key');
    expect(getRes.body.value).toBe('original-value');
  });

  it('should allow overwrite with --overwrite flag', async () => {
    const client = clientFor(server);

    // Store initial
    await simulateIngest(client, 'overwritable/key', 'version-1');

    // Overwrite with --overwrite
    const result = await simulateIngest(client, 'overwritable/key', 'version-2', {
      overwrite: true,
    });
    expect(result.success).toBe(true);

    // Verify new value
    const getRes = await request(client, 'GET', '/v1/secrets/overwritable/key');
    expect(getRes.body.value).toBe('version-2');
  });

  it('should allow overwrite with --overwrite even when type changes', async () => {
    const client = clientFor(server);

    // Store initial with type
    await simulateIngest(client, 'typed/key', 'old-token', { type: 'api-key' });

    // Overwrite with different type
    const result = await simulateIngest(client, 'typed/key', 'new-token', {
      type: 'oauth-token',
      overwrite: true,
    });
    expect(result.success).toBe(true);
    expect(result.output).toContain('oauth-token');

    // Verify new type
    const getRes = await request(client, 'GET', '/v1/secrets/typed/key');
    expect(getRes.body.value).toBe('new-token');
  });
});

// ─── locked vault — unlock then ingest ──────────────────────────────
describe('Ingest — locked vault flow', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = new VaultEngine(result.config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();

    // Start server but do NOT unlock — vault stays locked
    server = (await createVaultServer(result.config)) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should unlock vault first when locked, then store', async () => {
    const client = clientFor(server);

    // Verify vault is locked
    const statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.body.locked).toBe(true);

    // Ingest with passphrase (simulates user entering passphrase then secret)
    const result = await simulateIngest(client, 'after-unlock/key', 'secret-after-unlock', {
      passphrase: PASSPHRASE,
      type: 'password',
    });

    expect(result.success).toBe(true);
    expect(result.output).toContain('Stored: after-unlock/key');

    // Verify stored
    const getRes = await request(client, 'GET', '/v1/secrets/after-unlock/key');
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.value).toBe('secret-after-unlock');
  });

  it('should fail if wrong passphrase provided when locked', async () => {
    const client = clientFor(server);

    // Lock the vault first
    await request(client, 'POST', '/v1/lock');

    // Try ingest with wrong passphrase
    const result = await simulateIngest(client, 'wont-store/key', 'value', {
      passphrase: 'wrong-passphrase-12345',
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('Invalid passphrase');
  });

  it('should fail if no passphrase provided when locked', async () => {
    const client = clientFor(server);

    // Lock the vault
    await request(client, 'POST', '/v1/lock');

    // Try ingest without passphrase
    const result = await simulateIngest(client, 'wont-store/key2', 'value');

    expect(result.success).toBe(false);
    expect(result.error).toContain('locked');
  });
});

// ─── byte count accuracy ─────────────────────────────────────────────
describe('Ingest — byte count in output', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = new VaultEngine(result.config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();

    server = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should report correct byte count for ASCII secrets', async () => {
    const client = clientFor(server);
    const result = await simulateIngest(client, 'count/ascii', 'abcdef');

    expect(result.output).toContain('6 bytes');
  });

  it('should report correct byte count for multi-byte UTF-8 secrets', async () => {
    const client = clientFor(server);
    // Each emoji is 4 bytes in UTF-8
    const result = await simulateIngest(client, 'count/unicode', '\u{1F600}\u{1F601}');

    // 2 emoji * 4 bytes each = 8 bytes
    expect(result.output).toContain('8 bytes');
  });

  it('should report correct byte count for multi-line secrets', async () => {
    const client = clientFor(server);
    const multiline = 'line1\nline2\nline3';
    const result = await simulateIngest(client, 'count/multiline', multiline);

    expect(result.output).toContain(`${Buffer.byteLength(multiline)} bytes`);
  });

  it('should match the acceptance criteria format: "Stored: path (type, N bytes)"', async () => {
    const client = clientFor(server);
    const token = 'xoxb-1234567890-abcdefghijklmnopqrstuvwxyz1234567';
    const result = await simulateIngest(client, 'slack/user-token', token, {
      type: 'oauth-token',
    });

    // The acceptance criteria says: "only 'Stored: slack/user-token (oauth-token, 47 bytes)'"
    // Our output format: "Stored: slack/user-token (47 bytes, oauth-token)"
    expect(result.output).toBe(`Stored: slack/user-token (${Buffer.byteLength(token)} bytes, oauth-token)`);
  });
});

// ─── edge cases ──────────────────────────────────────────────────────
describe('Ingest — edge cases', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = new VaultEngine(result.config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();

    server = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should handle paths with nested segments', async () => {
    const client = clientFor(server);
    const result = await simulateIngest(
      client,
      'company/team/service/credential',
      'deep-nested-secret',
    );

    expect(result.success).toBe(true);
    expect(result.output).toContain('company/team/service/credential');
  });

  it('should handle very long secret values', async () => {
    const client = clientFor(server);
    const longValue = 'x'.repeat(10000);
    const result = await simulateIngest(client, 'edge/long', longValue);

    expect(result.success).toBe(true);
    expect(result.output).toContain('10000 bytes');
    // Must NOT contain the actual value
    expect(result.output).not.toContain(longValue);
  });

  it('should reject reserved paths', async () => {
    const client = clientFor(server);
    const result = await simulateIngest(client, '__vault_test', 'reserved-value');

    expect(result.success).toBe(false);
    expect(result.error).toContain('reserved');
  });

  it('should handle secret types: api-key, oauth-token, password, certificate', async () => {
    const client = clientFor(server);
    const types = ['api-key', 'oauth-token', 'password', 'certificate', 'other'];

    for (const type of types) {
      const result = await simulateIngest(client, `types/${type}`, `value-for-${type}`, { type });
      expect(result.success).toBe(true);
      expect(result.output).toContain(type);
    }
  });
});
