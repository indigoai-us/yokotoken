/**
 * Tests for the access token system — US-005.
 *
 * Covers:
 * - Token creation (random 32 bytes, base64url, stored as SHA-256 hash)
 * - Token validation against stored hash (not plaintext)
 * - Token metadata: name, created_at, expires_at, last_used_at, use_count
 * - TTL parsing and expiry rejection
 * - Max uses enforcement
 * - Token listing (metadata only, no raw values)
 * - Token revocation by name
 * - Server endpoints: POST /v1/tokens, GET /v1/tokens, DELETE /v1/tokens/:name
 * - Managed tokens accepted by all vault endpoints
 * - Expired and max-use-exceeded tokens rejected with 401
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { VaultEngine } from '../src/vault.js';
import { VaultDatabase } from '../src/db.js';
import {
  TokenManager,
  generateAccessToken,
  hashToken,
  parseTTL,
} from '../src/tokens.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-token-passphrase-2026';
const ADMIN_TOKEN = 'admin-bootstrap-token-for-tests';

// ─── Helper: temp config ─────────────────────────────────────────────

function createTmpConfig(overrides?: Partial<ServerConfig>): {
  tmpDir: string;
  config: ServerConfig;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-tokens-'));
  const config: ServerConfig = {
    vaultPath: path.join(tmpDir, 'vault.db'),
    port: 0,
    idleTimeoutMs: 0,
    pidFile: path.join(tmpDir, 'vault.pid'),
    portFile: path.join(tmpDir, 'vault.port'),
    tokenFile: path.join(tmpDir, 'token'),
    insecure: true,
    token: ADMIN_TOKEN,
    ...overrides,
  };
  return { tmpDir, config };
}

function getPort(server: http.Server): number {
  const addr = server.address();
  if (typeof addr === 'object' && addr) return addr.port;
  throw new Error('Server has no address');
}

function adminClient(server: http.Server): ClientConfig {
  return { port: getPort(server), host: '127.0.0.1', token: ADMIN_TOKEN, insecure: true };
}

// ─── Unit: generateAccessToken ────────────────────────────────────────

describe('Tokens — generateAccessToken', () => {
  it('should generate unique tokens', () => {
    const t1 = generateAccessToken();
    const t2 = generateAccessToken();
    expect(t1).not.toBe(t2);
  });

  it('should generate base64url tokens from 32 random bytes', () => {
    const token = generateAccessToken();
    // 32 bytes base64url = 43 characters
    expect(token.length).toBe(43);
    expect(/^[A-Za-z0-9_-]+$/.test(token)).toBe(true);
  });
});

// ─── Unit: hashToken ──────────────────────────────────────────────────

describe('Tokens — hashToken', () => {
  it('should produce consistent SHA-256 hex output', () => {
    const token = 'test-token-value';
    const h1 = hashToken(token);
    const h2 = hashToken(token);
    expect(h1).toBe(h2);
    expect(h1.length).toBe(64); // SHA-256 hex = 64 chars
    expect(/^[0-9a-f]+$/.test(h1)).toBe(true);
  });

  it('should produce different hashes for different tokens', () => {
    expect(hashToken('token-a')).not.toBe(hashToken('token-b'));
  });
});

// ─── Unit: parseTTL ───────────────────────────────────────────────────

describe('Tokens — parseTTL', () => {
  it('should parse seconds', () => {
    expect(parseTTL('30s')).toBe(30_000);
  });

  it('should parse minutes', () => {
    expect(parseTTL('10m')).toBe(600_000);
  });

  it('should parse hours', () => {
    expect(parseTTL('1h')).toBe(3_600_000);
  });

  it('should parse days', () => {
    expect(parseTTL('7d')).toBe(604_800_000);
  });

  it('should return null for null/undefined/empty', () => {
    expect(parseTTL(null)).toBeNull();
    expect(parseTTL(undefined)).toBeNull();
    expect(parseTTL('')).toBeNull();
  });

  it('should throw on invalid format', () => {
    expect(() => parseTTL('abc')).toThrow('Invalid TTL format');
    expect(() => parseTTL('1x')).toThrow('Invalid TTL format');
    expect(() => parseTTL('h')).toThrow('Invalid TTL format');
  });
});

// ─── Unit: TokenManager with direct DB ────────────────────────────────

describe('Tokens — TokenManager (direct)', () => {
  let tmpDir: string;
  let db: VaultDatabase;
  let manager: TokenManager;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-tm-'));
    db = await VaultDatabase.open(path.join(tmpDir, 'vault.db'));
    manager = new TokenManager(db);
  });

  it('should create a token and return raw value + metadata', () => {
    const result = manager.create({ name: 'test-agent' });
    expect(result.token).toBeTruthy();
    expect(result.token.length).toBe(43); // 32 bytes base64url
    expect(result.metadata.name).toBe('test-agent');
    expect(result.metadata.expiresAt).toBeNull();
    expect(result.metadata.maxUses).toBeNull();
    expect(result.metadata.useCount).toBe(0);
  });

  it('should validate a created token', () => {
    const result = manager.create({ name: 'my-token' });
    const validation = manager.validate(result.token);
    expect(validation.valid).toBe(true);
    expect(validation.tokenName).toBe('my-token');
  });

  it('should reject an unknown token', () => {
    const validation = manager.validate('totally-fake-token-value');
    expect(validation.valid).toBe(false);
    expect(validation.reason).toBe('not_found');
  });

  it('should reject duplicate token names', () => {
    manager.create({ name: 'agent-1' });
    expect(() => manager.create({ name: 'agent-1' })).toThrow('already exists');
  });

  it('should reject empty token name', () => {
    expect(() => manager.create({ name: '' })).toThrow('cannot be empty');
  });

  it('should track use_count on validation', () => {
    const result = manager.create({ name: 'counted' });

    manager.validate(result.token);
    manager.validate(result.token);
    manager.validate(result.token);

    const meta = manager.getByName('counted');
    expect(meta).not.toBeNull();
    expect(meta!.useCount).toBe(3);
    expect(meta!.lastUsedAt).not.toBeNull();
  });

  it('should enforce max_uses', () => {
    const result = manager.create({ name: 'limited', maxUses: 2 });

    // First two uses succeed
    expect(manager.validate(result.token).valid).toBe(true);
    expect(manager.validate(result.token).valid).toBe(true);

    // Third use exceeds limit
    const third = manager.validate(result.token);
    expect(third.valid).toBe(false);
    expect(third.reason).toBe('max_uses_exceeded');
  });

  it('should create token with TTL and set expires_at', () => {
    const result = manager.create({ name: 'ttl-token', ttl: '1h' });
    expect(result.metadata.expiresAt).not.toBeNull();

    // expires_at should be roughly 1 hour from now
    const expiresMs = new Date(result.metadata.expiresAt!).getTime();
    const nowMs = Date.now();
    const diff = expiresMs - nowMs;
    expect(diff).toBeGreaterThan(3500_000); // ~58 min
    expect(diff).toBeLessThan(3700_000);    // ~62 min
  });

  it('should reject expired tokens', () => {
    // Create a token that expires immediately by using a very short TTL
    const result = manager.create({ name: 'expired-token', ttl: '1s' });

    // Manually hack the expires_at to be in the past
    // (We can't really wait — so we'll do a direct DB update)
    const pastDate = new Date(Date.now() - 10_000).toISOString();
    db['db'].run(
      "UPDATE token_store SET expires_at = ? WHERE name = ?",
      [pastDate, 'expired-token'],
    );

    const validation = manager.validate(result.token);
    expect(validation.valid).toBe(false);
    expect(validation.reason).toBe('expired');
  });

  it('should list tokens with metadata (no raw values)', () => {
    manager.create({ name: 'token-a' });
    manager.create({ name: 'token-b', ttl: '7d' });
    manager.create({ name: 'token-c', maxUses: 100 });

    const list = manager.list();
    expect(list.length).toBe(3);

    // Should have metadata but no raw token values
    for (const t of list) {
      expect(t.name).toBeTruthy();
      expect(t.createdAt).toBeTruthy();
      expect((t as any).token).toBeUndefined();
      expect((t as any).token_hash).toBeUndefined();
    }

    const names = list.map(t => t.name);
    expect(names).toContain('token-a');
    expect(names).toContain('token-b');
    expect(names).toContain('token-c');
  });

  it('should revoke a token', () => {
    const result = manager.create({ name: 'to-revoke' });

    // Token should work initially
    expect(manager.validate(result.token).valid).toBe(true);

    // Revoke
    const revoked = manager.revoke('to-revoke');
    expect(revoked).toBe(true);

    // Token should no longer work
    const validation = manager.validate(result.token);
    expect(validation.valid).toBe(false);
    expect(validation.reason).toBe('not_found');
  });

  it('should return false when revoking non-existent token', () => {
    const revoked = manager.revoke('nonexistent');
    expect(revoked).toBe(false);
  });

  it('should count tokens', () => {
    expect(manager.count()).toBe(0);
    manager.create({ name: 'a' });
    manager.create({ name: 'b' });
    expect(manager.count()).toBe(2);
    manager.revoke('a');
    expect(manager.count()).toBe(1);
  });

  it('should reject invalid max_uses', () => {
    expect(() => manager.create({ name: 'bad', maxUses: 0 })).toThrow('positive integer');
    expect(() => manager.create({ name: 'bad2', maxUses: -1 })).toThrow('positive integer');
    expect(() => manager.create({ name: 'bad3', maxUses: 1.5 })).toThrow('positive integer');
  });
});

// ─── Integration: server token endpoints ──────────────────────────────

describe('Tokens — server endpoints (POST/GET/DELETE /v1/tokens)', () => {
  let server: http.Server;
  let tmpDir: string;
  let port: number;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    // Pre-initialize vault
    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('test/secret', 'secret-value');
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
    port = getPort(server);
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should create a token via POST /v1/tokens', async () => {
    const client = adminClient(server);
    const res = await request(client, 'POST', '/v1/tokens', {
      name: 'agent-worker',
    });

    expect(res.statusCode).toBe(201);
    expect(res.body.ok).toBe(true);
    expect(typeof res.body.token).toBe('string');
    expect((res.body.token as string).length).toBe(43);
    expect(res.body.metadata).toBeDefined();
    expect((res.body.metadata as any).name).toBe('agent-worker');
  });

  it('should create a token with TTL', async () => {
    const client = adminClient(server);
    const res = await request(client, 'POST', '/v1/tokens', {
      name: 'ttl-agent',
      ttl: '24h',
    });

    expect(res.statusCode).toBe(201);
    const meta = res.body.metadata as any;
    expect(meta.expiresAt).not.toBeNull();
  });

  it('should create a token with max_uses', async () => {
    const client = adminClient(server);
    const res = await request(client, 'POST', '/v1/tokens', {
      name: 'limited-agent',
      max_uses: 10,
    });

    expect(res.statusCode).toBe(201);
    const meta = res.body.metadata as any;
    expect(meta.maxUses).toBe(10);
  });

  it('should reject token creation without name', async () => {
    const client = adminClient(server);
    const res = await request(client, 'POST', '/v1/tokens', {});
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('name is required');
  });

  it('should reject duplicate token name', async () => {
    const client = adminClient(server);
    const res = await request(client, 'POST', '/v1/tokens', {
      name: 'agent-worker', // already created above
    });
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('already exists');
  });

  it('should list tokens via GET /v1/tokens', async () => {
    const client = adminClient(server);
    const res = await request(client, 'GET', '/v1/tokens');

    expect(res.statusCode).toBe(200);
    const tokens = res.body.tokens as any[];
    expect(tokens.length).toBeGreaterThanOrEqual(3);

    // Should NOT include raw token values
    for (const t of tokens) {
      expect(t.token).toBeUndefined();
      expect(t.token_hash).toBeUndefined();
      expect(t.name).toBeTruthy();
    }
  });

  it('should revoke a token via DELETE /v1/tokens/:name', async () => {
    const client = adminClient(server);

    // Create a token to revoke
    const createRes = await request(client, 'POST', '/v1/tokens', {
      name: 'to-revoke-via-api',
    });
    expect(createRes.statusCode).toBe(201);

    // Revoke it
    const res = await request(client, 'DELETE', '/v1/tokens/to-revoke-via-api');
    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);

    // Should not appear in list anymore
    const listRes = await request(client, 'GET', '/v1/tokens');
    const names = (listRes.body.tokens as any[]).map(t => t.name);
    expect(names).not.toContain('to-revoke-via-api');
  });

  it('should return 404 when revoking non-existent token', async () => {
    const client = adminClient(server);
    const res = await request(client, 'DELETE', '/v1/tokens/ghost-token');
    expect(res.statusCode).toBe(404);
  });
});

// ─── Integration: managed token auth on vault endpoints ───────────────

describe('Tokens — managed token auth on vault endpoints', () => {
  let server: http.Server;
  let tmpDir: string;
  let port: number;
  let managedTokenValue: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    // Pre-initialize vault
    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('test/my-secret', 'the-value');
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
    port = getPort(server);

    // Create a managed token using the admin token
    const client = adminClient(server);
    const createRes = await request(client, 'POST', '/v1/tokens', {
      name: 'managed-agent',
    });
    managedTokenValue = createRes.body.token as string;

    // Unlock the vault
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should accept managed token on GET /v1/status', async () => {
    const client: ClientConfig = {
      port, host: '127.0.0.1', token: managedTokenValue, insecure: true,
    };
    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(200);
    expect(res.body.locked).toBe(false);
  });

  it('should accept managed token on GET /v1/secrets/:path', async () => {
    const client: ClientConfig = {
      port, host: '127.0.0.1', token: managedTokenValue, insecure: true,
    };
    const res = await request(client, 'GET', '/v1/secrets/test%2Fmy-secret');
    expect(res.statusCode).toBe(200);
    expect(res.body.value).toBe('the-value');
  });

  it('should accept managed token on PUT /v1/secrets/:path', async () => {
    const client: ClientConfig = {
      port, host: '127.0.0.1', token: managedTokenValue, insecure: true,
    };
    const res = await request(client, 'PUT', '/v1/secrets/test%2Fnew-secret', {
      value: 'new-value',
    });
    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it('should accept managed token on GET /v1/secrets (list)', async () => {
    const client: ClientConfig = {
      port, host: '127.0.0.1', token: managedTokenValue, insecure: true,
    };
    const res = await request(client, 'GET', '/v1/secrets');
    expect(res.statusCode).toBe(200);
    expect((res.body.entries as any[]).length).toBeGreaterThanOrEqual(1);
  });

  it('should reject a fake token', async () => {
    const client: ClientConfig = {
      port, host: '127.0.0.1', token: 'completely-fake-token', insecure: true,
    };
    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);
  });
});

// ─── Integration: expired and max-uses rejection via server ───────────

describe('Tokens — expired and max-uses rejection at server level', () => {
  let server: http.Server;
  let tmpDir: string;
  let port: number;
  let expiredTokenValue: string;
  let limitedTokenValue: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    server = await createVaultServer(result.config) as http.Server;
    port = getPort(server);

    const client = adminClient(server);

    // Create an expired token (short TTL, then hack the DB)
    const expiredRes = await request(client, 'POST', '/v1/tokens', {
      name: 'expired-agent',
      ttl: '1s',
    });
    expiredTokenValue = expiredRes.body.token as string;

    // Create a max-uses=1 token
    const limitedRes = await request(client, 'POST', '/v1/tokens', {
      name: 'limited-agent',
      max_uses: 1,
    });
    limitedTokenValue = limitedRes.body.token as string;

    // Unlock the vault
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });

    // Use the limited token once (its only allowed use)
    const limitedClient: ClientConfig = {
      port, host: '127.0.0.1', token: limitedTokenValue, insecure: true,
    };
    await request(limitedClient, 'GET', '/v1/status');

    // Wait for the expired token to actually expire
    await new Promise(resolve => setTimeout(resolve, 1500));
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should reject expired token with 401', async () => {
    const client: ClientConfig = {
      port, host: '127.0.0.1', token: expiredTokenValue, insecure: true,
    };
    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('should reject max-uses-exceeded token with 401', async () => {
    const client: ClientConfig = {
      port, host: '127.0.0.1', token: limitedTokenValue, insecure: true,
    };
    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('should still accept the admin/bootstrap token', async () => {
    const client = adminClient(server);
    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(200);
  });
});
