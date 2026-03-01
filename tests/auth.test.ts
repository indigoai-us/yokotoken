/**
 * Tests for authentication and rate limiting — US-004.
 *
 * Covers:
 * - Bearer token validation on all endpoints
 * - Unauthorized requests return 401 with no information leakage
 * - Missing/malformed Authorization headers are rejected
 * - Rate limiting: 10 failed auth attempts per minute triggers 5-minute lockout
 * - Rate limiter state management (per-IP tracking, lockout expiry, success clears)
 * - Token generation and file storage
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { VaultEngine } from '../src/vault.js';
import {
  generateToken,
  writeTokenFile,
  readTokenFile,
  validateBearerToken,
  RateLimiter,
} from '../src/auth.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-auth-passphrase-2026';
const VALID_TOKEN = 'valid-test-token-for-auth-tests';
const WRONG_TOKEN = 'wrong-token-totally-invalid';

/**
 * Helper: create a temporary directory and server config.
 */
function createTmpConfig(overrides?: Partial<ServerConfig>): {
  tmpDir: string;
  config: ServerConfig;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-auth-'));
  const config: ServerConfig = {
    vaultPath: path.join(tmpDir, 'vault.db'),
    port: 0,
    idleTimeoutMs: 0,
    pidFile: path.join(tmpDir, 'vault.pid'),
    portFile: path.join(tmpDir, 'vault.port'),
    tokenFile: path.join(tmpDir, 'token'),
    insecure: true,
    token: VALID_TOKEN,
    ...overrides,
  };
  return { tmpDir, config };
}

function getPort(server: http.Server): number {
  const addr = server.address();
  if (typeof addr === 'object' && addr) return addr.port;
  throw new Error('Server has no address');
}

// ─── Token generation and storage ────────────────────────────────────

describe('Auth — token generation', () => {
  it('should generate unique tokens', () => {
    const t1 = generateToken();
    const t2 = generateToken();
    expect(t1).not.toBe(t2);
  });

  it('should generate base64url tokens of expected length', () => {
    const token = generateToken();
    // 32 bytes base64url = 43 characters
    expect(token.length).toBe(43);
    // Should only contain base64url characters
    expect(/^[A-Za-z0-9_-]+$/.test(token)).toBe(true);
  });

  it('should write and read token from file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-token-'));
    const tokenFile = path.join(tmpDir, 'token');
    const token = 'test-token-value-12345';

    writeTokenFile(tokenFile, token);
    expect(fs.existsSync(tokenFile)).toBe(true);

    const readBack = readTokenFile(tokenFile);
    expect(readBack).toBe(token);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should return null for missing token file', () => {
    const result = readTokenFile('/nonexistent/path/token');
    expect(result).toBeNull();
  });
});

// ─── Bearer token validation ─────────────────────────────────────────

describe('Auth — validateBearerToken', () => {
  const token = 'my-secret-token-abc123';

  it('should accept valid Bearer token', () => {
    expect(validateBearerToken(`Bearer ${token}`, token)).toBe(true);
  });

  it('should reject missing header', () => {
    expect(validateBearerToken(undefined, token)).toBe(false);
  });

  it('should reject empty header', () => {
    expect(validateBearerToken('', token)).toBe(false);
  });

  it('should reject wrong scheme', () => {
    expect(validateBearerToken(`Basic ${token}`, token)).toBe(false);
  });

  it('should reject wrong token value', () => {
    expect(validateBearerToken('Bearer wrong-token', token)).toBe(false);
  });

  it('should reject token with extra spaces', () => {
    expect(validateBearerToken(`Bearer  ${token}`, token)).toBe(false);
  });

  it('should reject header with no token after Bearer', () => {
    expect(validateBearerToken('Bearer', token)).toBe(false);
  });
});

// ─── Server auth enforcement ─────────────────────────────────────────

describe('Auth — server rejects unauthorized requests', () => {
  let server: http.Server;
  let tmpDir: string;
  let port: number;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = new VaultEngine(result.config.vaultPath);
    vault.init(PASSPHRASE);
    vault.store('test/secret', 'my-value');
    vault.close();

    server = await createVaultServer(result.config) as http.Server;
    port = getPort(server);
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should reject request with no Authorization header', async () => {
    const client: ClientConfig = { port, host: '127.0.0.1', insecure: true };
    // No token set — request without auth
    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('should reject request with wrong token', async () => {
    const client: ClientConfig = { port, host: '127.0.0.1', token: WRONG_TOKEN, insecure: true };
    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('should accept request with valid token', async () => {
    const client: ClientConfig = { port, host: '127.0.0.1', token: VALID_TOKEN, insecure: true };
    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(200);
  });

  it('should return 401 with no information leakage on unauthorized', async () => {
    const client: ClientConfig = { port, host: '127.0.0.1', token: WRONG_TOKEN, insecure: true };

    // Try various endpoints — all should return same 401 with no details
    const endpoints = [
      { method: 'GET', path: '/v1/status' },
      { method: 'POST', path: '/v1/unlock' },
      { method: 'POST', path: '/v1/lock' },
      { method: 'GET', path: '/v1/secrets' },
      { method: 'GET', path: '/v1/secrets/test/secret' },
      { method: 'PUT', path: '/v1/secrets/test/new' },
      { method: 'DELETE', path: '/v1/secrets/test/secret' },
    ];

    for (const ep of endpoints) {
      const res = await request(client, ep.method, ep.path);
      // Should be 401 (or 429 if rate-limited after too many attempts)
      expect([401, 429]).toContain(res.statusCode);
      if (res.statusCode === 401) {
        // Only "Unauthorized" — no endpoint info, no vault state, no hints
        expect(res.body.error).toBe('Unauthorized');
        expect(Object.keys(res.body)).toEqual(['error']);
      }
    }
  });

  it('should not reveal whether vault is locked/unlocked to unauthorized', async () => {
    const client: ClientConfig = { port, host: '127.0.0.1', token: WRONG_TOKEN, insecure: true };
    const res = await request(client, 'GET', '/v1/status');
    // Should be 401 (or 429)
    expect([401, 429]).toContain(res.statusCode);
    expect(res.body).not.toHaveProperty('locked');
    expect(res.body).not.toHaveProperty('initialized');
    expect(res.body).not.toHaveProperty('vaultPath');
  });
});

// ─── Rate limiter unit tests ─────────────────────────────────────────

describe('Auth — RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter({
      maxFailures: 3,     // Lower threshold for testing
      windowMs: 1000,     // 1 second window
      lockoutMs: 2000,    // 2 second lockout
    });
  });

  it('should not be locked initially', () => {
    expect(limiter.isLocked('127.0.0.1')).toBe(0);
  });

  it('should track failures per IP', () => {
    limiter.recordFailure('127.0.0.1');
    limiter.recordFailure('127.0.0.1');
    expect(limiter.getFailureCount('127.0.0.1')).toBe(2);
    expect(limiter.getFailureCount('10.0.0.1')).toBe(0);
  });

  it('should lock after max failures', () => {
    limiter.recordFailure('127.0.0.1');
    limiter.recordFailure('127.0.0.1');
    const locked = limiter.recordFailure('127.0.0.1');
    expect(locked).toBe(true);
    expect(limiter.isLocked('127.0.0.1')).toBeGreaterThan(0);
  });

  it('should not affect other IPs when one is locked', () => {
    // Lock 127.0.0.1
    for (let i = 0; i < 3; i++) limiter.recordFailure('127.0.0.1');
    expect(limiter.isLocked('127.0.0.1')).toBeGreaterThan(0);
    expect(limiter.isLocked('10.0.0.1')).toBe(0);
  });

  it('should clear failures on success', () => {
    limiter.recordFailure('127.0.0.1');
    limiter.recordFailure('127.0.0.1');
    expect(limiter.getFailureCount('127.0.0.1')).toBe(2);

    limiter.recordSuccess('127.0.0.1');
    expect(limiter.getFailureCount('127.0.0.1')).toBe(0);
  });

  it('should expire lockout after timeout', async () => {
    // Lock the IP
    for (let i = 0; i < 3; i++) limiter.recordFailure('127.0.0.1');
    expect(limiter.isLocked('127.0.0.1')).toBeGreaterThan(0);

    // Wait for lockout to expire (2 seconds + buffer)
    await new Promise(resolve => setTimeout(resolve, 2200));

    expect(limiter.isLocked('127.0.0.1')).toBe(0);
  });

  it('should expire old failures outside the window', async () => {
    limiter.recordFailure('127.0.0.1');
    limiter.recordFailure('127.0.0.1');
    expect(limiter.getFailureCount('127.0.0.1')).toBe(2);

    // Wait for window to expire (1 second + buffer)
    await new Promise(resolve => setTimeout(resolve, 1200));

    // Old failures are expired, so should not be locked even after one more
    const locked = limiter.recordFailure('127.0.0.1');
    expect(locked).toBe(false);
    expect(limiter.getFailureCount('127.0.0.1')).toBe(1);
  });

  it('should reset all state', () => {
    limiter.recordFailure('127.0.0.1');
    limiter.recordFailure('10.0.0.1');
    limiter.reset();
    expect(limiter.getFailureCount('127.0.0.1')).toBe(0);
    expect(limiter.getFailureCount('10.0.0.1')).toBe(0);
  });
});

// ─── Server-level rate limiting ──────────────────────────────────────

describe('Auth — server rate limiting', () => {
  let server: http.Server;
  let tmpDir: string;
  let port: number;

  beforeAll(async () => {
    const result = createTmpConfig({
      rateLimitConfig: {
        maxFailures: 5,      // 5 failures for testing
        windowMs: 60000,     // 1 minute window
        lockoutMs: 2000,     // 2 second lockout (short for testing)
      },
    });
    tmpDir = result.tmpDir;

    server = await createVaultServer(result.config) as http.Server;
    port = getPort(server);
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should return 429 after too many failed auth attempts', async () => {
    const badClient: ClientConfig = { port, host: '127.0.0.1', token: WRONG_TOKEN, insecure: true };

    // Make 5 failed attempts
    for (let i = 0; i < 5; i++) {
      const res = await request(badClient, 'GET', '/v1/status');
      // Each should be 401 until we hit the limit
      expect([401, 429]).toContain(res.statusCode);
    }

    // Next attempt should be 429 (rate limited)
    const res = await request(badClient, 'GET', '/v1/status');
    expect(res.statusCode).toBe(429);
    expect(res.body.error).toContain('Too many failed attempts');
  });

  it('should still allow valid token after rate limit on bad token', async () => {
    // The valid token should still work (rate limit is per behavior, but
    // a successful auth clears the failure count — here same IP though)
    // After lockout expires, valid requests should work
    await new Promise(resolve => setTimeout(resolve, 2200));

    const goodClient: ClientConfig = { port, host: '127.0.0.1', token: VALID_TOKEN, insecure: true };
    const res = await request(goodClient, 'GET', '/v1/status');
    expect(res.statusCode).toBe(200);
  });
});
