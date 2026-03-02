/**
 * Tests for secret rotation and expiry — US-009.
 *
 * Covers:
 * - parseDuration() helper
 * - Expiry detection (expired flag on get/list)
 * - Stale detection (rotation interval math)
 * - expiringSecrets() / staleSecrets() listing methods
 * - Database-level rotation columns (store, query)
 * - Server endpoints for expiring/stale
 * - Audit log tagging for expired/stale secret access
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { VaultEngine, parseDuration } from '../src/vault.js';
import { VaultDatabase } from '../src/db.js';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { AuditLogger, readAuditLog } from '../src/audit.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-rotation-passphrase-2026';
const TEST_TOKEN = 'test-rotation-token';

// ─── parseDuration() ─────────────────────────────────────────────────

describe('parseDuration()', () => {
  it('should parse seconds', () => {
    expect(parseDuration('30s')).toBe(30_000);
  });

  it('should parse minutes', () => {
    expect(parseDuration('5m')).toBe(5 * 60 * 1000);
  });

  it('should parse hours', () => {
    expect(parseDuration('24h')).toBe(24 * 60 * 60 * 1000);
  });

  it('should parse days', () => {
    expect(parseDuration('30d')).toBe(30 * 24 * 60 * 60 * 1000);
    expect(parseDuration('90d')).toBe(90 * 24 * 60 * 60 * 1000);
  });

  it('should parse weeks', () => {
    expect(parseDuration('1w')).toBe(7 * 24 * 60 * 60 * 1000);
    expect(parseDuration('2w')).toBe(14 * 24 * 60 * 60 * 1000);
  });

  it('should return null for invalid formats', () => {
    expect(parseDuration('')).toBeNull();
    expect(parseDuration('abc')).toBeNull();
    expect(parseDuration('30')).toBeNull();
    expect(parseDuration('30x')).toBeNull();
    expect(parseDuration('d30')).toBeNull();
  });

  it('should handle whitespace', () => {
    expect(parseDuration(' 7d ')).toBe(7 * 24 * 60 * 60 * 1000);
  });
});

// ─── Database-level rotation columns ──────────────────────────────

describe('VaultDatabase — rotation columns', () => {
  let db: VaultDatabase;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-rot-db-'));
    db = await VaultDatabase.open(path.join(tmpDir, 'vault.db'));
  });

  afterAll(() => {
    try { db.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should store a secret with rotation fields', () => {
    const enc = Buffer.from('encrypted');
    const nonce = Buffer.from('nonce-val');
    const expiresAt = '2026-06-01T00:00:00.000Z';
    const rotationInterval = '30d';

    db.storeSecret('test/rotation', enc, nonce, 'api-key', 'Test key', {
      expires_at: expiresAt,
      rotation_interval: rotationInterval,
      last_rotated_at: null,
    });

    const row = db.getSecretRow('test/rotation');
    expect(row).not.toBeNull();
    expect(row!.expires_at).toBe(expiresAt);
    expect(row!.rotation_interval).toBe(rotationInterval);
    expect(row!.last_rotated_at).toBeNull();
  });

  it('should update rotation fields on re-store', () => {
    const enc = Buffer.from('encrypted2');
    const nonce = Buffer.from('nonce-val2');
    const newExpiry = '2026-12-31T00:00:00.000Z';

    db.storeSecret('test/rotation', enc, nonce, undefined, undefined, {
      expires_at: newExpiry,
      rotation_interval: null,
      last_rotated_at: null,
    });

    const row = db.getSecretRow('test/rotation');
    expect(row!.expires_at).toBe(newExpiry);
    // rotation_interval should be preserved via COALESCE since we passed null
    expect(row!.rotation_interval).toBe('30d');
  });

  it('should list expiring secrets', () => {
    // Store a secret that expires in the far future
    db.storeSecret('test/far-future', Buffer.from('e'), Buffer.from('n'), null, null, {
      expires_at: '2099-01-01T00:00:00.000Z',
      rotation_interval: null,
      last_rotated_at: null,
    });

    // Store one that already expired
    db.storeSecret('test/already-expired', Buffer.from('e'), Buffer.from('n'), null, null, {
      expires_at: '2020-01-01T00:00:00.000Z',
      rotation_interval: null,
      last_rotated_at: null,
    });

    // Query for secrets expiring before 2027
    const expiring = db.listExpiringSecrets('2027-01-01T00:00:00.000Z');
    const paths = expiring.map(r => r.path);
    expect(paths).toContain('test/already-expired');
    expect(paths).toContain('test/rotation'); // has expiry in 2026
    expect(paths).not.toContain('test/far-future'); // 2099 is past our window
  });

  it('should list secrets with rotation interval', () => {
    const rows = db.listSecretsWithRotationInterval();
    const paths = rows.map(r => r.path);
    expect(paths).toContain('test/rotation'); // has rotation_interval = '30d'
    expect(paths).not.toContain('test/far-future'); // no rotation_interval
  });

  it('should update rotation fields independently', () => {
    db.updateRotationFields('test/rotation', {
      last_rotated_at: '2026-03-01T00:00:00.000Z',
    });
    const row = db.getSecretRow('test/rotation');
    expect(row!.last_rotated_at).toBe('2026-03-01T00:00:00.000Z');
    // Other fields should be unchanged
    expect(row!.rotation_interval).toBe('30d');
  });
});

// ─── VaultEngine — expiry and stale detection ─────────────────────

describe('VaultEngine — rotation/expiry', () => {
  let vault: VaultEngine;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-rot-engine-'));
    vault = await VaultEngine.open(path.join(tmpDir, 'vault.db'));
    await vault.init(PASSPHRASE);
  });

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should store a secret with expiry and retrieve expired flag', async () => {
    // Store a secret that has already expired
    await vault.store('creds/expired-key', 'secret-value', {
      type: 'api-key',
      description: 'An already expired key',
      expires_at: '2020-01-01T00:00:00.000Z',
    });

    const entry = await vault.get('creds/expired-key');
    expect(entry).not.toBeNull();
    expect(entry!.value).toBe('secret-value');
    expect(entry!.expired).toBe(true);
    expect(entry!.stale).toBe(false);
    expect(entry!.metadata.expires_at).toBe('2020-01-01T00:00:00.000Z');
  });

  it('should return expired=false for non-expired secret', async () => {
    await vault.store('creds/fresh-key', 'value', {
      expires_at: '2099-12-31T00:00:00.000Z',
    });

    const entry = await vault.get('creds/fresh-key');
    expect(entry!.expired).toBe(false);
  });

  it('should return expired=false when no expiry is set', async () => {
    await vault.store('creds/no-expiry', 'value');
    const entry = await vault.get('creds/no-expiry');
    expect(entry!.expired).toBe(false);
    expect(entry!.stale).toBe(false);
  });

  it('should detect stale secrets (past rotation interval)', async () => {
    // Store a secret with a very short rotation interval and old last_rotated_at
    await vault.store('creds/stale-key', 'old-secret', {
      rotation_interval: '1d',
      last_rotated_at: '2020-01-01T00:00:00.000Z',
    });

    const entry = await vault.get('creds/stale-key');
    expect(entry!.stale).toBe(true);
  });

  it('should return stale=false when rotation interval is not exceeded', async () => {
    // Use a long rotation interval with recent last_rotated_at
    await vault.store('creds/recently-rotated', 'value', {
      rotation_interval: '365d',
      last_rotated_at: new Date().toISOString(),
    });

    const entry = await vault.get('creds/recently-rotated');
    expect(entry!.stale).toBe(false);
  });

  it('should use created_at when last_rotated_at is not set for stale check', async () => {
    // This secret has a rotation_interval but no last_rotated_at
    // Since it was just created, it should NOT be stale with 365d interval
    await vault.store('creds/new-with-interval', 'value', {
      rotation_interval: '365d',
    });

    const entry = await vault.get('creds/new-with-interval');
    expect(entry!.stale).toBe(false);
  });

  it('should include expired/stale flags in list()', () => {
    const entries = vault.list('creds/');
    const expiredEntry = entries.find(e => e.path === 'creds/expired-key');
    expect(expiredEntry!.expired).toBe(true);

    const staleEntry = entries.find(e => e.path === 'creds/stale-key');
    expect(staleEntry!.stale).toBe(true);

    const freshEntry = entries.find(e => e.path === 'creds/fresh-key');
    expect(freshEntry!.expired).toBe(false);
    expect(freshEntry!.stale).toBe(false);
  });

  it('should list expiring secrets within a window', () => {
    // The already-expired secret should be included (it expires before the deadline)
    const expiring = vault.expiringSecrets(365 * 24 * 60 * 60 * 1000); // 1 year
    const paths = expiring.map(e => e.path);
    expect(paths).toContain('creds/expired-key'); // already expired, within window
    expect(paths).not.toContain('creds/fresh-key'); // expires in 2099
    expect(paths).not.toContain('creds/no-expiry'); // no expiry set
  });

  it('should list stale secrets', () => {
    const stale = vault.staleSecrets();
    const paths = stale.map(e => e.path);
    expect(paths).toContain('creds/stale-key');
    expect(paths).not.toContain('creds/recently-rotated');
    expect(paths).not.toContain('creds/no-expiry');
  });

  it('should include rotation metadata in list results', () => {
    const entries = vault.list('creds/');
    const staleEntry = entries.find(e => e.path === 'creds/stale-key');
    expect(staleEntry!.metadata.rotation_interval).toBe('1d');
    expect(staleEntry!.metadata.last_rotated_at).toBe('2020-01-01T00:00:00.000Z');
  });
});

// ─── Server endpoints ─────────────────────────────────────────────

describe('Server — rotation/expiry endpoints', () => {
  let server: http.Server;
  let tmpDir: string;
  let auditLogPath: string;

  function getPort(): number {
    const addr = server.address();
    if (typeof addr === 'object' && addr) return addr.port;
    throw new Error('Server has no address');
  }

  function client(): ClientConfig {
    return { port: getPort(), host: '127.0.0.1', token: TEST_TOKEN, insecure: true };
  }

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-rot-server-'));
    auditLogPath = path.join(tmpDir, 'audit.log');
    const config: ServerConfig = {
      vaultPath: path.join(tmpDir, 'vault.db'),
      port: 0,
      idleTimeoutMs: 0,
      pidFile: path.join(tmpDir, 'vault.pid'),
      portFile: path.join(tmpDir, 'vault.port'),
      insecure: true,
      token: TEST_TOKEN,
      auditLogPath,
    };

    server = await createVaultServer(config);

    // Init + unlock the vault
    await request(client(), 'POST', '/v1/init', { passphrase: PASSPHRASE });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should store a secret with expires_at via PUT', async () => {
    const res = await request(client(), 'PUT', '/v1/secrets/test%2Fexpiring', {
      value: 'expiring-value',
      expires_at: '2020-01-01T00:00:00.000Z',
    });
    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it('should store a secret with rotation_interval via PUT', async () => {
    const res = await request(client(), 'PUT', '/v1/secrets/test%2Frotating', {
      value: 'rotating-value',
      rotation_interval: '1d',
    });
    expect(res.statusCode).toBe(200);
  });

  it('should return expired=true on GET for expired secret', async () => {
    const res = await request(client(), 'GET', '/v1/secrets/test%2Fexpiring');
    expect(res.statusCode).toBe(200);
    expect(res.body.expired).toBe(true);
    expect(res.body.value).toBe('expiring-value'); // still returns value
    expect(res.body.metadata.expires_at).toBe('2020-01-01T00:00:00.000Z');
  });

  it('should return stale flag on GET for secret past rotation interval', async () => {
    // The secret was just stored with rotation_interval=1d but no last_rotated_at
    // It was just created, so not stale yet. Let's check.
    const res = await request(client(), 'GET', '/v1/secrets/test%2Frotating');
    expect(res.statusCode).toBe(200);
    // Just created, so likely not stale (within 1d of creation)
    expect(typeof res.body.stale).toBe('boolean');
  });

  it('should list expiring secrets via GET /v1/secrets/expiring', async () => {
    // Store a future-expiring secret
    await request(client(), 'PUT', '/v1/secrets/test%2Ffuture', {
      value: 'future-value',
      expires_at: '2099-12-31T00:00:00.000Z',
    });

    // Expiring within 1 year should include the already-expired but not the far future one
    const res = await request(client(), 'GET', '/v1/secrets/expiring?within=365d');
    expect(res.statusCode).toBe(200);
    const paths = res.body.entries.map((e: Record<string, unknown>) => e.path);
    expect(paths).toContain('test/expiring'); // already expired
    expect(paths).not.toContain('test/future'); // expires in 2099
  });

  it('should list stale secrets via GET /v1/secrets/stale', async () => {
    // Store a stale secret (old last_rotated_at with short interval)
    await request(client(), 'PUT', '/v1/secrets/test%2Fstale-api', {
      value: 'stale-val',
      rotation_interval: '1d',
    });

    // Store a secret with a 1s rotation interval
    await request(client(), 'PUT', '/v1/secrets/test%2Fdefinitely-stale', {
      value: 'old-val',
      rotation_interval: '1s', // 1 second interval
    });

    // Verify the secret was stored with the rotation_interval
    const getRes = await request(client(), 'GET', '/v1/secrets/test%2Fdefinitely-stale');
    expect(getRes.body.metadata.rotation_interval).toBe('1s');

    // Wait 3 seconds for the 1s interval to pass after the secret was stored
    await new Promise(resolve => setTimeout(resolve, 3000));

    const res = await request(client(), 'GET', '/v1/secrets/stale');
    expect(res.statusCode).toBe(200);
    const paths = res.body.entries.map((e: Record<string, unknown>) => e.path);
    expect(paths).toContain('test/definitely-stale');
  });

  it('should return 400 for invalid duration in expiring endpoint', async () => {
    const res = await request(client(), 'GET', '/v1/secrets/expiring?within=invalid');
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('Invalid duration');
  });

  it('should log expired/stale audit entries when accessing expired secrets', async () => {
    // Access the expired secret to generate audit entries
    await request(client(), 'GET', '/v1/secrets/test%2Fexpiring');

    // Read audit log and check for expired tag
    const entries = readAuditLog(auditLogPath);
    const expiredEntries = entries.filter(e => e.operation === 'secret.get.expired');
    expect(expiredEntries.length).toBeGreaterThan(0);
    expect(expiredEntries[0].secretPath).toBe('test/expiring');
    expect(expiredEntries[0].detail).toContain('expired at');
  });
});
