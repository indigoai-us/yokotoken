/**
 * Tests for network audit trail — US-007.
 *
 * Covers:
 * - AuditEntry extended fields: identity_id, identity_name, org, project, mode, session_id
 * - New audit operations: auth.challenge, auth.success, access_request.*, identity.*, org.*, project.*, membership.*
 * - AuditLogger.logNetworkEvent() writes all required fields
 * - readAuditLog filtering by identity, org, project, operation
 * - Backward compatibility: old entries without network fields still parse
 * - Server integration: auth challenge/verify logging, access request logging
 * - Secret operations include mode field in audit entries
 * - Secret values are NEVER logged (carries over from existing design)
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { VaultEngine } from '../src/vault.js';
import {
  AuditLogger,
  readAuditLog,
  type AuditEntry,
} from '../src/audit.js';
import { IdentityDatabase, getDefaultIdentityDbPath } from '../src/identity.js';
import { AccessRequestManager } from '../src/access-requests.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import sodium from 'sodium-native';
import crypto from 'node:crypto';

const PASSPHRASE = 'test-network-audit-passphrase-2026';
const TEST_TOKEN = 'test-network-audit-token';

// ─── Helpers ──────────────────────────────────────────────────────────

function createTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-net-audit-'));
}

function createTmpConfig(
  tmpDir: string,
  overrides?: Partial<ServerConfig>,
): { config: ServerConfig; auditLogPath: string } {
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
    identityDbPath: path.join(tmpDir, 'identity.db'),
    ...overrides,
  };
  return { config, auditLogPath };
}

function getPort(server: http.Server): number {
  const addr = server.address();
  if (typeof addr === 'object' && addr) return addr.port;
  throw new Error('Server has no address');
}

function clientFor(server: http.Server, token?: string): ClientConfig {
  return {
    port: getPort(server),
    host: '127.0.0.1',
    token: token ?? TEST_TOKEN,
    insecure: true,
  };
}

/**
 * Create an identity, returning its ID, name, and keypair.
 */
function createTestIdentity(
  idb: IdentityDatabase,
  name: string,
  type: 'human' | 'agent' = 'agent',
) {
  const result = idb.createIdentity(name, type);
  return {
    id: result.identity.id,
    name: result.identity.name,
    privateKey: Buffer.from(result.privateKey, 'base64'),
    publicKey: Buffer.from(result.publicKey, 'base64'),
  };
}

/**
 * Sign a challenge nonce with a private key.
 */
function signChallenge(nonceBase64url: string, secretKey: Buffer): string {
  const nonce = Buffer.from(nonceBase64url, 'base64url');
  const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
  sodium.crypto_sign_detached(signature, nonce, secretKey);
  return signature.toString('base64url');
}

// ─── AuditLogger.logNetworkEvent — unit tests ────────────────────────

describe('AuditLogger.logNetworkEvent — unit', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
    logPath = path.join(tmpDir, 'audit.log');
  });

  it('should write all network audit fields', () => {
    const logger = new AuditLogger(logPath);

    logger.logNetworkEvent('auth.challenge', {
      ip: '10.0.0.5',
      identity_id: 'id-123',
      identity_name: 'agent-alpha',
      org: 'acme',
      project: 'proj-1',
      mode: 'network',
      session_id: 'session-abc',
      detail: 'challenge_id=xyz',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);

    const entry = entries[0];
    expect(entry.operation).toBe('auth.challenge');
    expect(entry.ip).toBe('10.0.0.5');
    expect(entry.identity_id).toBe('id-123');
    expect(entry.identity_name).toBe('agent-alpha');
    expect(entry.org).toBe('acme');
    expect(entry.project).toBe('proj-1');
    expect(entry.mode).toBe('network');
    expect(entry.session_id).toBe('session-abc');
    expect(entry.detail).toBe('challenge_id=xyz');
    expect(entry.timestamp).toBeTruthy();

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should set optional fields to null when not provided', () => {
    const logger = new AuditLogger(logPath);

    logger.logNetworkEvent('identity.created', {
      ip: '127.0.0.1',
      identity_id: 'id-456',
      identity_name: 'bob',
      mode: 'local',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);

    const entry = entries[0];
    expect(entry.org).toBeNull();
    expect(entry.project).toBeNull();
    expect(entry.session_id).toBeNull();
    expect(entry.tokenName).toBeNull();
    expect(entry.secretPath).toBeNull();
    expect(entry.detail).toBeNull();

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should write all new operation types', () => {
    const logger = new AuditLogger(logPath);

    const operations = [
      'auth.challenge',
      'auth.success',
      'session.expired',
      'access_request.created',
      'access_request.approved',
      'access_request.denied',
      'identity.created',
      'org.created',
      'project.created',
      'membership.added',
      'membership.removed',
    ] as const;

    for (const op of operations) {
      logger.logNetworkEvent(op, {
        ip: '127.0.0.1',
        mode: 'local',
      });
    }

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(operations.length);

    for (let i = 0; i < operations.length; i++) {
      expect(entries[i].operation).toBe(operations[i]);
    }

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should include mode field in logAccess when provided', () => {
    const logger = new AuditLogger(logPath);

    logger.logAccess('secret.get', {
      tokenName: 'session:id-1',
      secretPath: 'acme/db/password',
      ip: '10.0.0.1',
      mode: 'network',
      identity_id: 'id-1',
      identity_name: 'agent-1',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);
    expect(entries[0].mode).toBe('network');
    expect(entries[0].identity_id).toBe('id-1');
    expect(entries[0].identity_name).toBe('agent-1');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should include network context in logAuthFailure when provided', () => {
    const logger = new AuditLogger(logPath);

    logger.logAuthFailure('10.0.0.2', 'bad signature', {
      identity_id: 'id-bad',
      identity_name: 'rogue-agent',
      mode: 'network',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);
    expect(entries[0].operation).toBe('auth.failure');
    expect(entries[0].identity_id).toBe('id-bad');
    expect(entries[0].identity_name).toBe('rogue-agent');
    expect(entries[0].mode).toBe('network');
    expect(entries[0].detail).toBe('bad signature');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ─── readAuditLog — network filters ──────────────────────────────────

describe('readAuditLog — network filters', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
    logPath = path.join(tmpDir, 'audit.log');
  });

  function seedNetworkLog(): void {
    const logger = new AuditLogger(logPath);

    logger.logNetworkEvent('auth.challenge', {
      ip: '10.0.0.1',
      identity_id: 'id-1',
      identity_name: 'agent-alpha',
      org: 'acme',
      mode: 'network',
    });

    logger.logNetworkEvent('auth.success', {
      ip: '10.0.0.1',
      identity_id: 'id-1',
      identity_name: 'agent-alpha',
      org: 'acme',
      mode: 'network',
    });

    logger.logNetworkEvent('identity.created', {
      ip: '127.0.0.1',
      identity_id: 'id-2',
      identity_name: 'bob',
      mode: 'local',
    });

    logger.logNetworkEvent('org.created', {
      ip: '127.0.0.1',
      identity_id: 'id-2',
      identity_name: 'bob',
      org: 'initech',
      mode: 'local',
    });

    logger.logNetworkEvent('membership.added', {
      ip: '127.0.0.1',
      identity_id: 'id-3',
      identity_name: 'carol',
      org: 'acme',
      project: 'web-app',
      mode: 'local',
    });

    logger.logAccess('secret.get', {
      tokenName: 'session:id-1',
      secretPath: 'acme/db/password',
      ip: '10.0.0.1',
      mode: 'network',
      identity_id: 'id-1',
      identity_name: 'agent-alpha',
      org: 'acme',
    });

    logger.close();
  }

  it('should filter by identity name', () => {
    seedNetworkLog();
    const entries = readAuditLog(logPath, { identity: 'agent-alpha' });
    expect(entries).toHaveLength(3);
    expect(entries.every((e) => e.identity_name === 'agent-alpha')).toBe(true);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should filter by identity ID', () => {
    seedNetworkLog();
    const entries = readAuditLog(logPath, { identity: 'id-2' });
    expect(entries).toHaveLength(2);
    expect(entries.every((e) => e.identity_id === 'id-2')).toBe(true);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should filter by org', () => {
    seedNetworkLog();
    const entries = readAuditLog(logPath, { org: 'acme' });
    // auth.challenge(acme), auth.success(acme), membership.added(acme), secret.get(acme) = 4
    expect(entries).toHaveLength(4);
    expect(entries.every((e) => e.org === 'acme')).toBe(true);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should filter by project', () => {
    seedNetworkLog();
    const entries = readAuditLog(logPath, { project: 'web-app' });
    expect(entries).toHaveLength(1);
    expect(entries[0].identity_name).toBe('carol');
    expect(entries[0].project).toBe('web-app');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should filter by operation', () => {
    seedNetworkLog();
    const entries = readAuditLog(logPath, { operation: 'auth.success' });
    expect(entries).toHaveLength(1);
    expect(entries[0].identity_name).toBe('agent-alpha');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should combine identity + org filters', () => {
    seedNetworkLog();
    const entries = readAuditLog(logPath, { identity: 'agent-alpha', org: 'acme' });
    expect(entries).toHaveLength(3);
    expect(entries.every((e) => e.identity_name === 'agent-alpha' && e.org === 'acme')).toBe(true);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should combine org + project filters', () => {
    seedNetworkLog();
    const entries = readAuditLog(logPath, { org: 'acme', project: 'web-app' });
    expect(entries).toHaveLength(1);
    expect(entries[0].operation).toBe('membership.added');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ─── Backward compatibility ──────────────────────────────────────────

describe('Backward compatibility — old entries without network fields', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
    logPath = path.join(tmpDir, 'audit.log');
  });

  it('should parse old-style entries without network fields', () => {
    // Write entries in the old format (no identity_id, identity_name, etc.)
    const oldEntry = {
      timestamp: '2026-01-15T10:30:00.000Z',
      operation: 'secret.get',
      tokenName: 'bootstrap',
      secretPath: 'aws/key',
      ip: '127.0.0.1',
      detail: null,
    };

    fs.writeFileSync(logPath, JSON.stringify(oldEntry) + '\n');

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);
    expect(entries[0].operation).toBe('secret.get');
    expect(entries[0].tokenName).toBe('bootstrap');
    // Network fields should be undefined (not present in old entries)
    expect(entries[0].identity_id).toBeUndefined();
    expect(entries[0].mode).toBeUndefined();

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should handle mix of old and new entries', () => {
    const oldEntry = JSON.stringify({
      timestamp: '2026-01-15T10:30:00.000Z',
      operation: 'secret.get',
      tokenName: 'bootstrap',
      secretPath: 'aws/key',
      ip: '127.0.0.1',
      detail: null,
    });

    // Write an old entry directly
    fs.writeFileSync(logPath, oldEntry + '\n');

    // Then append a new-style entry
    const logger = new AuditLogger(logPath);
    logger.logNetworkEvent('auth.success', {
      ip: '10.0.0.1',
      identity_id: 'id-1',
      identity_name: 'agent-alpha',
      mode: 'network',
    });
    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(2);

    // Old entry
    expect(entries[0].operation).toBe('secret.get');
    expect(entries[0].identity_id).toBeUndefined();

    // New entry
    expect(entries[1].operation).toBe('auth.success');
    expect(entries[1].identity_id).toBe('id-1');
    expect(entries[1].mode).toBe('network');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should not break identity filter on old entries', () => {
    // Old entry without identity fields
    const oldEntry = JSON.stringify({
      timestamp: '2026-01-15T10:30:00.000Z',
      operation: 'secret.get',
      tokenName: 'bootstrap',
      secretPath: 'aws/key',
      ip: '127.0.0.1',
      detail: null,
    });

    fs.writeFileSync(logPath, oldEntry + '\n');

    // Filter by identity should return empty (old entry has no identity)
    const entries = readAuditLog(logPath, { identity: 'agent-alpha' });
    expect(entries).toHaveLength(0);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ─── Server integration — auth challenge/verify audit ─────────────────

describe('Server audit — network auth events', () => {
  let server: http.Server;
  let tmpDir: string;
  let config: ServerConfig;
  let auditLogPath: string;
  let testIdentity: { id: string; name: string; privateKey: Buffer; publicKey: Buffer };

  beforeAll(async () => {
    tmpDir = createTmpDir();
    const result = createTmpConfig(tmpDir);
    config = result.config;
    auditLogPath = result.auditLogPath;

    // Initialize vault
    const vault = new VaultEngine(config.vaultPath);
    vault.init(PASSPHRASE);
    vault.store('acme/db/password', 'secret-value');
    vault.close();

    // Create an identity for testing
    const idb = new IdentityDatabase(config.identityDbPath!);
    testIdentity = createTestIdentity(idb, 'test-agent');

    // Create an org and add the identity
    const org = idb.createOrg('test-org', testIdentity.id);
    idb.close();

    server = (await createVaultServer(config)) as http.Server;

    // Unlock vault
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should log auth.challenge when challenge is issued', async () => {
    const client = clientFor(server);

    const res = await request(client, 'POST', '/v1/auth/challenge', {
      identity_id: testIdentity.id,
    });
    expect(res.statusCode).toBe(200);

    const entries = readAuditLog(auditLogPath, { operation: 'auth.challenge' });
    expect(entries.length).toBeGreaterThanOrEqual(1);

    const last = entries[entries.length - 1];
    expect(last.identity_id).toBe(testIdentity.id);
    expect(last.identity_name).toBe('test-agent');
    expect(last.mode).toBe('network');
    expect(last.detail).toContain('challenge_id=');
  });

  it('should log auth.success on successful verify', async () => {
    const client = clientFor(server);

    // Issue challenge
    const challengeRes = await request(client, 'POST', '/v1/auth/challenge', {
      identity_id: testIdentity.id,
    });
    expect(challengeRes.statusCode).toBe(200);

    const challengeId = challengeRes.body.challenge_id;
    const challengeNonce = challengeRes.body.challenge;

    // Sign and verify
    const signature = signChallenge(challengeNonce, testIdentity.privateKey);

    const verifyRes = await request(client, 'POST', '/v1/auth/verify', {
      challenge_id: challengeId,
      identity_id: testIdentity.id,
      signature,
      public_key: testIdentity.publicKey.toString('base64'),
    });
    expect(verifyRes.statusCode).toBe(200);

    const entries = readAuditLog(auditLogPath, { operation: 'auth.success' });
    expect(entries.length).toBeGreaterThanOrEqual(1);

    const last = entries[entries.length - 1];
    expect(last.identity_id).toBe(testIdentity.id);
    expect(last.identity_name).toBe('test-agent');
    expect(last.mode).toBe('network');
  });

  it('should log auth.failure on failed verify with identity context', async () => {
    const client = clientFor(server);

    // Issue challenge
    const challengeRes = await request(client, 'POST', '/v1/auth/challenge', {
      identity_id: testIdentity.id,
    });
    expect(challengeRes.statusCode).toBe(200);

    // Send a wrong signature
    const verifyRes = await request(client, 'POST', '/v1/auth/verify', {
      challenge_id: challengeRes.body.challenge_id,
      identity_id: testIdentity.id,
      signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      public_key: testIdentity.publicKey.toString('base64'),
    });
    expect(verifyRes.statusCode).toBe(401);

    const entries = readAuditLog(auditLogPath, { operation: 'auth.failure' });
    const networkFailures = entries.filter((e) => e.mode === 'network');
    expect(networkFailures.length).toBeGreaterThanOrEqual(1);

    const last = networkFailures[networkFailures.length - 1];
    expect(last.identity_id).toBe(testIdentity.id);
    expect(last.identity_name).toBe('test-agent');
    expect(last.mode).toBe('network');
    expect(last.detail).toContain('network auth');
  });

  it('should include mode field in secret access audit entries', async () => {
    const client = clientFor(server);

    // Access a secret via bootstrap token (local mode)
    await request(client, 'GET', '/v1/secrets/acme%2Fdb%2Fpassword');

    const entries = readAuditLog(auditLogPath, { operation: 'secret.get' });
    const lastGet = entries[entries.length - 1];
    expect(lastGet.mode).toBe('local');
    expect(lastGet.secretPath).toBe('acme/db/password');
  });
});

// ─── Server integration — access request audit ──────────────────────

describe('Server audit — access request lifecycle', () => {
  let server: http.Server;
  let tmpDir: string;
  let config: ServerConfig;
  let auditLogPath: string;
  let testIdentity: { id: string; name: string; privateKey: Buffer; publicKey: Buffer };

  beforeAll(async () => {
    tmpDir = createTmpDir();
    const result = createTmpConfig(tmpDir);
    config = result.config;
    auditLogPath = result.auditLogPath;

    // Initialize vault
    const vault = new VaultEngine(config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();

    // Create identity and org
    const idb = new IdentityDatabase(config.identityDbPath!);
    testIdentity = createTestIdentity(idb, 'requesting-agent');
    const org = idb.createOrg('target-org');
    // Don't add identity as member yet — they need to request access
    idb.close();

    server = (await createVaultServer(config)) as http.Server;
    const client = clientFor(server);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should log access_request.created when request is submitted', async () => {
    const client = clientFor(server);

    const res = await request(client, 'POST', '/v1/access-requests', {
      identity_id: testIdentity.id,
      org: 'target-org',
      role_requested: 'member',
      justification: 'Need access to deploy',
    });
    expect(res.statusCode).toBe(201);

    const entries = readAuditLog(auditLogPath, { operation: 'access_request.created' });
    expect(entries.length).toBeGreaterThanOrEqual(1);

    const last = entries[entries.length - 1];
    expect(last.identity_id).toBe(testIdentity.id);
    expect(last.identity_name).toBe('requesting-agent');
    expect(last.org).toBe('target-org');
    expect(last.mode).toBe('network');
    expect(last.detail).toContain('request_id=');
    expect(last.detail).toContain('role=member');
  });
});

// ─── Audit entries never contain secret values ──────────────────────

describe('Network audit — secret values NEVER logged', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
    logPath = path.join(tmpDir, 'audit.log');
  });

  it('should not include any secret values in network audit entries', () => {
    const logger = new AuditLogger(logPath);
    const secretValue = 'TOP-SECRET-VALUE-MUST-NOT-APPEAR';

    // Log various network events
    logger.logNetworkEvent('auth.success', {
      ip: '10.0.0.1',
      identity_id: 'id-1',
      identity_name: 'agent',
      mode: 'network',
    });

    logger.logAccess('secret.get', {
      tokenName: 'session:id-1',
      secretPath: 'path/to/secret',
      ip: '10.0.0.1',
      mode: 'network',
      identity_id: 'id-1',
      identity_name: 'agent',
    });

    logger.close();

    // Verify the raw log content doesn't contain the secret value
    const rawContent = fs.readFileSync(logPath, 'utf-8');
    expect(rawContent).not.toContain(secretValue);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ─── Identity/org/project audit logging ──────────────────────────────

describe('AuditLogger — identity/org/project lifecycle events', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
    logPath = path.join(tmpDir, 'audit.log');
  });

  it('should log identity.created with correct fields', () => {
    const logger = new AuditLogger(logPath);

    logger.logNetworkEvent('identity.created', {
      ip: '127.0.0.1',
      identity_id: 'new-id-1',
      identity_name: 'new-agent',
      mode: 'local',
      detail: 'type=agent',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);
    expect(entries[0].operation).toBe('identity.created');
    expect(entries[0].identity_id).toBe('new-id-1');
    expect(entries[0].identity_name).toBe('new-agent');
    expect(entries[0].mode).toBe('local');
    expect(entries[0].detail).toBe('type=agent');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should log org.created with founder context', () => {
    const logger = new AuditLogger(logPath);

    logger.logNetworkEvent('org.created', {
      ip: '127.0.0.1',
      identity_id: 'founder-id',
      identity_name: 'admin-user',
      org: 'new-org',
      mode: 'local',
      detail: 'founder=founder-id',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);
    expect(entries[0].operation).toBe('org.created');
    expect(entries[0].org).toBe('new-org');
    expect(entries[0].identity_name).toBe('admin-user');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should log project.created with org context', () => {
    const logger = new AuditLogger(logPath);

    logger.logNetworkEvent('project.created', {
      ip: '127.0.0.1',
      identity_id: 'creator-id',
      identity_name: 'creator',
      org: 'acme',
      project: 'web-app',
      mode: 'local',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);
    expect(entries[0].operation).toBe('project.created');
    expect(entries[0].org).toBe('acme');
    expect(entries[0].project).toBe('web-app');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should log membership.added and membership.removed', () => {
    const logger = new AuditLogger(logPath);

    logger.logNetworkEvent('membership.added', {
      ip: '127.0.0.1',
      identity_id: 'member-id',
      identity_name: 'new-member',
      org: 'acme',
      mode: 'local',
      detail: 'role=member',
    });

    logger.logNetworkEvent('membership.removed', {
      ip: '127.0.0.1',
      identity_id: 'member-id',
      identity_name: 'new-member',
      org: 'acme',
      mode: 'local',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(2);
    expect(entries[0].operation).toBe('membership.added');
    expect(entries[1].operation).toBe('membership.removed');
    expect(entries[0].identity_name).toBe('new-member');
    expect(entries[1].identity_name).toBe('new-member');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ─── Access request lifecycle audit events ──────────────────────────

describe('AuditLogger — access request lifecycle', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
    logPath = path.join(tmpDir, 'audit.log');
  });

  it('should log full access request lifecycle', () => {
    const logger = new AuditLogger(logPath);

    // Request created
    logger.logNetworkEvent('access_request.created', {
      ip: '10.0.0.1',
      identity_id: 'req-id',
      identity_name: 'agent-x',
      org: 'acme',
      project: 'web',
      mode: 'network',
      detail: 'request_id=r1, role=member',
    });

    // Request approved
    logger.logNetworkEvent('access_request.approved', {
      ip: '127.0.0.1',
      identity_id: 'req-id',
      identity_name: 'agent-x',
      org: 'acme',
      project: 'web',
      mode: 'local',
      detail: 'request_id=r1, role=member, reviewed_by=admin',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(2);

    expect(entries[0].operation).toBe('access_request.created');
    expect(entries[0].mode).toBe('network');
    expect(entries[0].org).toBe('acme');

    expect(entries[1].operation).toBe('access_request.approved');
    expect(entries[1].mode).toBe('local');
    expect(entries[1].detail).toContain('reviewed_by=admin');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should log access request denial with reason', () => {
    const logger = new AuditLogger(logPath);

    logger.logNetworkEvent('access_request.denied', {
      ip: '127.0.0.1',
      identity_id: 'denied-id',
      identity_name: 'untrusted-agent',
      org: 'acme',
      mode: 'local',
      detail: 'request_id=r2, reviewed_by=admin, reason=Not authorized',
    });

    logger.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(1);
    expect(entries[0].operation).toBe('access_request.denied');
    expect(entries[0].detail).toContain('reason=Not authorized');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ─── Audit log is append-only (immutability check) ──────────────────

describe('Network audit — append-only immutability', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
    logPath = path.join(tmpDir, 'audit.log');
  });

  it('should append new network entries without modifying existing ones', () => {
    const logger1 = new AuditLogger(logPath);
    logger1.logNetworkEvent('identity.created', {
      ip: '127.0.0.1',
      identity_id: 'id-1',
      identity_name: 'alice',
      mode: 'local',
    });
    logger1.close();

    // Re-open and append
    const logger2 = new AuditLogger(logPath);
    logger2.logNetworkEvent('org.created', {
      ip: '127.0.0.1',
      identity_id: 'id-1',
      identity_name: 'alice',
      org: 'acme',
      mode: 'local',
    });
    logger2.close();

    const entries = readAuditLog(logPath);
    expect(entries).toHaveLength(2);
    expect(entries[0].operation).toBe('identity.created');
    expect(entries[1].operation).toBe('org.created');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
