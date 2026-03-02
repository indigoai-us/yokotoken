/**
 * Tests for network server mode — US-005 (hq-vault-network).
 *
 * Covers:
 * - Network mode binds to 0.0.0.0 (or configurable --bind address)
 * - Network mode REQUIRES TLS — refuses to start with --insecure
 * - Network mode REQUIRES at least one identity
 * - Bootstrap token is DISABLED in network mode
 * - Identity-based session auth works in network mode
 * - Health endpoint: GET /v1/health (no auth, no information leakage)
 * - Status endpoint includes mode field
 * - Custom TLS cert/key paths
 * - Bind address configuration
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import https from 'node:https';

import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { IdentityDatabase } from '../src/identity.js';
import { VaultEngine } from '../src/vault.js';
import { ed25519Sign } from '../src/network-auth.js';
import { generateSelfSignedCert } from '../src/tls.js';

// ─── Constants ──────────────────────────────────────────────────────

const TEST_TOKEN = 'test-network-server-token';
const PASSPHRASE = 'test-network-passphrase-2026';

// ─── Helpers ────────────────────────────────────────────────────────

/** Generate an Ed25519 keypair. */
async function generateKeypair(): Promise<{ publicKey: Buffer; secretKey: Buffer }> {
  await sodium.ready;
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: Buffer.from(kp.publicKey), secretKey: Buffer.from(kp.privateKey) };
}

/** Create a temp directory for test artifacts. */
function createTmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `hq-vault-${prefix}-`));
}

/** Create a test identity database with one identity. */
async function createIdentityDb(tmpDir: string): Promise<{
  identityDbPath: string;
  identityDb: IdentityDatabase;
  identityId: string;
  publicKey: Buffer;
  secretKey: Buffer;
}> {
  const identityDbPath = path.join(tmpDir, 'identity.db');
  const identityDb = await IdentityDatabase.open(identityDbPath);

  // Create a keypair and identity manually (so we have the secret key for signing)
  const { publicKey, secretKey } = await generateKeypair();
  const publicKeyHash = crypto.createHash('sha256').update(publicKey).digest('hex');

  // Insert identity directly (createIdentity generates its own keypair internally)
  // We need to use the raw DB to insert our custom keypair
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const db = (identityDb as any).db;
  const id = crypto.randomBytes(16).toString('hex');
  db.run(
    'INSERT INTO identities (id, name, type, public_key_hash) VALUES (?, ?, ?, ?)',
    [id, 'test-agent', 'agent', publicKeyHash],
  );
  identityDb.persist();

  return { identityDbPath, identityDb, identityId: id, publicKey, secretKey };
}

/** Create a base server config (insecure, local mode). */
function createLocalConfig(tmpDir: string, overrides?: Partial<ServerConfig>): ServerConfig {
  return {
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
}

/** Get the actual port from a running server. */
function getPort(server: http.Server | https.Server): number {
  const addr = server.address();
  if (typeof addr === 'object' && addr) {
    return addr.port;
  }
  throw new Error('Server has no address');
}

/** Perform a challenge-response auth flow and return a session token. */
async function authenticateWithIdentity(
  client: ClientConfig,
  identityId: string,
  publicKey: Buffer,
  secretKey: Buffer,
): Promise<string> {
  // Step 1: Get a challenge
  const challengeRes = await request(
    { ...client, token: undefined },
    'POST',
    '/v1/auth/challenge',
    { identity_id: identityId },
  );
  if (challengeRes.statusCode !== 200) {
    throw new Error(`Challenge request failed: ${JSON.stringify(challengeRes.body)}`);
  }

  const challengeId = challengeRes.body.challenge_id as string;
  const challengeNonce = Buffer.from(challengeRes.body.challenge as string, 'base64url');

  // Step 2: Sign the challenge
  const signature = await ed25519Sign(challengeNonce, secretKey);

  // Step 3: Verify the challenge
  const verifyRes = await request(
    { ...client, token: undefined },
    'POST',
    '/v1/auth/verify',
    {
      challenge_id: challengeId,
      identity_id: identityId,
      signature: signature.toString('base64url'),
      public_key: publicKey.toString('base64'),
    },
  );
  if (verifyRes.statusCode !== 200) {
    throw new Error(`Verify request failed: ${JSON.stringify(verifyRes.body)}`);
  }

  return verifyRes.body.session_token as string;
}

// ─── Network mode validation tests ────────────────────────────────

describe('Network mode — startup validation', () => {
  it('should refuse to start in network mode with --insecure', async () => {
    const tmpDir = createTmpDir('net-insecure');
    const { identityDbPath, identityDb } = await createIdentityDb(tmpDir);

    try {
      const config = createLocalConfig(tmpDir, {
        network: true,
        insecure: true,
        identityDbPath,
      });
      await expect(createVaultServer(config)).rejects.toThrow('Network mode requires TLS');
    } finally {
      identityDb.close();
    }
  });

  it('should refuse to start in network mode without identity database', async () => {
    const tmpDir = createTmpDir('net-no-iddb');

    // Generate self-signed certs for TLS
    const certData = generateSelfSignedCert();

    const config: ServerConfig = {
      vaultPath: path.join(tmpDir, 'vault.db'),
      port: 0,
      idleTimeoutMs: 0,
      pidFile: path.join(tmpDir, 'vault.pid'),
      portFile: path.join(tmpDir, 'vault.port'),
      tokenFile: path.join(tmpDir, 'token'),
      token: TEST_TOKEN,
      network: true,
      tlsCertData: certData,
      // Point to a non-existent identity DB path
      identityDbPath: path.join(tmpDir, 'nonexistent', 'identity.db'),
    };

    await expect(createVaultServer(config)).rejects.toThrow('Network mode requires an identity database');
  });

  it('should refuse to start in network mode with empty identity database', async () => {
    const tmpDir = createTmpDir('net-empty-iddb');
    const identityDbPath = path.join(tmpDir, 'identity.db');
    const identityDb = await IdentityDatabase.open(identityDbPath);

    const certData = generateSelfSignedCert();

    const config: ServerConfig = {
      vaultPath: path.join(tmpDir, 'vault.db'),
      port: 0,
      idleTimeoutMs: 0,
      pidFile: path.join(tmpDir, 'vault.pid'),
      portFile: path.join(tmpDir, 'vault.port'),
      tokenFile: path.join(tmpDir, 'token'),
      token: TEST_TOKEN,
      network: true,
      tlsCertData: certData,
      identityDbPath,
    };

    try {
      await expect(createVaultServer(config)).rejects.toThrow('Network mode requires at least one identity');
    } finally {
      identityDb.close();
    }
  });
});

// ─── Health endpoint tests ────────────────────────────────────────

describe('Health endpoint — GET /v1/health', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = createTmpDir('health');
    const config = createLocalConfig(tmpDir);
    server = (await createVaultServer(config)) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should return health status without auth in local mode', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      insecure: true,
      // No token — health endpoint should not require auth
    };

    const res = await request(client, 'GET', '/v1/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.version).toBe('0.1.0');
    expect(res.body.mode).toBe('local');
  });

  it('should not leak sensitive information', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      insecure: true,
    };

    const res = await request(client, 'GET', '/v1/health');
    expect(res.statusCode).toBe(200);

    // Should ONLY contain status, version, mode
    const keys = Object.keys(res.body);
    expect(keys).toEqual(expect.arrayContaining(['status', 'version', 'mode']));
    expect(keys.length).toBe(3);

    // Should NOT contain vault state, secrets, tokens, etc.
    expect(res.body).not.toHaveProperty('initialized');
    expect(res.body).not.toHaveProperty('unlocked');
    expect(res.body).not.toHaveProperty('token');
    expect(res.body).not.toHaveProperty('port');
  });
});

// ─── Network mode server tests ────────────────────────────────────

describe('Network mode — server behavior', () => {
  let server: https.Server;
  let tmpDir: string;
  let identityId: string;
  let publicKey: Buffer;
  let secretKey: Buffer;
  let identityDb: IdentityDatabase;

  beforeAll(async () => {
    tmpDir = createTmpDir('net-server');
    const idSetup = await createIdentityDb(tmpDir);
    identityId = idSetup.identityId;
    publicKey = idSetup.publicKey;
    secretKey = idSetup.secretKey;
    identityDb = idSetup.identityDb;

    // Generate TLS cert data for the server
    const certData = generateSelfSignedCert();

    const config: ServerConfig = {
      vaultPath: path.join(tmpDir, 'vault.db'),
      port: 0,
      idleTimeoutMs: 0,
      pidFile: path.join(tmpDir, 'vault.pid'),
      portFile: path.join(tmpDir, 'vault.port'),
      tokenFile: path.join(tmpDir, 'token'),
      token: TEST_TOKEN,
      network: true,
      tlsCertData: certData,
      identityDbPath: idSetup.identityDbPath,
    };

    server = (await createVaultServer(config)) as https.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { identityDb.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should bind successfully in network mode with TLS', () => {
    const addr = server.address();
    expect(addr).toBeTruthy();
    expect(typeof addr === 'object' && addr !== null).toBe(true);
    if (typeof addr === 'object' && addr) {
      // Should bind to 0.0.0.0 in network mode
      expect(addr.address).toBe('0.0.0.0');
      expect(addr.port).toBeGreaterThan(0);
    }
  });

  it('should return network mode in health endpoint', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      rejectUnauthorized: false,
      // No token — health endpoint doesn't require auth
    };

    const res = await request(client, 'GET', '/v1/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.mode).toBe('network');
  });

  it('should REJECT bootstrap token in network mode', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      token: TEST_TOKEN,
      rejectUnauthorized: false,
    };

    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('should ACCEPT session token from identity auth in network mode', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      rejectUnauthorized: false,
    };

    // Authenticate with identity to get a session token
    const sessionToken = await authenticateWithIdentity(
      client,
      identityId,
      publicKey,
      secretKey,
    );

    expect(sessionToken).toBeTruthy();

    // Use the session token to access a protected endpoint
    const authClient: ClientConfig = {
      ...client,
      token: sessionToken,
    };

    const res = await request(authClient, 'GET', '/v1/status');
    expect(res.statusCode).toBe(200);
    expect(res.body.serverRunning).toBe(true);
    expect(res.body.mode).toBe('network');
  });

  it('should include mode field in status response', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      rejectUnauthorized: false,
    };

    const sessionToken = await authenticateWithIdentity(
      client,
      identityId,
      publicKey,
      secretKey,
    );

    const authClient: ClientConfig = {
      ...client,
      token: sessionToken,
    };

    const res = await request(authClient, 'GET', '/v1/status');
    expect(res.statusCode).toBe(200);
    expect(res.body.mode).toBe('network');
  });

  it('should reject unauthenticated requests to protected endpoints', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      rejectUnauthorized: false,
      // No token at all
    };

    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);
  });
});

// ─── Local mode backward compatibility ─────────────────────────────

describe('Local mode — backward compatibility', () => {
  let server: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = createTmpDir('local-compat');
    const config = createLocalConfig(tmpDir);
    server = (await createVaultServer(config)) as http.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should bind to 127.0.0.1 in local mode', () => {
    const addr = server.address();
    expect(addr).toBeTruthy();
    if (typeof addr === 'object' && addr) {
      expect(addr.address).toBe('127.0.0.1');
    }
  });

  it('should accept bootstrap token in local mode', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      token: TEST_TOKEN,
      insecure: true,
    };

    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(200);
    expect(res.body.mode).toBe('local');
  });

  it('should show local mode in health endpoint', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      insecure: true,
    };

    const res = await request(client, 'GET', '/v1/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.mode).toBe('local');
  });
});

// ─── Custom bind address ──────────────────────────────────────────

describe('Custom bind address', () => {
  let server: http.Server | https.Server | null = null;
  let tmpDir: string;
  let identityDb: IdentityDatabase | null = null;

  afterAll(() => {
    try { if (server) server.close(); } catch { /* ok */ }
    try { if (identityDb) identityDb.close(); } catch { /* ok */ }
    // Don't rmSync here — Windows file locks may persist. Let OS handle temp cleanup.
  });

  it('should bind to custom address in local mode', async () => {
    tmpDir = createTmpDir('bind-local');
    const config = createLocalConfig(tmpDir, {
      bindAddress: '127.0.0.1',
    });
    server = (await createVaultServer(config)) as http.Server;

    const addr = server.address();
    expect(addr).toBeTruthy();
    if (typeof addr === 'object' && addr) {
      expect(addr.address).toBe('127.0.0.1');
    }
  });

  it('should use custom bind address in network mode', async () => {
    // Close previous server if any
    try { if (server) server.close(); server = null; } catch { /* ok */ }

    tmpDir = createTmpDir('bind-net');
    const idSetup = await createIdentityDb(tmpDir);
    identityDb = idSetup.identityDb;

    const certData = generateSelfSignedCert();
    const config: ServerConfig = {
      vaultPath: path.join(tmpDir, 'vault.db'),
      port: 0,
      idleTimeoutMs: 0,
      pidFile: path.join(tmpDir, 'vault.pid'),
      portFile: path.join(tmpDir, 'vault.port'),
      tokenFile: path.join(tmpDir, 'token'),
      token: TEST_TOKEN,
      network: true,
      bindAddress: '127.0.0.1', // Override the default 0.0.0.0 for network
      tlsCertData: certData,
      identityDbPath: idSetup.identityDbPath,
    };

    server = (await createVaultServer(config)) as https.Server;
    const addr = server.address();
    expect(addr).toBeTruthy();
    if (typeof addr === 'object' && addr) {
      expect(addr.address).toBe('127.0.0.1');
    }
  });
});

// ─── Custom TLS cert/key ──────────────────────────────────────────

describe('Custom TLS certificate paths', () => {
  let server: https.Server | null = null;
  let identityDb: IdentityDatabase | null = null;

  afterAll(() => {
    try { if (server) server.close(); } catch { /* ok */ }
    try { if (identityDb) identityDb.close(); } catch { /* ok */ }
  });

  it('should use custom cert/key files when provided', async () => {
    const tmpDir = createTmpDir('custom-tls');
    const idSetup = await createIdentityDb(tmpDir);
    identityDb = idSetup.identityDb;

    // Generate and write cert/key to files
    const certData = generateSelfSignedCert();
    const certFile = path.join(tmpDir, 'custom.crt');
    const keyFile = path.join(tmpDir, 'custom.key');
    fs.writeFileSync(certFile, certData.cert, 'utf-8');
    fs.writeFileSync(keyFile, certData.key, 'utf-8');

    const config: ServerConfig = {
      vaultPath: path.join(tmpDir, 'vault.db'),
      port: 0,
      idleTimeoutMs: 0,
      pidFile: path.join(tmpDir, 'vault.pid'),
      portFile: path.join(tmpDir, 'vault.port'),
      tokenFile: path.join(tmpDir, 'token'),
      token: TEST_TOKEN,
      network: true,
      tlsCertFile: certFile,
      tlsKeyFile: keyFile,
      identityDbPath: idSetup.identityDbPath,
    };

    server = (await createVaultServer(config)) as https.Server;
    const port = getPort(server);
    expect(port).toBeGreaterThan(0);

    // Verify the server works with the custom certs
    const client: ClientConfig = {
      port,
      host: '127.0.0.1',
      rejectUnauthorized: false,
    };

    const res = await request(client, 'GET', '/v1/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.mode).toBe('network');
  });
});

// ─── Network mode with vault operations ───────────────────────────

describe('Network mode — vault operations with session auth', () => {
  let server: https.Server;
  let tmpDir: string;
  let identityId: string;
  let publicKey: Buffer;
  let secretKey: Buffer;
  let identityDb: IdentityDatabase;

  beforeAll(async () => {
    tmpDir = createTmpDir('net-ops');
    const idSetup = await createIdentityDb(tmpDir);
    identityId = idSetup.identityId;
    publicKey = idSetup.publicKey;
    secretKey = idSetup.secretKey;
    identityDb = idSetup.identityDb;

    const certData = generateSelfSignedCert();

    const config: ServerConfig = {
      vaultPath: path.join(tmpDir, 'vault.db'),
      port: 0,
      idleTimeoutMs: 0,
      pidFile: path.join(tmpDir, 'vault.pid'),
      portFile: path.join(tmpDir, 'vault.port'),
      tokenFile: path.join(tmpDir, 'token'),
      token: TEST_TOKEN,
      network: true,
      tlsCertData: certData,
      identityDbPath: idSetup.identityDbPath,
    };

    server = (await createVaultServer(config)) as https.Server;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { identityDb.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should allow init and unlock with session token', async () => {
    const baseClient: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      rejectUnauthorized: false,
    };

    // Get session token
    const sessionToken = await authenticateWithIdentity(
      baseClient,
      identityId,
      publicKey,
      secretKey,
    );

    const client: ClientConfig = {
      ...baseClient,
      token: sessionToken,
    };

    // Init vault
    const initRes = await request(client, 'POST', '/v1/init', {
      passphrase: PASSPHRASE,
    });
    expect(initRes.statusCode).toBe(200);
    expect(initRes.body.ok).toBe(true);

    // Status should show unlocked (locked: false)
    const statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.statusCode).toBe(200);
    expect(statusRes.body.locked).toBe(false);
    expect(statusRes.body.mode).toBe('network');

    // Lock
    const lockRes = await request(client, 'POST', '/v1/lock');
    expect(lockRes.statusCode).toBe(200);

    // Unlock
    const unlockRes = await request(client, 'POST', '/v1/unlock', {
      passphrase: PASSPHRASE,
    });
    expect(unlockRes.statusCode).toBe(200);
  });

  it('should reject bootstrap token for all operations in network mode', async () => {
    const client: ClientConfig = {
      port: getPort(server),
      host: '127.0.0.1',
      token: TEST_TOKEN,
      rejectUnauthorized: false,
    };

    // All these should return 401
    const statusRes = await request(client, 'GET', '/v1/status');
    expect(statusRes.statusCode).toBe(401);

    const listRes = await request(client, 'GET', '/v1/tokens');
    expect(listRes.statusCode).toBe(401);
  });
});
