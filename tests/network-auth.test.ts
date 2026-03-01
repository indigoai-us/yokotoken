/**
 * Tests for network authentication — US-003.
 *
 * Covers:
 * - ChallengeStore: issue, consume, single-use, expiry, cleanup
 * - SessionStore: create, validate, expire, revoke
 * - Ed25519 sign/verify: successful signing, wrong key rejection
 * - NetworkAuthenticator: full challenge-response flow
 * - Server endpoints: POST /v1/auth/challenge, POST /v1/auth/verify
 * - Session token used as Bearer token for subsequent requests
 * - Replay rejection: signed challenge cannot be reused
 * - Expired challenge rejection
 * - Rate limiting on failed verifications
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import sodium from 'sodium-native';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';

import {
  ChallengeStore,
  SessionStore,
  NetworkAuthenticator,
  ed25519Sign,
  ed25519Verify,
} from '../src/network-auth.js';
import { IdentityDatabase, getDefaultIdentityDbPath } from '../src/identity.js';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';

// ─── Helpers ────────────────────────────────────────────────────────

const TEST_TOKEN = 'test-network-auth-token';

/** Generate an Ed25519 keypair. */
function generateKeypair(): { publicKey: Buffer; secretKey: Buffer } {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_keypair(publicKey, secretKey);
  return { publicKey, secretKey };
}

/** Hash a public key (SHA-256 hex) — same as IdentityDatabase does. */
function hashPublicKey(publicKey: Buffer): string {
  return crypto.createHash('sha256').update(publicKey).digest('hex');
}

/** Create a temp dir with an identity database pre-populated. */
function createTestSetup(): {
  tmpDir: string;
  identityDb: IdentityDatabase;
  identityDbPath: string;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-netauth-'));
  const identityDbPath = path.join(tmpDir, 'identity.db');
  const identityDb = new IdentityDatabase(identityDbPath);
  return { tmpDir, identityDb, identityDbPath };
}

/** Create server config for testing. */
function createTmpConfig(
  identityDbPath: string,
  overrides?: Partial<ServerConfig>,
): { tmpDir: string; config: ServerConfig } {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-netauth-srv-'));
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

// ─── ChallengeStore ──────────────────────────────────────────────────

describe('ChallengeStore', () => {
  it('should issue a challenge with expected fields', () => {
    const store = new ChallengeStore(60_000);
    try {
      const result = store.issue('test-id');
      expect(result.challenge_id).toBeTruthy();
      expect(result.challenge).toBeTruthy();
      expect(result.expires_in).toBe(60);

      // Decode the challenge nonce
      const nonce = Buffer.from(result.challenge, 'base64url');
      expect(nonce.length).toBe(32);
    } finally {
      store.close();
    }
  });

  it('should consume a valid challenge', () => {
    const store = new ChallengeStore(60_000);
    try {
      const issued = store.issue('test-id');
      const { challenge, error } = store.consume(issued.challenge_id, 'test-id');
      expect(challenge).not.toBeNull();
      expect(error).toBeUndefined();
      expect(challenge!.identity_id).toBe('test-id');
      expect(challenge!.used).toBe(true);
    } finally {
      store.close();
    }
  });

  it('should reject replay (second consumption)', () => {
    const store = new ChallengeStore(60_000);
    try {
      const issued = store.issue('test-id');
      store.consume(issued.challenge_id, 'test-id');
      const { challenge, error } = store.consume(issued.challenge_id, 'test-id');
      expect(challenge).toBeNull();
      expect(error).toBe('Challenge already used');
    } finally {
      store.close();
    }
  });

  it('should reject expired challenges', async () => {
    const store = new ChallengeStore(50); // 50ms TTL
    try {
      const issued = store.issue('test-id');
      // Wait for expiry
      await new Promise((r) => setTimeout(r, 100));
      const { challenge, error } = store.consume(issued.challenge_id, 'test-id');
      expect(challenge).toBeNull();
      expect(error).toBe('Challenge expired');
    } finally {
      store.close();
    }
  });

  it('should reject identity mismatch', () => {
    const store = new ChallengeStore(60_000);
    try {
      const issued = store.issue('identity-a');
      const { challenge, error } = store.consume(issued.challenge_id, 'identity-b');
      expect(challenge).toBeNull();
      expect(error).toBe('Identity mismatch');
    } finally {
      store.close();
    }
  });

  it('should reject non-existent challenge', () => {
    const store = new ChallengeStore(60_000);
    try {
      const { challenge, error } = store.consume('nonexistent-id', 'test-id');
      expect(challenge).toBeNull();
      expect(error).toBe('Challenge not found');
    } finally {
      store.close();
    }
  });

  it('should track active challenge count', () => {
    const store = new ChallengeStore(60_000);
    try {
      expect(store.size).toBe(0);
      store.issue('id-1');
      store.issue('id-2');
      expect(store.size).toBe(2);
    } finally {
      store.close();
    }
  });

  it('should clean up expired/used challenges', async () => {
    const store = new ChallengeStore(50); // 50ms TTL
    try {
      store.issue('id-1');
      const c2 = store.issue('id-2');
      store.consume(c2.challenge_id, 'id-2'); // Use one

      await new Promise((r) => setTimeout(r, 100));
      store.cleanup();
      expect(store.size).toBe(0);
    } finally {
      store.close();
    }
  });
});

// ─── SessionStore ───────────────────────────────────────────────────

describe('SessionStore', () => {
  it('should create a session with expected fields', () => {
    const store = new SessionStore(3600_000);
    try {
      const session = store.create('id-1', { org1: 'admin' }, { proj1: 'member' });
      expect(session.token).toBeTruthy();
      expect(session.token.length).toBeGreaterThan(0);
      expect(session.identity_id).toBe('id-1');
      expect(session.orgs).toEqual({ org1: 'admin' });
      expect(session.projects).toEqual({ proj1: 'member' });
      expect(session.expires_at).toBeGreaterThan(Date.now());
    } finally {
      store.close();
    }
  });

  it('should validate a valid session token', () => {
    const store = new SessionStore(3600_000);
    try {
      const session = store.create('id-1', {}, {});
      const result = store.validate(session.token);
      expect(result.valid).toBe(true);
      expect(result.session).toBeTruthy();
      expect(result.session!.identity_id).toBe('id-1');
    } finally {
      store.close();
    }
  });

  it('should reject unknown session token', () => {
    const store = new SessionStore(3600_000);
    try {
      const result = store.validate('nonexistent-token');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Session not found');
    } finally {
      store.close();
    }
  });

  it('should reject expired session token', async () => {
    const store = new SessionStore(50); // 50ms TTL
    try {
      const session = store.create('id-1', {}, {});
      await new Promise((r) => setTimeout(r, 100));
      const result = store.validate(session.token);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Session expired');
    } finally {
      store.close();
    }
  });

  it('should revoke a session token', () => {
    const store = new SessionStore(3600_000);
    try {
      const session = store.create('id-1', {}, {});
      expect(store.revoke(session.token)).toBe(true);
      const result = store.validate(session.token);
      expect(result.valid).toBe(false);
    } finally {
      store.close();
    }
  });

  it('should track active session count', () => {
    const store = new SessionStore(3600_000);
    try {
      expect(store.size).toBe(0);
      store.create('id-1', {}, {});
      store.create('id-2', {}, {});
      expect(store.size).toBe(2);
    } finally {
      store.close();
    }
  });
});

// ─── Ed25519 Sign/Verify ────────────────────────────────────────────

describe('Ed25519 sign/verify', () => {
  it('should sign and verify a message', () => {
    const { publicKey, secretKey } = generateKeypair();
    const message = Buffer.from('test message to sign');

    const signature = ed25519Sign(message, secretKey);
    expect(signature.length).toBe(sodium.crypto_sign_BYTES);

    const valid = ed25519Verify(signature, message, publicKey);
    expect(valid).toBe(true);
  });

  it('should reject signature with wrong public key', () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const message = Buffer.from('test message');

    const signature = ed25519Sign(message, kp1.secretKey);
    const valid = ed25519Verify(signature, message, kp2.publicKey);
    expect(valid).toBe(false);
  });

  it('should reject tampered message', () => {
    const { publicKey, secretKey } = generateKeypair();
    const message = Buffer.from('original message');

    const signature = ed25519Sign(message, secretKey);
    const tampered = Buffer.from('tampered message');
    const valid = ed25519Verify(signature, tampered, publicKey);
    expect(valid).toBe(false);
  });

  it('should reject invalid signature length', () => {
    const { publicKey } = generateKeypair();
    const message = Buffer.from('test message');
    const badSig = Buffer.alloc(32); // Wrong length

    const valid = ed25519Verify(badSig, message, publicKey);
    expect(valid).toBe(false);
  });

  it('should reject invalid public key length', () => {
    const message = Buffer.from('test message');
    const sig = Buffer.alloc(sodium.crypto_sign_BYTES);
    const badKey = Buffer.alloc(16); // Wrong length

    const valid = ed25519Verify(sig, message, badKey);
    expect(valid).toBe(false);
  });

  it('should throw for invalid secret key length', () => {
    const message = Buffer.from('test message');
    const badKey = Buffer.alloc(16);

    expect(() => ed25519Sign(message, badKey)).toThrow('Secret key must be');
  });
});

// ─── NetworkAuthenticator ───────────────────────────────────────────

describe('NetworkAuthenticator', () => {
  let tmpDir: string;
  let identityDb: IdentityDatabase;
  let auth: NetworkAuthenticator;
  let identity1: { id: string; publicKey: Buffer; secretKey: Buffer };

  beforeAll(() => {
    const setup = createTestSetup();
    tmpDir = setup.tmpDir;
    identityDb = setup.identityDb;

    // Create an identity
    const result = identityDb.createIdentity('agent-1', 'agent');
    const secretKey = Buffer.from(result.privateKey, 'base64');
    const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
    sodium.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);

    identity1 = { id: result.identity.id, publicKey, secretKey };

    // Create org and project, add identity as member
    const org = identityDb.createOrg('test-org', identity1.id);
    const project = identityDb.createProject(org.id, 'test-project', identity1.id);

    auth = new NetworkAuthenticator(identityDb);
  });

  afterAll(() => {
    auth.close();
    identityDb.close();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ok */
    }
  });

  it('should issue a challenge for a valid identity', () => {
    const result = auth.issueChallenge(identity1.id);
    expect(result).not.toBeNull();
    expect(result!.challenge_id).toBeTruthy();
    expect(result!.challenge).toBeTruthy();
    expect(result!.expires_in).toBe(60);
  });

  it('should return null for non-existent identity', () => {
    const result = auth.issueChallenge('nonexistent-id');
    expect(result).toBeNull();
  });

  it('should verify a correctly signed challenge', () => {
    const challenge = auth.issueChallenge(identity1.id)!;
    const nonce = Buffer.from(challenge.challenge, 'base64url');

    // Sign the nonce
    const signature = ed25519Sign(nonce, identity1.secretKey);
    const signatureBase64url = signature.toString('base64url');

    const result = auth.verifyChallenge(
      challenge.challenge_id,
      identity1.id,
      signatureBase64url,
      identity1.publicKey.toString('base64'),
    );

    expect(result.success).toBe(true);
    expect(result.session_token).toBeTruthy();
    expect(result.expires_in).toBeGreaterThan(0);
    expect(result.identity_id).toBe(identity1.id);
  });

  it('should reject wrong key signature', () => {
    const challenge = auth.issueChallenge(identity1.id)!;
    const nonce = Buffer.from(challenge.challenge, 'base64url');

    // Sign with a DIFFERENT key
    const wrongKeypair = generateKeypair();
    const signature = ed25519Sign(nonce, wrongKeypair.secretKey);

    const result = auth.verifyChallenge(
      challenge.challenge_id,
      identity1.id,
      signature.toString('base64url'),
      wrongKeypair.publicKey.toString('base64'), // Public key won't match stored hash
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain('Public key does not match');
  });

  it('should reject replay of used challenge', () => {
    const challenge = auth.issueChallenge(identity1.id)!;
    const nonce = Buffer.from(challenge.challenge, 'base64url');
    const signature = ed25519Sign(nonce, identity1.secretKey);

    // First verify succeeds
    auth.verifyChallenge(
      challenge.challenge_id,
      identity1.id,
      signature.toString('base64url'),
      identity1.publicKey.toString('base64'),
    );

    // Second verify (replay) fails
    const result = auth.verifyChallenge(
      challenge.challenge_id,
      identity1.id,
      signature.toString('base64url'),
      identity1.publicKey.toString('base64'),
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe('Challenge already used');
  });

  it('should reject expired challenge', async () => {
    // Create authenticator with very short challenge TTL
    const shortAuth = new NetworkAuthenticator(identityDb, 50); // 50ms
    try {
      const challenge = shortAuth.issueChallenge(identity1.id)!;
      const nonce = Buffer.from(challenge.challenge, 'base64url');
      const signature = ed25519Sign(nonce, identity1.secretKey);

      // Wait for expiry
      await new Promise((r) => setTimeout(r, 100));

      const result = shortAuth.verifyChallenge(
        challenge.challenge_id,
        identity1.id,
        signature.toString('base64url'),
        identity1.publicKey.toString('base64'),
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('Challenge expired');
    } finally {
      shortAuth.close();
    }
  });

  it('should include org and project memberships in session', () => {
    const challenge = auth.issueChallenge(identity1.id)!;
    const nonce = Buffer.from(challenge.challenge, 'base64url');
    const signature = ed25519Sign(nonce, identity1.secretKey);

    const result = auth.verifyChallenge(
      challenge.challenge_id,
      identity1.id,
      signature.toString('base64url'),
      identity1.publicKey.toString('base64'),
    );

    expect(result.success).toBe(true);

    // Validate the session token contains memberships
    const session = auth.sessions.validate(result.session_token!);
    expect(session.valid).toBe(true);
    expect(Object.keys(session.session!.orgs).length).toBeGreaterThan(0);
    expect(Object.keys(session.session!.projects).length).toBeGreaterThan(0);

    // Check the roles
    const orgIds = Object.keys(session.session!.orgs);
    expect(session.session!.orgs[orgIds[0]]).toBe('admin');
    const projectIds = Object.keys(session.session!.projects);
    expect(session.session!.projects[projectIds[0]]).toBe('admin');
  });

  it('should validate session tokens', () => {
    const challenge = auth.issueChallenge(identity1.id)!;
    const nonce = Buffer.from(challenge.challenge, 'base64url');
    const signature = ed25519Sign(nonce, identity1.secretKey);

    const verifyResult = auth.verifyChallenge(
      challenge.challenge_id,
      identity1.id,
      signature.toString('base64url'),
      identity1.publicKey.toString('base64'),
    );

    const sessionResult = auth.validateSession(verifyResult.session_token!);
    expect(sessionResult.valid).toBe(true);
    expect(sessionResult.session!.identity_id).toBe(identity1.id);
  });

  it('should reject invalid session tokens', () => {
    const result = auth.validateSession('totally-fake-token');
    expect(result.valid).toBe(false);
  });
});

// ─── Server integration tests ───────────────────────────────────────

describe('Server — /v1/auth/* endpoints', () => {
  let server: http.Server;
  let tmpDir: string;
  let srvTmpDir: string;
  let identityDb: IdentityDatabase;
  let identityDbPath: string;
  let clientCfg: ClientConfig;
  let identity1: { id: string; publicKey: Buffer; secretKey: Buffer };

  beforeAll(async () => {
    // Create identity database with a test identity
    const setup = createTestSetup();
    tmpDir = setup.tmpDir;
    identityDb = setup.identityDb;
    identityDbPath = setup.identityDbPath;

    const result = identityDb.createIdentity('server-agent', 'agent');
    const secretKey = Buffer.from(result.privateKey, 'base64');
    const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
    sodium.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);
    identity1 = { id: result.identity.id, publicKey, secretKey };

    // Create org + project memberships
    const org = identityDb.createOrg('srv-org', identity1.id);
    identityDb.createProject(org.id, 'srv-project', identity1.id);

    // Start server
    const srvSetup = createTmpConfig(identityDbPath);
    srvTmpDir = srvSetup.tmpDir;
    server = (await createVaultServer(srvSetup.config)) as http.Server;

    clientCfg = {
      port: getPort(server),
      host: '127.0.0.1',
      insecure: true,
    };
  });

  afterAll(() => {
    try {
      server.close();
    } catch {
      /* ok */
    }
    identityDb.close();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ok */
    }
    try {
      fs.rmSync(srvTmpDir, { recursive: true, force: true });
    } catch {
      /* ok */
    }
  });

  it('should issue a challenge via POST /v1/auth/challenge', async () => {
    const res = await request(clientCfg, 'POST', '/v1/auth/challenge', {
      identity_id: identity1.id,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.challenge_id).toBeTruthy();
    expect(res.body.challenge).toBeTruthy();
    expect(res.body.expires_in).toBe(60);
  });

  it('should reject challenge without identity_id', async () => {
    const res = await request(clientCfg, 'POST', '/v1/auth/challenge', {});
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('identity_id');
  });

  it('should reject challenge for non-existent identity', async () => {
    const res = await request(clientCfg, 'POST', '/v1/auth/challenge', {
      identity_id: 'nonexistent',
    });
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('Unable to issue challenge');
  });

  it('should complete full challenge-response flow', async () => {
    // Step 1: Get challenge
    const challengeRes = await request(clientCfg, 'POST', '/v1/auth/challenge', {
      identity_id: identity1.id,
    });
    expect(challengeRes.statusCode).toBe(200);

    const nonce = Buffer.from(challengeRes.body.challenge as string, 'base64url');
    const challengeId = challengeRes.body.challenge_id as string;

    // Step 2: Sign the challenge
    const signature = ed25519Sign(nonce, identity1.secretKey);

    // Step 3: Verify
    const verifyRes = await request(clientCfg, 'POST', '/v1/auth/verify', {
      challenge_id: challengeId,
      identity_id: identity1.id,
      signature: signature.toString('base64url'),
      public_key: identity1.publicKey.toString('base64'),
    });

    expect(verifyRes.statusCode).toBe(200);
    expect(verifyRes.body.ok).toBe(true);
    expect(verifyRes.body.session_token).toBeTruthy();
    expect(verifyRes.body.expires_in).toBeGreaterThan(0);
    expect(verifyRes.body.identity_id).toBe(identity1.id);
  });

  it('should reject verify with wrong key', async () => {
    // Get challenge
    const challengeRes = await request(clientCfg, 'POST', '/v1/auth/challenge', {
      identity_id: identity1.id,
    });

    const nonce = Buffer.from(challengeRes.body.challenge as string, 'base64url');
    const challengeId = challengeRes.body.challenge_id as string;

    // Sign with wrong key
    const wrongKeypair = generateKeypair();
    const signature = ed25519Sign(nonce, wrongKeypair.secretKey);

    const verifyRes = await request(clientCfg, 'POST', '/v1/auth/verify', {
      challenge_id: challengeId,
      identity_id: identity1.id,
      signature: signature.toString('base64url'),
      public_key: wrongKeypair.publicKey.toString('base64'),
    });

    expect(verifyRes.statusCode).toBe(401);
  });

  it('should reject replay of signed challenge', async () => {
    // Get challenge
    const challengeRes = await request(clientCfg, 'POST', '/v1/auth/challenge', {
      identity_id: identity1.id,
    });

    const nonce = Buffer.from(challengeRes.body.challenge as string, 'base64url');
    const challengeId = challengeRes.body.challenge_id as string;
    const signature = ed25519Sign(nonce, identity1.secretKey);

    // First verify succeeds
    const verifyRes1 = await request(clientCfg, 'POST', '/v1/auth/verify', {
      challenge_id: challengeId,
      identity_id: identity1.id,
      signature: signature.toString('base64url'),
      public_key: identity1.publicKey.toString('base64'),
    });
    expect(verifyRes1.statusCode).toBe(200);

    // Replay attempt
    const verifyRes2 = await request(clientCfg, 'POST', '/v1/auth/verify', {
      challenge_id: challengeId,
      identity_id: identity1.id,
      signature: signature.toString('base64url'),
      public_key: identity1.publicKey.toString('base64'),
    });
    expect(verifyRes2.statusCode).toBe(401);
  });

  it('should use session token as Bearer for subsequent requests', async () => {
    // Authenticate
    const challengeRes = await request(clientCfg, 'POST', '/v1/auth/challenge', {
      identity_id: identity1.id,
    });
    const nonce = Buffer.from(challengeRes.body.challenge as string, 'base64url');
    const signature = ed25519Sign(nonce, identity1.secretKey);

    const verifyRes = await request(clientCfg, 'POST', '/v1/auth/verify', {
      challenge_id: challengeRes.body.challenge_id as string,
      identity_id: identity1.id,
      signature: signature.toString('base64url'),
      public_key: identity1.publicKey.toString('base64'),
    });

    const sessionToken = verifyRes.body.session_token as string;

    // Use session token for an authenticated request (e.g., /v1/status)
    const statusRes = await request(
      { ...clientCfg, token: sessionToken },
      'GET',
      '/v1/status',
    );

    expect(statusRes.statusCode).toBe(200);
    expect(statusRes.body.serverRunning).toBe(true);
  });

  it('should reject verify with missing fields', async () => {
    // Missing challenge_id
    let res = await request(clientCfg, 'POST', '/v1/auth/verify', {
      identity_id: identity1.id,
      signature: 'abc',
      public_key: 'def',
    });
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('challenge_id');

    // Missing identity_id
    res = await request(clientCfg, 'POST', '/v1/auth/verify', {
      challenge_id: 'abc',
      signature: 'def',
      public_key: 'ghi',
    });
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('identity_id');

    // Missing signature
    res = await request(clientCfg, 'POST', '/v1/auth/verify', {
      challenge_id: 'abc',
      identity_id: identity1.id,
      public_key: 'ghi',
    });
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('signature');

    // Missing public_key
    res = await request(clientCfg, 'POST', '/v1/auth/verify', {
      challenge_id: 'abc',
      identity_id: identity1.id,
      signature: 'def',
    });
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('public_key');
  });

  it('should rate-limit failed verification attempts', async () => {
    // Create a separate server with aggressive rate limiting for this test
    const setup2 = createTestSetup();
    const srvSetup2 = createTmpConfig(setup2.identityDbPath, {
      rateLimitConfig: { maxFailures: 3, windowMs: 60_000, lockoutMs: 300_000 },
    });

    // Create an identity in the new DB
    const idResult = setup2.identityDb.createIdentity('rate-test', 'agent');
    const sk = Buffer.from(idResult.privateKey, 'base64');
    const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
    sodium.crypto_sign_ed25519_sk_to_pk(pk, sk);

    const srv2 = (await createVaultServer(srvSetup2.config)) as http.Server;
    const cfg2: ClientConfig = {
      port: getPort(srv2),
      host: '127.0.0.1',
      insecure: true,
    };

    try {
      const wrongKeypair = generateKeypair();

      // Generate 3 failed attempts
      for (let i = 0; i < 3; i++) {
        const challengeRes = await request(cfg2, 'POST', '/v1/auth/challenge', {
          identity_id: idResult.identity.id,
        });
        const nonce = Buffer.from(challengeRes.body.challenge as string, 'base64url');
        const wrongSig = ed25519Sign(nonce, wrongKeypair.secretKey);

        await request(cfg2, 'POST', '/v1/auth/verify', {
          challenge_id: challengeRes.body.challenge_id,
          identity_id: idResult.identity.id,
          signature: wrongSig.toString('base64url'),
          public_key: wrongKeypair.publicKey.toString('base64'),
        });
      }

      // Next attempt should be rate limited (429)
      const challengeRes = await request(cfg2, 'POST', '/v1/auth/challenge', {
        identity_id: idResult.identity.id,
      });
      // Rate limit check happens before route handling
      expect(challengeRes.statusCode).toBe(429);
    } finally {
      srv2.close();
      setup2.identityDb.close();
      try {
        fs.rmSync(setup2.tmpDir, { recursive: true, force: true });
      } catch {
        /* ok */
      }
      try {
        fs.rmSync(srvSetup2.tmpDir, { recursive: true, force: true });
      } catch {
        /* ok */
      }
    }
  });
});
