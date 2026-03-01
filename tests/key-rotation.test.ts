/**
 * Tests for identity key rotation — US-010.
 *
 * Covers:
 * - rotateKey() generates new Ed25519 keypair and updates stored hash
 * - Old key is immediately invalidated (no grace period)
 * - Grace period allows both old and new key
 * - Grace period expiry invalidates old key
 * - isValidKeyHash() checks current key and old key within grace period
 * - verifyIdentity() works with new key after rotation
 * - verifyIdentity() works with old key during grace period
 * - SessionStore.revokeSessionsForIdentity() clears sessions
 * - Key rotation invalidates old sessions (without grace period)
 * - NetworkAuthenticator verifyChallenge accepts old key during grace period
 * - Audit logging of identity.key_rotated
 * - Error handling: rotate nonexistent identity
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import {
  IdentityDatabase,
  type KeyRotationResult,
} from '../src/identity.js';
import {
  SessionStore,
  NetworkAuthenticator,
  ed25519Sign,
} from '../src/network-auth.js';
import { AuditLogger, readAuditLog } from '../src/audit.js';
import sodium from 'sodium-native';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// ─── Test Helpers ─────────────────────────────────────────────────

let tmpDir: string;
let db: IdentityDatabase;

function createTestDb(): IdentityDatabase {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-keyrot-'));
  const dbPath = path.join(tmpDir, 'identity.db');
  return new IdentityDatabase(dbPath);
}

function cleanupTestDb(): void {
  if (db) {
    try { db.close(); } catch { /* already closed */ }
  }
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/** Hash a public key (SHA-256 hex) — same as IdentityDatabase does. */
function hashPublicKey(publicKey: Buffer): string {
  return crypto.createHash('sha256').update(publicKey).digest('hex');
}

/** Extract public key from private key. */
function extractPublicKey(privateKeyBase64: string): Buffer {
  const secretKey = Buffer.from(privateKeyBase64, 'base64');
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  sodium.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);
  return publicKey;
}

beforeEach(() => {
  db = createTestDb();
});

afterEach(() => {
  cleanupTestDb();
});

// ─── rotateKey() ─────────────────────────────────────────────────

describe('Key Rotation — rotateKey()', () => {
  it('should generate a new keypair and update the stored hash', () => {
    const original = db.createIdentity('alice', 'human');
    const originalKeyHash = original.identity.public_key_hash;

    const result = db.rotateKey(original.identity.id);

    // New key should be different
    expect(result.identity.public_key_hash).not.toBe(originalKeyHash);

    // Private key should be valid Ed25519 secret key (64 bytes)
    const skBuf = Buffer.from(result.privateKey, 'base64');
    expect(skBuf.length).toBe(64);

    // Public key should be valid Ed25519 public key (32 bytes)
    const pkBuf = Buffer.from(result.publicKey, 'base64');
    expect(pkBuf.length).toBe(32);

    // Hash prefixes should match
    expect(result.oldKeyHashPrefix).toBe(originalKeyHash.substring(0, 12));
    expect(result.newKeyHashPrefix).toBe(result.identity.public_key_hash.substring(0, 12));
  });

  it('should immediately invalidate old key without grace period', () => {
    const original = db.createIdentity('alice', 'human');
    const originalKeyHash = original.identity.public_key_hash;

    const result = db.rotateKey(original.identity.id);

    // Old key hash fields should be null (no grace period)
    expect(result.identity.old_public_key_hash).toBeNull();
    expect(result.identity.old_key_expires_at).toBeNull();

    // isValidKeyHash should reject old key
    expect(db.isValidKeyHash(original.identity.id, originalKeyHash)).toBe(false);

    // isValidKeyHash should accept new key
    expect(db.isValidKeyHash(original.identity.id, result.identity.public_key_hash)).toBe(true);
  });

  it('should keep old key valid during grace period', () => {
    const original = db.createIdentity('alice', 'human');
    const originalKeyHash = original.identity.public_key_hash;

    // Rotate with 1 hour grace period
    const result = db.rotateKey(original.identity.id, 60 * 60 * 1000);

    // Old key hash should be stored
    expect(result.identity.old_public_key_hash).toBe(originalKeyHash);
    expect(result.identity.old_key_expires_at).toBeTruthy();

    // Both old and new keys should be valid
    expect(db.isValidKeyHash(original.identity.id, originalKeyHash)).toBe(true);
    expect(db.isValidKeyHash(original.identity.id, result.identity.public_key_hash)).toBe(true);
  });

  it('should invalidate old key after grace period expires', async () => {
    const original = db.createIdentity('alice', 'human');
    const originalKeyHash = original.identity.public_key_hash;

    // Rotate with 50ms grace period
    db.rotateKey(original.identity.id, 50);

    // Old key should be valid immediately
    expect(db.isValidKeyHash(original.identity.id, originalKeyHash)).toBe(true);

    // Wait for grace period to expire
    await new Promise((r) => setTimeout(r, 100));

    // Old key should now be invalid
    expect(db.isValidKeyHash(original.identity.id, originalKeyHash)).toBe(false);
  });

  it('should throw for nonexistent identity', () => {
    expect(() => db.rotateKey('nonexistent')).toThrow("Identity 'nonexistent' not found");
  });

  it('should allow multiple consecutive rotations', () => {
    const original = db.createIdentity('alice', 'human');

    const rotation1 = db.rotateKey(original.identity.id);
    const rotation2 = db.rotateKey(original.identity.id);

    // Final key should be from rotation2
    const identity = db.getIdentity(original.identity.id)!;
    expect(identity.public_key_hash).toBe(rotation2.identity.public_key_hash);

    // rotation1 key should be invalid (no grace period)
    expect(db.isValidKeyHash(original.identity.id, rotation1.identity.public_key_hash)).toBe(false);
  });

  it('should allow rotation with grace period then another rotation replaces old key', () => {
    const original = db.createIdentity('alice', 'human');
    const originalKeyHash = original.identity.public_key_hash;

    // First rotation with grace period
    const rotation1 = db.rotateKey(original.identity.id, 60 * 60 * 1000);

    // Second rotation without grace period
    const rotation2 = db.rotateKey(original.identity.id);

    // Original key should now be invalid (replaced by rotation1's old key which was then replaced)
    expect(db.isValidKeyHash(original.identity.id, originalKeyHash)).toBe(false);
    // rotation1 key should also be invalid (no grace period on rotation2)
    expect(db.isValidKeyHash(original.identity.id, rotation1.identity.public_key_hash)).toBe(false);
    // Only rotation2 key should be valid
    expect(db.isValidKeyHash(original.identity.id, rotation2.identity.public_key_hash)).toBe(true);
  });
});

// ─── verifyIdentity after rotation ─────────────────────────────

describe('Key Rotation — verifyIdentity()', () => {
  it('should verify with new key after rotation', () => {
    const original = db.createIdentity('alice', 'human');
    const rotation = db.rotateKey(original.identity.id);

    // New key should verify
    const verified = db.verifyIdentity(rotation.privateKey);
    expect(verified).not.toBeNull();
    expect(verified!.id).toBe(original.identity.id);
    expect(verified!.name).toBe('alice');
  });

  it('should not verify with old key after rotation (no grace period)', () => {
    const original = db.createIdentity('alice', 'human');
    db.rotateKey(original.identity.id);

    // Old key should no longer verify
    const verified = db.verifyIdentity(original.privateKey);
    expect(verified).toBeNull();
  });

  it('should verify with old key during grace period', () => {
    const original = db.createIdentity('alice', 'human');
    db.rotateKey(original.identity.id, 60 * 60 * 1000); // 1 hour

    // Old key should still verify during grace period
    const verified = db.verifyIdentity(original.privateKey);
    expect(verified).not.toBeNull();
    expect(verified!.id).toBe(original.identity.id);
  });

  it('should not verify with old key after grace period expires', async () => {
    const original = db.createIdentity('alice', 'human');
    db.rotateKey(original.identity.id, 50); // 50ms

    // Wait for grace period to expire
    await new Promise((r) => setTimeout(r, 100));

    // Old key should no longer verify
    const verified = db.verifyIdentity(original.privateKey);
    expect(verified).toBeNull();
  });
});

// ─── isValidKeyHash() ───────────────────────────────────────────

describe('Key Rotation — isValidKeyHash()', () => {
  it('should return true for current key hash', () => {
    const { identity } = db.createIdentity('alice', 'human');
    expect(db.isValidKeyHash(identity.id, identity.public_key_hash)).toBe(true);
  });

  it('should return false for random hash', () => {
    const { identity } = db.createIdentity('alice', 'human');
    expect(db.isValidKeyHash(identity.id, 'deadbeef'.repeat(8))).toBe(false);
  });

  it('should return false for nonexistent identity', () => {
    expect(db.isValidKeyHash('nonexistent', 'somehash')).toBe(false);
  });
});

// ─── SessionStore.revokeSessionsForIdentity() ───────────────────

describe('Key Rotation — revokeSessionsForIdentity()', () => {
  it('should revoke all sessions for an identity', () => {
    const store = new SessionStore(3600_000);
    try {
      // Create sessions for two identities
      const s1 = store.create('id-1', {}, {});
      const s2 = store.create('id-1', {}, {}); // second session for id-1
      const s3 = store.create('id-2', {}, {}); // different identity

      expect(store.size).toBe(3);

      // Revoke sessions for id-1
      const revoked = store.revokeSessionsForIdentity('id-1');
      expect(revoked).toBe(2);

      // id-1 sessions should be invalid
      expect(store.validate(s1.token).valid).toBe(false);
      expect(store.validate(s2.token).valid).toBe(false);

      // id-2 session should still be valid
      expect(store.validate(s3.token).valid).toBe(true);

      expect(store.size).toBe(1);
    } finally {
      store.close();
    }
  });

  it('should return 0 when no sessions exist for identity', () => {
    const store = new SessionStore(3600_000);
    try {
      store.create('id-1', {}, {});
      const revoked = store.revokeSessionsForIdentity('id-2');
      expect(revoked).toBe(0);
      expect(store.size).toBe(1);
    } finally {
      store.close();
    }
  });
});

// ─── NetworkAuthenticator integration ───────────────────────────

describe('Key Rotation — NetworkAuthenticator integration', () => {
  let testDir: string;
  let identityDb: IdentityDatabase;
  let auth: NetworkAuthenticator;

  beforeAll(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-keyrot-auth-'));
    const dbPath = path.join(testDir, 'identity.db');
    identityDb = new IdentityDatabase(dbPath);
    auth = new NetworkAuthenticator(identityDb);
  });

  afterAll(() => {
    auth.close();
    identityDb.close();
    try { fs.rmSync(testDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should invalidate old sessions after key rotation (no grace period)', () => {
    // Create identity and authenticate
    const idResult = identityDb.createIdentity('rotate-agent-1', 'agent');
    const secretKey = Buffer.from(idResult.privateKey, 'base64');
    const publicKey = extractPublicKey(idResult.privateKey);

    // Create a session
    const challenge = auth.issueChallenge(idResult.identity.id)!;
    const nonce = Buffer.from(challenge.challenge, 'base64url');
    const signature = ed25519Sign(nonce, secretKey);

    const verifyResult = auth.verifyChallenge(
      challenge.challenge_id,
      idResult.identity.id,
      signature.toString('base64url'),
      publicKey.toString('base64'),
    );
    expect(verifyResult.success).toBe(true);

    // Verify the session is valid
    const sessionBefore = auth.validateSession(verifyResult.session_token!);
    expect(sessionBefore.valid).toBe(true);

    // Rotate key (no grace period) and revoke sessions
    identityDb.rotateKey(idResult.identity.id);
    auth.sessions.revokeSessionsForIdentity(idResult.identity.id);

    // Old session should be invalidated
    const sessionAfter = auth.validateSession(verifyResult.session_token!);
    expect(sessionAfter.valid).toBe(false);
  });

  it('should accept old key during grace period for auth', () => {
    // Create identity
    const idResult = identityDb.createIdentity('rotate-agent-2', 'agent');
    const oldSecretKey = Buffer.from(idResult.privateKey, 'base64');
    const oldPublicKey = extractPublicKey(idResult.privateKey);

    // Rotate with 1 hour grace period
    const rotation = identityDb.rotateKey(idResult.identity.id, 60 * 60 * 1000);

    // Authenticate with OLD key (should work during grace period)
    const challenge = auth.issueChallenge(idResult.identity.id)!;
    const nonce = Buffer.from(challenge.challenge, 'base64url');
    const signature = ed25519Sign(nonce, oldSecretKey);

    const verifyResult = auth.verifyChallenge(
      challenge.challenge_id,
      idResult.identity.id,
      signature.toString('base64url'),
      oldPublicKey.toString('base64'),
    );

    expect(verifyResult.success).toBe(true);
    expect(verifyResult.session_token).toBeTruthy();
  });

  it('should accept new key after rotation for auth', () => {
    // Create identity
    const idResult = identityDb.createIdentity('rotate-agent-3', 'agent');

    // Rotate key
    const rotation = identityDb.rotateKey(idResult.identity.id);
    const newSecretKey = Buffer.from(rotation.privateKey, 'base64');
    const newPublicKey = extractPublicKey(rotation.privateKey);

    // Authenticate with NEW key
    const challenge = auth.issueChallenge(idResult.identity.id)!;
    const nonce = Buffer.from(challenge.challenge, 'base64url');
    const signature = ed25519Sign(nonce, newSecretKey);

    const verifyResult = auth.verifyChallenge(
      challenge.challenge_id,
      idResult.identity.id,
      signature.toString('base64url'),
      newPublicKey.toString('base64'),
    );

    expect(verifyResult.success).toBe(true);
    expect(verifyResult.session_token).toBeTruthy();
  });

  it('should reject old key after rotation without grace period', () => {
    // Create identity
    const idResult = identityDb.createIdentity('rotate-agent-4', 'agent');
    const oldSecretKey = Buffer.from(idResult.privateKey, 'base64');
    const oldPublicKey = extractPublicKey(idResult.privateKey);

    // Rotate without grace period
    identityDb.rotateKey(idResult.identity.id);

    // Authenticate with OLD key (should fail)
    const challenge = auth.issueChallenge(idResult.identity.id)!;
    const nonce = Buffer.from(challenge.challenge, 'base64url');
    const signature = ed25519Sign(nonce, oldSecretKey);

    const verifyResult = auth.verifyChallenge(
      challenge.challenge_id,
      idResult.identity.id,
      signature.toString('base64url'),
      oldPublicKey.toString('base64'),
    );

    expect(verifyResult.success).toBe(false);
    expect(verifyResult.error).toContain('Public key does not match');
  });
});

// ─── Audit logging ──────────────────────────────────────────────

describe('Key Rotation — Audit logging', () => {
  it('should log identity.key_rotated with old and new hash prefixes', () => {
    const auditDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-keyrot-audit-'));
    const auditLogPath = path.join(auditDir, 'audit.log');

    try {
      const auditLogger = new AuditLogger(auditLogPath);

      const original = db.createIdentity('audit-test', 'human');
      const rotation = db.rotateKey(original.identity.id);

      // Log the rotation event
      auditLogger.logNetworkEvent('identity.key_rotated', {
        ip: '127.0.0.1',
        identity_id: original.identity.id,
        identity_name: 'audit-test',
        mode: 'local',
        detail: `old_key_hash=${rotation.oldKeyHashPrefix}... new_key_hash=${rotation.newKeyHashPrefix}...`,
      });
      auditLogger.close();

      // Read and verify audit log
      const entries = readAuditLog(auditLogPath);
      const rotationEntries = entries.filter(e => e.operation === 'identity.key_rotated');

      expect(rotationEntries.length).toBe(1);
      expect(rotationEntries[0].identity_id).toBe(original.identity.id);
      expect(rotationEntries[0].identity_name).toBe('audit-test');
      expect(rotationEntries[0].detail).toContain('old_key_hash=');
      expect(rotationEntries[0].detail).toContain('new_key_hash=');
      // Verify hash prefixes are partial (not full 64-char hashes)
      const oldHashMatch = rotationEntries[0].detail!.match(/old_key_hash=([a-f0-9]+)/);
      expect(oldHashMatch).toBeTruthy();
      expect(oldHashMatch![1].length).toBe(12); // prefix only
    } finally {
      fs.rmSync(auditDir, { recursive: true, force: true });
    }
  });
});

// ─── clearExpiredOldKeys() ──────────────────────────────────────

describe('Key Rotation — clearExpiredOldKeys()', () => {
  it('should clear expired old key hashes', async () => {
    const original = db.createIdentity('alice', 'human');
    const originalKeyHash = original.identity.public_key_hash;

    // Rotate with very short grace period
    db.rotateKey(original.identity.id, 50); // 50ms

    // Verify old key is stored
    let identity = db.getIdentity(original.identity.id)!;
    expect(identity.old_public_key_hash).toBe(originalKeyHash);

    // Wait for grace period to expire
    await new Promise((r) => setTimeout(r, 100));

    // Clear expired old keys
    const cleared = db.clearExpiredOldKeys();
    expect(cleared).toBe(1);

    // Verify old key fields are cleared
    identity = db.getIdentity(original.identity.id)!;
    expect(identity.old_public_key_hash).toBeNull();
    expect(identity.old_key_expires_at).toBeNull();
  });

  it('should not clear old keys that have not expired', () => {
    const original = db.createIdentity('alice', 'human');

    // Rotate with 1 hour grace period
    db.rotateKey(original.identity.id, 60 * 60 * 1000);

    // Clear expired old keys (should not clear anything)
    const cleared = db.clearExpiredOldKeys();
    expect(cleared).toBe(0);

    // Verify old key fields are still set
    const identity = db.getIdentity(original.identity.id)!;
    expect(identity.old_public_key_hash).not.toBeNull();
    expect(identity.old_key_expires_at).not.toBeNull();
  });
});
