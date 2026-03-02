/**
 * Network authentication module for hq-vault — US-003.
 *
 * Provides challenge-response authentication using Ed25519 keypairs:
 * - ChallengeStore: in-memory store for challenge nonces with 60s TTL
 * - issueChallenge: generates 32-byte nonce, returns challenge_id + base64url nonce
 * - verifyChallenge: validates Ed25519 signature, creates session token with identity metadata
 * - SessionStore: in-memory store for session tokens with 1-hour TTL
 *
 * Uses libsodium-wrappers-sumo (WASM) for Ed25519 operations.
 */

import sodium from 'libsodium-wrappers-sumo';
import crypto from 'node:crypto';
import type { IdentityDatabase, MemberRole } from './identity.js';
import { ensureSodium } from './crypto.js';

// ─── Types ──────────────────────────────────────────────────────────

export interface Challenge {
  /** Unique ID for this challenge. */
  challenge_id: string;
  /** The identity_id this challenge was issued for. */
  identity_id: string;
  /** The raw challenge nonce (32 bytes). */
  nonce: Buffer;
  /** When this challenge expires (Unix ms). */
  expires_at: number;
  /** Whether this challenge has been consumed. */
  used: boolean;
}

export interface ChallengeResponse {
  challenge_id: string;
  /** Base64url-encoded challenge nonce. */
  challenge: string;
  /** Seconds until expiry. */
  expires_in: number;
}

export interface SessionToken {
  /** The opaque token string (32 bytes, base64url). */
  token: string;
  /** SHA-256 hash of the token for lookup. */
  token_hash: string;
  /** The identity this session belongs to. */
  identity_id: string;
  /** Org memberships: { org_id: role }. */
  orgs: Record<string, MemberRole>;
  /** Project memberships: { project_id: role }. */
  projects: Record<string, MemberRole>;
  /** When this session was created (Unix ms). */
  created_at: number;
  /** When this session expires (Unix ms). */
  expires_at: number;
}

export interface SessionValidationResult {
  valid: boolean;
  reason?: string;
  session?: SessionToken;
}

export interface VerifyChallengeResult {
  success: boolean;
  error?: string;
  session_token?: string;
  expires_in?: number;
  identity_id?: string;
}

// ─── Constants ──────────────────────────────────────────────────────

/** Default challenge TTL: 60 seconds. */
export const DEFAULT_CHALLENGE_TTL_MS = 60 * 1000;

/** Default session token TTL: 1 hour. */
export const DEFAULT_SESSION_TTL_MS = 60 * 60 * 1000;

/** Challenge nonce size: 32 bytes. */
const CHALLENGE_NONCE_BYTES = 32;

// ─── ChallengeStore ─────────────────────────────────────────────────

export class ChallengeStore {
  private challenges: Map<string, Challenge> = new Map();
  private ttlMs: number;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(ttlMs: number = DEFAULT_CHALLENGE_TTL_MS) {
    this.ttlMs = ttlMs;
    this.cleanupTimer = setInterval(() => this.cleanup(), 30_000);
    this.cleanupTimer.unref();
  }

  /**
   * Issue a new challenge for an identity.
   */
  async issue(identityId: string): Promise<ChallengeResponse> {
    await ensureSodium();
    const nonce = Buffer.from(sodium.randombytes_buf(CHALLENGE_NONCE_BYTES));

    const challengeId = crypto.randomBytes(16).toString('hex');

    const now = Date.now();
    const challenge: Challenge = {
      challenge_id: challengeId,
      identity_id: identityId,
      nonce,
      expires_at: now + this.ttlMs,
      used: false,
    };

    this.challenges.set(challengeId, challenge);

    return {
      challenge_id: challengeId,
      challenge: nonce.toString('base64url'),
      expires_in: Math.ceil(this.ttlMs / 1000),
    };
  }

  /**
   * Consume a challenge by ID.
   */
  consume(challengeId: string, identityId: string): { challenge: Challenge | null; error?: string } {
    const challenge = this.challenges.get(challengeId);

    if (!challenge) {
      return { challenge: null, error: 'Challenge not found' };
    }

    if (challenge.used) {
      return { challenge: null, error: 'Challenge already used' };
    }

    if (Date.now() > challenge.expires_at) {
      this.challenges.delete(challengeId);
      return { challenge: null, error: 'Challenge expired' };
    }

    if (challenge.identity_id !== identityId) {
      return { challenge: null, error: 'Identity mismatch' };
    }

    challenge.used = true;
    return { challenge };
  }

  cleanup(): void {
    const now = Date.now();
    for (const [id, challenge] of this.challenges) {
      if (challenge.used || now > challenge.expires_at) {
        this.challenges.delete(id);
      }
    }
  }

  get size(): number {
    let count = 0;
    const now = Date.now();
    for (const challenge of this.challenges.values()) {
      if (!challenge.used && now <= challenge.expires_at) {
        count++;
      }
    }
    return count;
  }

  close(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.challenges.clear();
  }
}

// ─── SessionStore ───────────────────────────────────────────────────

export class SessionStore {
  private sessions: Map<string, SessionToken> = new Map();
  private ttlMs: number;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(ttlMs: number = DEFAULT_SESSION_TTL_MS) {
    this.ttlMs = ttlMs;
    this.cleanupTimer = setInterval(() => this.cleanup(), 5 * 60_000);
    this.cleanupTimer.unref();
  }

  create(
    identityId: string,
    orgs: Record<string, MemberRole>,
    projects: Record<string, MemberRole>,
  ): SessionToken {
    const rawToken = crypto.randomBytes(32).toString('base64url');
    const tokenHash = crypto.createHash('sha256').update(rawToken, 'utf-8').digest('hex');

    const now = Date.now();
    const session: SessionToken = {
      token: rawToken,
      token_hash: tokenHash,
      identity_id: identityId,
      orgs,
      projects,
      created_at: now,
      expires_at: now + this.ttlMs,
    };

    this.sessions.set(tokenHash, session);
    return session;
  }

  validate(rawToken: string): SessionValidationResult {
    const tokenHash = crypto.createHash('sha256').update(rawToken, 'utf-8').digest('hex');
    const session = this.sessions.get(tokenHash);

    if (!session) {
      return { valid: false, reason: 'Session not found' };
    }

    if (Date.now() > session.expires_at) {
      this.sessions.delete(tokenHash);
      return { valid: false, reason: 'Session expired' };
    }

    return { valid: true, session };
  }

  revoke(rawToken: string): boolean {
    const tokenHash = crypto.createHash('sha256').update(rawToken, 'utf-8').digest('hex');
    return this.sessions.delete(tokenHash);
  }

  revokeSessionsForIdentity(identityId: string): number {
    let count = 0;
    for (const [hash, session] of this.sessions) {
      if (session.identity_id === identityId) {
        this.sessions.delete(hash);
        count++;
      }
    }
    return count;
  }

  cleanup(): void {
    const now = Date.now();
    for (const [hash, session] of this.sessions) {
      if (now > session.expires_at) {
        this.sessions.delete(hash);
      }
    }
  }

  get size(): number {
    let count = 0;
    const now = Date.now();
    for (const session of this.sessions.values()) {
      if (now <= session.expires_at) {
        count++;
      }
    }
    return count;
  }

  close(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.sessions.clear();
  }
}

// ─── Ed25519 Sign/Verify ────────────────────────────────────────────

/**
 * Sign a message with an Ed25519 private key.
 */
export async function ed25519Sign(message: Buffer, secretKey: Buffer): Promise<Buffer> {
  await ensureSodium();
  if (secretKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
    throw new Error(
      `Secret key must be ${sodium.crypto_sign_SECRETKEYBYTES} bytes, got ${secretKey.length}`,
    );
  }

  const signature = sodium.crypto_sign_detached(
    new Uint8Array(message),
    new Uint8Array(secretKey),
  );
  return Buffer.from(signature);
}

/**
 * Verify an Ed25519 detached signature.
 */
export async function ed25519Verify(signature: Buffer, message: Buffer, publicKey: Buffer): Promise<boolean> {
  await ensureSodium();
  if (publicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
    return false;
  }
  if (signature.length !== sodium.crypto_sign_BYTES) {
    return false;
  }

  try {
    return sodium.crypto_sign_verify_detached(
      new Uint8Array(signature),
      new Uint8Array(message),
      new Uint8Array(publicKey),
    );
  } catch {
    return false;
  }
}

// ─── NetworkAuthenticator ───────────────────────────────────────────

export class NetworkAuthenticator {
  private challengeStore: ChallengeStore;
  private sessionStore: SessionStore;
  private identityDb: IdentityDatabase;

  constructor(
    identityDb: IdentityDatabase,
    challengeTtlMs?: number,
    sessionTtlMs?: number,
  ) {
    this.identityDb = identityDb;
    this.challengeStore = new ChallengeStore(challengeTtlMs);
    this.sessionStore = new SessionStore(sessionTtlMs);
  }

  /**
   * Issue a challenge for an identity.
   */
  async issueChallenge(identityId: string): Promise<ChallengeResponse | null> {
    const identity = this.identityDb.getIdentity(identityId);
    if (!identity) {
      return null;
    }

    return this.challengeStore.issue(identityId);
  }

  /**
   * Verify a challenge response and create a session token.
   */
  async verifyChallenge(
    challengeId: string,
    identityId: string,
    signatureBase64: string,
    publicKeyBase64: string,
  ): Promise<VerifyChallengeResult> {
    // 1. Consume the challenge
    const { challenge, error } = this.challengeStore.consume(challengeId, identityId);
    if (!challenge || error) {
      return { success: false, error: error || 'Invalid challenge' };
    }

    // 2. Look up the identity
    const identity = this.identityDb.getIdentity(identityId);
    if (!identity) {
      return { success: false, error: 'Identity not found' };
    }

    // 3. Verify the public key matches the stored hash
    await ensureSodium();

    let publicKey: Buffer;
    try {
      publicKey = Buffer.from(publicKeyBase64, 'base64');
    } catch {
      return { success: false, error: 'Invalid public key encoding' };
    }

    if (publicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
      return { success: false, error: 'Invalid public key length' };
    }

    const computedHash = crypto
      .createHash('sha256')
      .update(publicKey)
      .digest('hex');

    if (!this.identityDb.isValidKeyHash(identityId, computedHash)) {
      return { success: false, error: 'Public key does not match identity' };
    }

    // 4. Verify the Ed25519 signature
    let signature: Buffer;
    try {
      signature = Buffer.from(signatureBase64, 'base64url');
    } catch {
      return { success: false, error: 'Invalid signature encoding' };
    }

    const valid = await ed25519Verify(signature, challenge.nonce, publicKey);
    if (!valid) {
      return { success: false, error: 'Signature verification failed' };
    }

    // 5. Get identity memberships
    const memberships = this.getIdentityMemberships(identityId);

    // 6. Create session token
    const session = this.sessionStore.create(identityId, memberships.orgs, memberships.projects);

    return {
      success: true,
      session_token: session.token,
      expires_in: Math.ceil((session.expires_at - Date.now()) / 1000),
      identity_id: identityId,
    };
  }

  validateSession(rawToken: string): SessionValidationResult {
    return this.sessionStore.validate(rawToken);
  }

  private getIdentityMemberships(identityId: string): {
    orgs: Record<string, MemberRole>;
    projects: Record<string, MemberRole>;
  } {
    const orgs: Record<string, MemberRole> = {};
    const projects: Record<string, MemberRole> = {};

    const allOrgs = this.identityDb.listOrgs();
    for (const org of allOrgs) {
      const role = this.identityDb.getOrgRole(org.id, identityId);
      if (role) {
        orgs[org.id] = role;

        const orgProjects = this.identityDb.listProjects(org.id);
        for (const project of orgProjects) {
          const projectRole = this.identityDb.getProjectRole(project.id, identityId);
          if (projectRole) {
            projects[project.id] = projectRole;
          }
        }
      }
    }

    return { orgs, projects };
  }

  get challenges(): ChallengeStore {
    return this.challengeStore;
  }

  get sessions(): SessionStore {
    return this.sessionStore;
  }

  close(): void {
    this.challengeStore.close();
    this.sessionStore.close();
  }
}
