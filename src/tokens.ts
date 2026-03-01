/**
 * Token management module for hq-vault — US-005.
 *
 * Provides:
 * - Token creation with cryptographic randomness (32 bytes, base64url)
 * - Token validation by comparing SHA-256 hash (never stores plaintext)
 * - TTL-based expiry and max-uses enforcement
 * - Token listing (metadata only, never raw values)
 * - Token revocation by name
 *
 * All tokens have full vault access (scoped paths deferred to future iteration).
 */

import crypto from 'node:crypto';
import { VaultDatabase, type TokenRow } from './db.js';

export interface TokenCreateOptions {
  /** Human-readable name for the token (must be unique). */
  name: string;
  /** Time-to-live string (e.g. '1h', '30m', '7d'). Null = no expiry. */
  ttl?: string | null;
  /** Maximum number of times this token can be used. Null = unlimited. */
  maxUses?: number | null;
}

export interface TokenCreateResult {
  /** The raw token value (displayed once, never stored). */
  token: string;
  /** Token metadata. */
  metadata: TokenMetadata;
}

export interface TokenMetadata {
  name: string;
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  useCount: number;
  maxUses: number | null;
}

export interface TokenValidationResult {
  valid: boolean;
  reason?: 'not_found' | 'expired' | 'max_uses_exceeded';
  tokenName?: string;
}

/**
 * Generate a cryptographically random token (32 bytes, base64url encoded).
 */
export function generateAccessToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Compute the SHA-256 hash of a token for storage.
 * We never store the plaintext token — only its hash.
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf-8').digest('hex');
}

/**
 * Parse a TTL string (e.g. '1h', '30m', '7d', '90s') into milliseconds.
 * Supported suffixes: s (seconds), m (minutes), h (hours), d (days).
 *
 * Returns null if the input is null/undefined/empty.
 * Throws on invalid format.
 */
export function parseTTL(ttl: string | null | undefined): number | null {
  if (!ttl || ttl.trim().length === 0) return null;

  const match = ttl.trim().match(/^(\d+)\s*(s|m|h|d)$/i);
  if (!match) {
    throw new Error(`Invalid TTL format: '${ttl}'. Use: 30s, 10m, 1h, 7d`);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  const multipliers: Record<string, number> = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };

  return value * multipliers[unit];
}

/**
 * Token manager — handles creating, validating, listing, and revoking
 * access tokens stored in the vault database.
 */
export class TokenManager {
  private db: VaultDatabase;

  constructor(db: VaultDatabase) {
    this.db = db;
  }

  /**
   * Create a new access token.
   *
   * Generates a random 32-byte token (base64url encoded), stores its SHA-256
   * hash in the database, and returns the raw token for one-time display.
   */
  create(options: TokenCreateOptions): TokenCreateResult {
    // Validate name
    if (!options.name || options.name.trim().length === 0) {
      throw new Error('Token name cannot be empty');
    }

    // Check for duplicate name
    const existing = this.db.getTokenByName(options.name);
    if (existing) {
      throw new Error(`Token with name '${options.name}' already exists`);
    }

    // Parse TTL to compute expires_at
    let expiresAt: string | null = null;
    if (options.ttl) {
      const ttlMs = parseTTL(options.ttl);
      if (ttlMs !== null) {
        const expiresDate = new Date(Date.now() + ttlMs);
        expiresAt = expiresDate.toISOString();
      }
    }

    // Validate max_uses
    if (options.maxUses !== undefined && options.maxUses !== null) {
      if (!Number.isInteger(options.maxUses) || options.maxUses < 1) {
        throw new Error('max-uses must be a positive integer');
      }
    }

    // Generate token and hash
    const rawToken = generateAccessToken();
    const tokenHash = hashToken(rawToken);

    // Store in database
    const row = this.db.insertToken(
      options.name.trim(),
      tokenHash,
      expiresAt,
      options.maxUses ?? null,
    );

    return {
      token: rawToken,
      metadata: rowToMetadata(row),
    };
  }

  /**
   * Validate a raw token against stored hashes.
   *
   * Checks:
   * 1. Token hash exists in the database
   * 2. Token has not expired (if expires_at is set)
   * 3. Token has not exceeded max_uses (if max_uses is set)
   *
   * On successful validation, records usage (updates last_used_at and use_count).
   */
  validate(rawToken: string): TokenValidationResult {
    const tokenHash = hashToken(rawToken);
    const row = this.db.getTokenByHash(tokenHash);

    if (!row) {
      return { valid: false, reason: 'not_found' };
    }

    // Check expiry
    if (row.expires_at) {
      const expiresAt = new Date(row.expires_at);
      if (Date.now() >= expiresAt.getTime()) {
        return { valid: false, reason: 'expired', tokenName: row.name };
      }
    }

    // Check max uses
    if (row.max_uses !== null && row.use_count >= row.max_uses) {
      return { valid: false, reason: 'max_uses_exceeded', tokenName: row.name };
    }

    // Valid — record usage
    this.db.recordTokenUsage(tokenHash);

    return { valid: true, tokenName: row.name };
  }

  /**
   * List all tokens with metadata (never includes raw token values).
   */
  list(): TokenMetadata[] {
    const rows = this.db.listTokens();
    return rows.map(rowToMetadata);
  }

  /**
   * Revoke (delete) a token by name.
   * Returns true if the token was found and deleted.
   */
  revoke(name: string): boolean {
    return this.db.deleteToken(name);
  }

  /**
   * Get a token's metadata by name.
   */
  getByName(name: string): TokenMetadata | null {
    const row = this.db.getTokenByName(name);
    return row ? rowToMetadata(row) : null;
  }

  /**
   * Get the total number of tokens.
   */
  count(): number {
    return this.db.countTokens();
  }
}

/**
 * Convert a database TokenRow to a TokenMetadata object.
 */
function rowToMetadata(row: TokenRow): TokenMetadata {
  return {
    name: row.name,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastUsedAt: row.last_used_at,
    useCount: row.use_count,
    maxUses: row.max_uses,
  };
}
