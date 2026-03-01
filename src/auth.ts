/**
 * Authentication module for hq-vault server.
 *
 * Provides:
 * - Bearer token generation and file-based storage
 * - Token validation from Authorization headers
 * - Rate limiting for failed auth attempts (10 failures/min -> 5-min lockout)
 *
 * The server token is generated on first `hq-vault serve` and stored in
 * ~/.hq-vault/token. Clients read this file to authenticate.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// ─── Token management ────────────────────────────────────────────────

/**
 * Generate a cryptographically random bearer token (32 bytes, base64url).
 */
export function generateToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Get the default token file path.
 */
export function getDefaultTokenFile(): string {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  return path.join(home, '.hq-vault', 'token');
}

/**
 * Write a token to the token file with restrictive permissions.
 */
export function writeTokenFile(tokenFile: string, token: string): void {
  const dir = path.dirname(tokenFile);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  // Write with restrictive permissions (owner-only read/write)
  fs.writeFileSync(tokenFile, token, { encoding: 'utf-8', mode: 0o600 });
}

/**
 * Read a token from the token file.
 */
export function readTokenFile(tokenFile: string): string | null {
  if (!fs.existsSync(tokenFile)) {
    return null;
  }
  return fs.readFileSync(tokenFile, 'utf-8').trim();
}

/**
 * Validate an Authorization header against the expected token.
 * Returns true if the token matches.
 *
 * Uses timing-safe comparison to prevent timing attacks.
 */
export function validateBearerToken(
  authHeader: string | undefined,
  expectedToken: string,
): boolean {
  if (!authHeader) return false;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return false;

  const provided = parts[1];
  if (provided.length !== expectedToken.length) return false;

  // Timing-safe comparison
  const a = Buffer.from(provided, 'utf-8');
  const b = Buffer.from(expectedToken, 'utf-8');
  if (a.length !== b.length) return false;

  return crypto.timingSafeEqual(a, b);
}

// ─── Rate limiting ───────────────────────────────────────────────────

export interface RateLimitConfig {
  maxFailures: number;     // Max failed attempts before lockout (default: 10)
  windowMs: number;        // Time window for counting failures (default: 60000 = 1 min)
  lockoutMs: number;       // Lockout duration after exceeding limit (default: 300000 = 5 min)
}

export const DEFAULT_RATE_LIMIT: RateLimitConfig = {
  maxFailures: 10,
  windowMs: 60 * 1000,        // 1 minute
  lockoutMs: 5 * 60 * 1000,   // 5 minutes
};

interface FailureRecord {
  timestamps: number[];    // Timestamps of recent failures
  lockedUntil: number;     // 0 if not locked, timestamp if locked
}

/**
 * Rate limiter that tracks failed auth attempts per IP address.
 *
 * After `maxFailures` failures within `windowMs`, the IP is locked out
 * for `lockoutMs`.
 */
export class RateLimiter {
  private failures: Map<string, FailureRecord> = new Map();
  private config: RateLimitConfig;

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = { ...DEFAULT_RATE_LIMIT, ...config };
  }

  /**
   * Check if an IP is currently locked out.
   * Returns the remaining lockout time in ms, or 0 if not locked.
   */
  isLocked(ip: string): number {
    const record = this.failures.get(ip);
    if (!record) return 0;

    const now = Date.now();
    if (record.lockedUntil > now) {
      return record.lockedUntil - now;
    }

    // Lockout expired
    if (record.lockedUntil > 0) {
      record.lockedUntil = 0;
      record.timestamps = [];
    }

    return 0;
  }

  /**
   * Record a failed auth attempt for an IP.
   * Returns true if the IP is now locked out.
   */
  recordFailure(ip: string): boolean {
    const now = Date.now();
    let record = this.failures.get(ip);

    if (!record) {
      record = { timestamps: [], lockedUntil: 0 };
      this.failures.set(ip, record);
    }

    // If already locked, extend the lockout
    if (record.lockedUntil > now) {
      return true;
    }

    // Add the failure timestamp
    record.timestamps.push(now);

    // Prune old timestamps outside the window
    const windowStart = now - this.config.windowMs;
    record.timestamps = record.timestamps.filter(t => t >= windowStart);

    // Check if we've exceeded the limit
    if (record.timestamps.length >= this.config.maxFailures) {
      record.lockedUntil = now + this.config.lockoutMs;
      record.timestamps = [];
      return true;
    }

    return false;
  }

  /**
   * Record a successful auth (clear failures for IP).
   */
  recordSuccess(ip: string): void {
    this.failures.delete(ip);
  }

  /**
   * Get the number of recent failures for an IP (for testing).
   */
  getFailureCount(ip: string): number {
    const record = this.failures.get(ip);
    if (!record) return 0;

    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    return record.timestamps.filter(t => t >= windowStart).length;
  }

  /**
   * Reset all rate limit state (for testing).
   */
  reset(): void {
    this.failures.clear();
  }
}
