/**
 * Vault engine — the unified API that ties crypto and database together.
 *
 * Manages the full lifecycle:
 * - Initialize a new vault with a passphrase
 * - Unlock/lock the vault
 * - Store, retrieve, list, and delete secrets
 *
 * The master key is derived from the passphrase via Argon2id and held in
 * memory only while the vault is unlocked. All secrets are encrypted with
 * XChaCha20-Poly1305 before touching the database.
 */

import { VaultDatabase, type SecretRow } from './db.js';
import {
  deriveMasterKey,
  encrypt,
  decrypt,
  generateSalt,
  secureZero,
  SALT_BYTES,
} from './crypto.js';

// ─── Duration parsing helpers (US-009) ────────────────────────────

/**
 * Parse a human-friendly duration string into milliseconds.
 * Supports: '30d', '90d', '24h', '1w', '7d', etc.
 * Returns null if the format is not recognized.
 */
export function parseDuration(input: string): number | null {
  const match = input.trim().match(/^(\d+)\s*(d|h|w|m|s)$/i);
  if (!match) return null;

  const value = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case 's': return value * 1000;
    case 'm': return value * 60 * 1000;
    case 'h': return value * 60 * 60 * 1000;
    case 'd': return value * 24 * 60 * 60 * 1000;
    case 'w': return value * 7 * 24 * 60 * 60 * 1000;
    default: return null;
  }
}

/**
 * Parse a datetime string as UTC.
 */
function parseUtcDate(dateStr: string): number {
  if (dateStr.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(dateStr) || dateStr.includes('T')) {
    return new Date(dateStr).getTime();
  }
  return new Date(dateStr + 'Z').getTime();
}

/**
 * Determine if a secret row is "stale" — past its rotation interval.
 */
function isStale(row: SecretRow, nowMs: number): boolean {
  if (!row.rotation_interval) return false;

  const intervalMs = parseDuration(row.rotation_interval);
  if (!intervalMs) return false;

  const baseTime = row.last_rotated_at
    ? parseUtcDate(row.last_rotated_at)
    : parseUtcDate(row.created_at);

  return (baseTime + intervalMs) < nowMs;
}

export interface SecretMetadata {
  type?: string;
  description?: string;
  expires_at?: string;
  rotation_interval?: string;
  last_rotated_at?: string;
}

export interface SecretEntry {
  path: string;
  value: string;
  metadata: SecretMetadata;
  createdAt: string;
  updatedAt: string;
  expired?: boolean;
  stale?: boolean;
}

export interface SecretListEntry {
  path: string;
  metadata: SecretMetadata;
  createdAt: string;
  updatedAt: string;
  expired?: boolean;
  stale?: boolean;
}

export interface VaultStatus {
  initialized: boolean;
  locked: boolean;
  secretCount: number;
  vaultPath: string;
}

export class VaultEngine {
  private db: VaultDatabase;
  private masterKey: Buffer | null = null;
  private vaultPath: string;

  /** Use VaultEngine.open(dbPath) instead. */
  private constructor(db: VaultDatabase, dbPath: string) {
    this.vaultPath = dbPath;
    this.db = db;
  }

  /**
   * Open or create a vault engine at the given path.
   */
  static async open(dbPath: string): Promise<VaultEngine> {
    const db = await VaultDatabase.open(dbPath);
    return new VaultEngine(db, dbPath);
  }

  /**
   * Initialize a new vault with a passphrase.
   */
  async init(passphrase: string): Promise<void> {
    const existingSalt = this.db.getMeta('salt');
    if (existingSalt) {
      throw new Error(
        'Vault is already initialized. Use unlock() to access it.'
      );
    }

    const salt = await generateSalt();
    this.db.setMeta('salt', salt);
    this.db.setMeta('version', '1');

    // Derive and hold the master key
    this.masterKey = await deriveMasterKey(passphrase, salt);

    // Store a verification entry so we can validate passphrases on unlock
    const verifyPlaintext = Buffer.from('hq-vault-ok', 'utf-8');
    const { ciphertext, nonce } = await encrypt(verifyPlaintext, this.masterKey);
    this.db.storeSecret('__vault_verify__', ciphertext, nonce, 'system', 'Vault verification entry');
  }

  /**
   * Unlock the vault by deriving the master key from the passphrase.
   */
  async unlock(passphrase: string): Promise<void> {
    const salt = this.db.getMeta('salt');
    if (!salt) {
      throw new Error('Vault is not initialized. Run init() first.');
    }
    if (salt.length !== SALT_BYTES) {
      throw new Error('Corrupt vault: invalid salt length');
    }

    const candidateKey = await deriveMasterKey(passphrase, salt);

    // Verify the passphrase against the verification entry stored during init()
    const verifyRow = this.db.getSecretRow('__vault_verify__');
    if (!verifyRow) {
      await secureZero(candidateKey);
      throw new Error('Corrupt vault: missing verification entry');
    }

    try {
      const decrypted = await decrypt(
        verifyRow.encrypted_value,
        verifyRow.nonce,
        candidateKey,
      );
      const text = decrypted.toString('utf-8');
      if (text !== 'hq-vault-ok') {
        await secureZero(candidateKey);
        throw new Error('Invalid passphrase');
      }
    } catch (err) {
      await secureZero(candidateKey);
      if (err instanceof Error && err.message === 'Invalid passphrase') {
        throw err;
      }
      throw new Error('Invalid passphrase');
    }

    // Wipe old key if any
    if (this.masterKey) {
      await secureZero(this.masterKey);
    }
    this.masterKey = candidateKey;
  }

  /**
   * Lock the vault by securely wiping the master key from memory.
   */
  async lock(): Promise<void> {
    if (this.masterKey) {
      await secureZero(this.masterKey);
      this.masterKey = null;
    }
  }

  /**
   * Check if the vault is currently unlocked.
   */
  get isUnlocked(): boolean {
    return this.masterKey !== null;
  }

  /**
   * Check if the vault has been initialized.
   */
  get isInitialized(): boolean {
    return this.db.getMeta('salt') !== null;
  }

  /**
   * Ensure the vault is unlocked before performing operations.
   */
  private requireUnlocked(): Buffer {
    if (!this.masterKey) {
      throw new Error('Vault is locked. Unlock it first.');
    }
    return this.masterKey;
  }

  /**
   * Store a secret at the given path.
   */
  async store(
    secretPath: string,
    value: string,
    metadata?: SecretMetadata,
  ): Promise<void> {
    const key = this.requireUnlocked();
    this.validatePath(secretPath);

    const plaintext = Buffer.from(value, 'utf-8');
    const { ciphertext, nonce } = await encrypt(plaintext, key);

    this.db.storeSecret(
      secretPath,
      ciphertext,
      nonce,
      metadata?.type,
      metadata?.description,
      {
        expires_at: metadata?.expires_at ?? null,
        rotation_interval: metadata?.rotation_interval ?? null,
        last_rotated_at: metadata?.last_rotated_at ?? null,
      },
    );
  }

  /**
   * Retrieve and decrypt a secret at the given path.
   */
  async get(secretPath: string): Promise<SecretEntry | null> {
    const key = this.requireUnlocked();
    this.validatePath(secretPath);

    const row = this.db.getSecretRow(secretPath);
    if (!row) {
      return null;
    }

    const decrypted = await decrypt(row.encrypted_value, row.nonce, key);

    const now = Date.now();
    const expired = row.expires_at ? parseUtcDate(row.expires_at) < now : false;
    const stale = isStale(row, now);

    return {
      path: row.path,
      value: decrypted.toString('utf-8'),
      metadata: {
        type: row.secret_type ?? undefined,
        description: row.description ?? undefined,
        expires_at: row.expires_at ?? undefined,
        rotation_interval: row.rotation_interval ?? undefined,
        last_rotated_at: row.last_rotated_at ?? undefined,
      },
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      expired,
      stale,
    };
  }

  /**
   * List secrets, optionally filtered by path prefix.
   * Returns metadata only — NOT decrypted values.
   */
  list(prefix?: string): SecretListEntry[] {
    this.requireUnlocked();

    const now = Date.now();
    const rows = this.db.listSecrets(prefix);
    return rows
      .filter(row => row.path !== '__vault_verify__')
      .map(row => ({
        path: row.path,
        metadata: {
          type: row.secret_type ?? undefined,
          description: row.description ?? undefined,
          expires_at: row.expires_at ?? undefined,
          rotation_interval: row.rotation_interval ?? undefined,
          last_rotated_at: row.last_rotated_at ?? undefined,
        },
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        expired: row.expires_at ? parseUtcDate(row.expires_at) < now : false,
        stale: isStale(row, now),
      }));
  }

  /**
   * Delete a secret at the given path.
   */
  delete(secretPath: string): boolean {
    this.requireUnlocked();
    this.validatePath(secretPath);

    if (secretPath === '__vault_verify__') {
      throw new Error('Cannot delete the vault verification entry');
    }

    return this.db.deleteSecret(secretPath);
  }

  /**
   * Get vault status information.
   */
  status(): VaultStatus {
    const totalCount = this.db.countSecrets();
    const hasVerify = this.db.hasSecret('__vault_verify__');
    const userSecretCount = hasVerify ? totalCount - 1 : totalCount;

    return {
      initialized: this.isInitialized,
      locked: !this.isUnlocked,
      secretCount: userSecretCount,
      vaultPath: this.vaultPath,
    };
  }

  // ─── Rotation / Expiry queries (US-009) ─────────────────────────

  /**
   * List secrets expiring within the given time window.
   */
  expiringSecrets(withinMs: number = 7 * 24 * 60 * 60 * 1000): SecretListEntry[] {
    this.requireUnlocked();

    const deadline = new Date(Date.now() + withinMs).toISOString();
    const now = Date.now();
    const rows = this.db.listExpiringSecrets(deadline);

    return rows.map(row => ({
      path: row.path,
      metadata: {
        type: row.secret_type ?? undefined,
        description: row.description ?? undefined,
        expires_at: row.expires_at ?? undefined,
        rotation_interval: row.rotation_interval ?? undefined,
        last_rotated_at: row.last_rotated_at ?? undefined,
      },
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      expired: row.expires_at ? parseUtcDate(row.expires_at) < now : false,
      stale: isStale(row, now),
    }));
  }

  /**
   * List secrets that are past their rotation interval (stale).
   */
  staleSecrets(): SecretListEntry[] {
    this.requireUnlocked();

    const now = Date.now();
    const rows = this.db.listSecretsWithRotationInterval();

    return rows
      .filter(row => isStale(row, now))
      .map(row => ({
        path: row.path,
        metadata: {
          type: row.secret_type ?? undefined,
          description: row.description ?? undefined,
          expires_at: row.expires_at ?? undefined,
          rotation_interval: row.rotation_interval ?? undefined,
          last_rotated_at: row.last_rotated_at ?? undefined,
        },
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        expired: row.expires_at ? parseUtcDate(row.expires_at) < now : false,
        stale: true,
      }));
  }

  /**
   * Get the underlying database (for token manager, etc.).
   */
  getDb(): VaultDatabase {
    return this.db;
  }

  /**
   * Close the vault, securely wiping the key and closing the database.
   */
  async close(): Promise<void> {
    await this.lock();
    this.db.close();
  }

  /**
   * Validate a secret path.
   */
  private validatePath(secretPath: string): void {
    if (!secretPath || secretPath.trim().length === 0) {
      throw new Error('Secret path cannot be empty');
    }
    if (secretPath.startsWith('__vault')) {
      throw new Error('Paths starting with __vault are reserved');
    }
    if (secretPath.startsWith('/') || secretPath.endsWith('/')) {
      throw new Error('Secret path must not start or end with /');
    }
    if (secretPath.includes('//')) {
      throw new Error('Secret path must not contain consecutive slashes');
    }
  }
}
