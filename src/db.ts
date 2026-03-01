/**
 * SQLite database layer for hq-vault.
 *
 * Uses better-sqlite3 for synchronous, single-file database access.
 * The vault file is a single portable SQLite database.
 *
 * Schema:
 * - vault_meta: stores vault configuration (salt, version, etc.)
 * - secrets: stores encrypted secret entries
 */

import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

export interface SecretRow {
  id: number;
  path: string;
  encrypted_value: Buffer;
  nonce: Buffer;
  secret_type: string | null;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface TokenRow {
  id: number;
  name: string;
  token_hash: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  use_count: number;
  max_uses: number | null;
}

export interface VaultMetaRow {
  key: string;
  value: Buffer | string;
}

export class VaultDatabase {
  private db: Database.Database;

  constructor(dbPath: string) {
    // Ensure the directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(dbPath);

    // Enable WAL mode for better concurrency
    this.db.pragma('journal_mode = WAL');
    // Enforce foreign keys
    this.db.pragma('foreign_keys = ON');

    this.initSchema();
  }

  /**
   * Initialize database schema if tables don't exist.
   */
  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_meta (
        key   TEXT PRIMARY KEY,
        value BLOB NOT NULL
      );

      CREATE TABLE IF NOT EXISTS secrets (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        path            TEXT NOT NULL UNIQUE,
        encrypted_value BLOB NOT NULL,
        nonce           BLOB NOT NULL,
        secret_type     TEXT,
        description     TEXT,
        created_at      TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_secrets_path ON secrets(path);

      CREATE TABLE IF NOT EXISTS token_store (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT NOT NULL UNIQUE,
        token_hash   TEXT NOT NULL,
        created_at   TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at   TEXT,
        last_used_at TEXT,
        use_count    INTEGER NOT NULL DEFAULT 0,
        max_uses     INTEGER
      );

      CREATE INDEX IF NOT EXISTS idx_token_store_name ON token_store(name);
      CREATE INDEX IF NOT EXISTS idx_token_store_hash ON token_store(token_hash);
    `);
  }

  /**
   * Store or update a vault metadata value.
   */
  setMeta(key: string, value: Buffer | string): void {
    const valueBuf = typeof value === 'string' ? Buffer.from(value, 'utf-8') : value;
    this.db.prepare(`
      INSERT INTO vault_meta (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(key, valueBuf);
  }

  /**
   * Retrieve a vault metadata value.
   */
  getMeta(key: string): Buffer | null {
    const row = this.db.prepare(
      'SELECT value FROM vault_meta WHERE key = ?'
    ).get(key) as { value: Buffer } | undefined;
    return row ? row.value : null;
  }

  /**
   * Store a new encrypted secret or update an existing one.
   */
  storeSecret(
    secretPath: string,
    encryptedValue: Buffer,
    nonce: Buffer,
    secretType?: string,
    description?: string,
  ): void {
    this.db.prepare(`
      INSERT INTO vault_meta (key, value) VALUES ('_noop', X'00')
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(); // no-op to ensure transaction works

    const existing = this.getSecretRow(secretPath);
    if (existing) {
      this.db.prepare(`
        UPDATE secrets
        SET encrypted_value = ?,
            nonce = ?,
            secret_type = COALESCE(?, secret_type),
            description = COALESCE(?, description),
            updated_at = datetime('now')
        WHERE path = ?
      `).run(encryptedValue, nonce, secretType ?? null, description ?? null, secretPath);
    } else {
      this.db.prepare(`
        INSERT INTO secrets (path, encrypted_value, nonce, secret_type, description)
        VALUES (?, ?, ?, ?, ?)
      `).run(secretPath, encryptedValue, nonce, secretType ?? null, description ?? null);
    }

    // Clean up no-op meta entry
    this.db.prepare("DELETE FROM vault_meta WHERE key = '_noop'").run();
  }

  /**
   * Retrieve an encrypted secret row by path.
   */
  getSecretRow(secretPath: string): SecretRow | null {
    const row = this.db.prepare(
      'SELECT * FROM secrets WHERE path = ?'
    ).get(secretPath) as SecretRow | undefined;
    return row ?? null;
  }

  /**
   * List all secret paths, optionally filtered by prefix.
   */
  listSecrets(prefix?: string): SecretRow[] {
    if (prefix) {
      return this.db.prepare(
        'SELECT * FROM secrets WHERE path LIKE ? ORDER BY path'
      ).all(`${prefix}%`) as SecretRow[];
    }
    return this.db.prepare(
      'SELECT * FROM secrets ORDER BY path'
    ).all() as SecretRow[];
  }

  /**
   * Delete a secret by path. Returns true if a row was deleted.
   */
  deleteSecret(secretPath: string): boolean {
    const result = this.db.prepare(
      'DELETE FROM secrets WHERE path = ?'
    ).run(secretPath);
    return result.changes > 0;
  }

  /**
   * Count total secrets in the vault.
   */
  countSecrets(): number {
    const row = this.db.prepare(
      'SELECT COUNT(*) as count FROM secrets'
    ).get() as { count: number };
    return row.count;
  }

  /**
   * Check if a secret exists at the given path.
   */
  hasSecret(secretPath: string): boolean {
    const row = this.db.prepare(
      'SELECT 1 FROM secrets WHERE path = ? LIMIT 1'
    ).get(secretPath);
    return row !== undefined;
  }

  // ─── Token store methods ──────────────────────────────────────────

  /**
   * Insert a new token record. Returns the inserted row.
   */
  insertToken(
    name: string,
    tokenHash: string,
    expiresAt?: string | null,
    maxUses?: number | null,
  ): TokenRow {
    this.db.prepare(`
      INSERT INTO token_store (name, token_hash, expires_at, max_uses)
      VALUES (?, ?, ?, ?)
    `).run(name, tokenHash, expiresAt ?? null, maxUses ?? null);

    return this.getTokenByName(name)!;
  }

  /**
   * Find a token by its SHA-256 hash.
   */
  getTokenByHash(tokenHash: string): TokenRow | null {
    const row = this.db.prepare(
      'SELECT * FROM token_store WHERE token_hash = ?'
    ).get(tokenHash) as TokenRow | undefined;
    return row ?? null;
  }

  /**
   * Find a token by name.
   */
  getTokenByName(name: string): TokenRow | null {
    const row = this.db.prepare(
      'SELECT * FROM token_store WHERE name = ?'
    ).get(name) as TokenRow | undefined;
    return row ?? null;
  }

  /**
   * List all tokens (metadata only).
   */
  listTokens(): TokenRow[] {
    return this.db.prepare(
      'SELECT * FROM token_store ORDER BY created_at DESC'
    ).all() as TokenRow[];
  }

  /**
   * Update the last_used_at timestamp and increment use_count for a token.
   */
  recordTokenUsage(tokenHash: string): void {
    this.db.prepare(`
      UPDATE token_store
      SET last_used_at = datetime('now'),
          use_count = use_count + 1
      WHERE token_hash = ?
    `).run(tokenHash);
  }

  /**
   * Delete a token by name. Returns true if a row was deleted.
   */
  deleteToken(name: string): boolean {
    const result = this.db.prepare(
      'DELETE FROM token_store WHERE name = ?'
    ).run(name);
    return result.changes > 0;
  }

  /**
   * Count total tokens in the store.
   */
  countTokens(): number {
    const row = this.db.prepare(
      'SELECT COUNT(*) as count FROM token_store'
    ).get() as { count: number };
    return row.count;
  }

  /**
   * Close the database connection.
   */
  close(): void {
    this.db.close();
  }
}
