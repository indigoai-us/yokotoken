/**
 * SQLite database layer for hq-vault.
 *
 * Uses sql.js (SQLite compiled to WASM) for portable, single-file database access.
 * The vault file is a single portable SQLite database.
 *
 * Because sql.js databases live in memory, this module handles file persistence:
 * - Read the .db file into a Buffer on open (if it exists)
 * - Call db.export() and write to disk after mutations
 *
 * Schema:
 * - vault_meta: stores vault configuration (salt, version, etc.)
 * - secrets: stores encrypted secret entries
 */

import initSqlJs, { type Database as SqlJsDatabase } from 'sql.js';
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
  expires_at: string | null;
  rotation_interval: string | null;
  last_rotated_at: string | null;
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
  /** Identity ID this token is bound to (for scope-based access control). Null = unscoped. */
  identity_id: string | null;
}

export interface VaultMetaRow {
  key: string;
  value: Buffer | string;
}

/** Cached sql.js SQL module (loaded once). */
let sqlJsModule: Awaited<ReturnType<typeof initSqlJs>> | null = null;

async function getSqlJs() {
  if (!sqlJsModule) {
    sqlJsModule = await initSqlJs();
  }
  return sqlJsModule;
}

export class VaultDatabase {
  private db: SqlJsDatabase;
  private dbPath: string;

  /** Use VaultDatabase.open(dbPath) instead of constructor. */
  private constructor(db: SqlJsDatabase, dbPath: string) {
    this.db = db;
    this.dbPath = dbPath;
  }

  /**
   * Open or create a vault database at the given path.
   * This is the async factory method that replaces the constructor.
   */
  static async open(dbPath: string): Promise<VaultDatabase> {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const SQL = await getSqlJs();

    let db: SqlJsDatabase;
    if (fs.existsSync(dbPath)) {
      const fileBuffer = fs.readFileSync(dbPath);
      db = new SQL.Database(fileBuffer);
    } else {
      db = new SQL.Database();
    }

    // Enforce foreign keys
    db.run('PRAGMA foreign_keys = ON');

    const instance = new VaultDatabase(db, dbPath);
    instance.initSchema();

    // Re-enable foreign keys after schema init — sql.js multi-statement
    // db.run() can reset connection-level PRAGMAs.
    db.run('PRAGMA foreign_keys = ON');

    return instance;
  }

  /**
   * Persist the in-memory database to disk.
   *
   * Note: sql.js `db.export()` resets connection-level PRAGMAs (including
   * foreign_keys) as a side-effect, so we re-enable foreign keys after export.
   */
  private save(): void {
    const data = this.db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(this.dbPath, buffer);
    this.db.run('PRAGMA foreign_keys = ON');
  }

  /**
   * Initialize database schema if tables don't exist.
   */
  private initSchema(): void {
    this.db.run(`
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
        max_uses     INTEGER,
        identity_id  TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_token_store_name ON token_store(name);
      CREATE INDEX IF NOT EXISTS idx_token_store_hash ON token_store(token_hash);
    `);

    // ── Migration: add rotation/expiry columns (US-009) ───────────────
    this.migrateRotationColumns();
    this.save();
  }

  /**
   * Add expires_at, rotation_interval, last_rotated_at columns to secrets
   * table if they don't already exist. Uses ALTER TABLE for forward compat.
   */
  private migrateRotationColumns(): void {
    // Check if columns already exist by inspecting table_info
    const stmt = this.db.prepare('PRAGMA table_info(secrets)');
    const colNames = new Set<string>();
    while (stmt.step()) {
      const row = stmt.getAsObject();
      colNames.add(row.name as string);
    }
    stmt.free();

    if (!colNames.has('expires_at')) {
      this.db.run('ALTER TABLE secrets ADD COLUMN expires_at TEXT');
    }
    if (!colNames.has('rotation_interval')) {
      this.db.run('ALTER TABLE secrets ADD COLUMN rotation_interval TEXT');
    }
    if (!colNames.has('last_rotated_at')) {
      this.db.run('ALTER TABLE secrets ADD COLUMN last_rotated_at TEXT');
    }
  }

  /**
   * Store or update a vault metadata value.
   */
  setMeta(key: string, value: Buffer | string): void {
    const valueBuf = typeof value === 'string' ? Buffer.from(value, 'utf-8') : value;
    this.db.run(
      `INSERT INTO vault_meta (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      [key, valueBuf as unknown as Uint8Array],
    );
    this.save();
  }

  /**
   * Retrieve a vault metadata value.
   */
  getMeta(key: string): Buffer | null {
    const stmt = this.db.prepare('SELECT value FROM vault_meta WHERE key = ?');
    stmt.bind([key]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return Buffer.from(row.value as Uint8Array);
    }
    stmt.free();
    return null;
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
    rotation?: {
      expires_at?: string | null;
      rotation_interval?: string | null;
      last_rotated_at?: string | null;
    },
  ): void {
    const existing = this.getSecretRow(secretPath);
    if (existing) {
      this.db.run(
        `UPDATE secrets
        SET encrypted_value = ?,
            nonce = ?,
            secret_type = COALESCE(?, secret_type),
            description = COALESCE(?, description),
            expires_at = COALESCE(?, expires_at),
            rotation_interval = COALESCE(?, rotation_interval),
            last_rotated_at = COALESCE(?, last_rotated_at),
            updated_at = datetime('now')
        WHERE path = ?`,
        [
          encryptedValue as unknown as Uint8Array,
          nonce as unknown as Uint8Array,
          secretType ?? null,
          description ?? null,
          rotation?.expires_at ?? null,
          rotation?.rotation_interval ?? null,
          rotation?.last_rotated_at ?? null,
          secretPath,
        ],
      );
    } else {
      this.db.run(
        `INSERT INTO secrets (path, encrypted_value, nonce, secret_type, description, expires_at, rotation_interval, last_rotated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          secretPath,
          encryptedValue as unknown as Uint8Array,
          nonce as unknown as Uint8Array,
          secretType ?? null,
          description ?? null,
          rotation?.expires_at ?? null,
          rotation?.rotation_interval ?? null,
          rotation?.last_rotated_at ?? null,
        ],
      );
    }
    this.save();
  }

  /**
   * Retrieve an encrypted secret row by path.
   */
  getSecretRow(secretPath: string): SecretRow | null {
    const stmt = this.db.prepare('SELECT * FROM secrets WHERE path = ?');
    stmt.bind([secretPath]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return this.toSecretRow(row);
    }
    stmt.free();
    return null;
  }

  /**
   * List all secret paths, optionally filtered by prefix.
   */
  listSecrets(prefix?: string): SecretRow[] {
    const results: SecretRow[] = [];
    let stmt;
    if (prefix) {
      stmt = this.db.prepare('SELECT * FROM secrets WHERE path LIKE ? ORDER BY path');
      stmt.bind([`${prefix}%`]);
    } else {
      stmt = this.db.prepare('SELECT * FROM secrets ORDER BY path');
    }
    while (stmt.step()) {
      results.push(this.toSecretRow(stmt.getAsObject()));
    }
    stmt.free();
    return results;
  }

  /**
   * Delete a secret by path. Returns true if a row was deleted.
   */
  deleteSecret(secretPath: string): boolean {
    const countBefore = this.countSecrets();
    this.db.run('DELETE FROM secrets WHERE path = ?', [secretPath]);
    const countAfter = this.countSecrets();
    const deleted = countAfter < countBefore;
    if (deleted) this.save();
    return deleted;
  }

  /**
   * Count total secrets in the vault.
   */
  countSecrets(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM secrets');
    stmt.step();
    const row = stmt.getAsObject();
    stmt.free();
    return row.count as number;
  }

  /**
   * Check if a secret exists at the given path.
   */
  hasSecret(secretPath: string): boolean {
    const stmt = this.db.prepare('SELECT 1 FROM secrets WHERE path = ? LIMIT 1');
    stmt.bind([secretPath]);
    const exists = stmt.step();
    stmt.free();
    return exists;
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
    identityId?: string | null,
  ): TokenRow {
    this.db.run(
      `INSERT INTO token_store (name, token_hash, expires_at, max_uses, identity_id)
      VALUES (?, ?, ?, ?, ?)`,
      [name, tokenHash, expiresAt ?? null, maxUses ?? null, identityId ?? null],
    );
    this.save();
    return this.getTokenByName(name)!;
  }

  /**
   * Find a token by its SHA-256 hash.
   */
  getTokenByHash(tokenHash: string): TokenRow | null {
    const stmt = this.db.prepare('SELECT * FROM token_store WHERE token_hash = ?');
    stmt.bind([tokenHash]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return this.toTokenRow(row);
    }
    stmt.free();
    return null;
  }

  /**
   * Find a token by name.
   */
  getTokenByName(name: string): TokenRow | null {
    const stmt = this.db.prepare('SELECT * FROM token_store WHERE name = ?');
    stmt.bind([name]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return this.toTokenRow(row);
    }
    stmt.free();
    return null;
  }

  /**
   * List all tokens (metadata only).
   */
  listTokens(): TokenRow[] {
    const results: TokenRow[] = [];
    const stmt = this.db.prepare('SELECT * FROM token_store ORDER BY created_at DESC');
    while (stmt.step()) {
      results.push(this.toTokenRow(stmt.getAsObject()));
    }
    stmt.free();
    return results;
  }

  /**
   * Update the last_used_at timestamp and increment use_count for a token.
   */
  recordTokenUsage(tokenHash: string): void {
    this.db.run(
      `UPDATE token_store
      SET last_used_at = datetime('now'),
          use_count = use_count + 1
      WHERE token_hash = ?`,
      [tokenHash],
    );
    this.save();
  }

  /**
   * Delete a token by name. Returns true if a row was deleted.
   */
  deleteToken(name: string): boolean {
    const before = this.countTokens();
    this.db.run('DELETE FROM token_store WHERE name = ?', [name]);
    const after = this.countTokens();
    const deleted = after < before;
    if (deleted) this.save();
    return deleted;
  }

  /**
   * Count total tokens in the store.
   */
  countTokens(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM token_store');
    stmt.step();
    const row = stmt.getAsObject();
    stmt.free();
    return row.count as number;
  }

  // ─── Rotation / Expiry queries (US-009) ─────────────────────────

  /**
   * List secrets that expire before the given ISO 8601 deadline.
   * Only returns rows where expires_at is non-null.
   */
  listExpiringSecrets(beforeIso: string): SecretRow[] {
    const results: SecretRow[] = [];
    const stmt = this.db.prepare(
      `SELECT * FROM secrets
       WHERE expires_at IS NOT NULL
         AND expires_at <= ?
         AND path != '__vault_verify__'
       ORDER BY expires_at ASC`,
    );
    stmt.bind([beforeIso]);
    while (stmt.step()) {
      results.push(this.toSecretRow(stmt.getAsObject()));
    }
    stmt.free();
    return results;
  }

  /**
   * List secrets that are past their rotation interval.
   */
  listSecretsWithRotationInterval(): SecretRow[] {
    const results: SecretRow[] = [];
    const stmt = this.db.prepare(
      `SELECT * FROM secrets
       WHERE rotation_interval IS NOT NULL
         AND path != '__vault_verify__'
       ORDER BY path ASC`,
    );
    while (stmt.step()) {
      results.push(this.toSecretRow(stmt.getAsObject()));
    }
    stmt.free();
    return results;
  }

  /**
   * Update rotation metadata for a secret (e.g., after rotation).
   */
  updateRotationFields(
    secretPath: string,
    fields: {
      expires_at?: string | null;
      rotation_interval?: string | null;
      last_rotated_at?: string | null;
    },
  ): void {
    const sets: string[] = [];
    const params: (string | null)[] = [];

    if (fields.expires_at !== undefined) {
      sets.push('expires_at = ?');
      params.push(fields.expires_at);
    }
    if (fields.rotation_interval !== undefined) {
      sets.push('rotation_interval = ?');
      params.push(fields.rotation_interval);
    }
    if (fields.last_rotated_at !== undefined) {
      sets.push('last_rotated_at = ?');
      params.push(fields.last_rotated_at);
    }

    if (sets.length === 0) return;

    sets.push("updated_at = datetime('now')");
    params.push(secretPath);

    this.db.run(
      `UPDATE secrets SET ${sets.join(', ')} WHERE path = ?`,
      params,
    );
    this.save();
  }

  /**
   * Get the underlying sql.js database. Used by AccessRequestManager
   * that needs direct access to the same connection.
   */
  getRawDb(): SqlJsDatabase {
    return this.db;
  }

  /**
   * Save pending changes to disk. Exposed for modules that use getRawDb()
   * to write directly and then need to persist.
   */
  persist(): void {
    this.save();
  }

  /**
   * Close the database connection.
   */
  close(): void {
    try {
      this.save();
    } catch {
      // best effort save on close
    }
    this.db.close();
  }

  // ─── Row mapping helpers ──────────────────────────────────────────

  private toSecretRow(row: Record<string, unknown>): SecretRow {
    return {
      id: row.id as number,
      path: row.path as string,
      encrypted_value: Buffer.from(row.encrypted_value as Uint8Array),
      nonce: Buffer.from(row.nonce as Uint8Array),
      secret_type: (row.secret_type as string) ?? null,
      description: (row.description as string) ?? null,
      created_at: row.created_at as string,
      updated_at: row.updated_at as string,
      expires_at: (row.expires_at as string) ?? null,
      rotation_interval: (row.rotation_interval as string) ?? null,
      last_rotated_at: (row.last_rotated_at as string) ?? null,
    };
  }

  private toTokenRow(row: Record<string, unknown>): TokenRow {
    return {
      id: row.id as number,
      name: row.name as string,
      token_hash: row.token_hash as string,
      created_at: row.created_at as string,
      expires_at: (row.expires_at as string) ?? null,
      last_used_at: (row.last_used_at as string) ?? null,
      use_count: row.use_count as number,
      max_uses: (row.max_uses as number) ?? null,
      identity_id: (row.identity_id as string) ?? null,
    };
  }
}
