/**
 * Vault backup and migration module (US-011).
 *
 * Provides:
 * - Encrypted backup/restore of the vault database
 * - Export secrets to .env format
 * - Import secrets from .env files with duplicate detection
 *
 * Backup format:
 * - 4-byte magic: "HQVB"
 * - 1-byte version: 0x01
 * - 16-byte salt (for Argon2id key derivation)
 * - 24-byte nonce (for XChaCha20-Poly1305)
 * - Remaining bytes: encrypted SQLite file (ciphertext + 16-byte MAC)
 *
 * The entire SQLite database is encrypted as a single blob, making the backup
 * file fully opaque without the master passphrase.
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  deriveMasterKey,
  encrypt,
  decrypt,
  generateSalt,
  secureZero,
  SALT_BYTES,
  NONCE_BYTES,
} from './crypto.js';
import { VaultEngine } from './vault.js';

/** Magic bytes identifying an hq-vault backup file. */
export const BACKUP_MAGIC = Buffer.from('HQVB', 'ascii');

/** Current backup format version. */
export const BACKUP_VERSION = 0x01;

/** Total header size: 4 (magic) + 1 (version) + 16 (salt) + 24 (nonce) = 45 bytes. */
export const BACKUP_HEADER_SIZE = BACKUP_MAGIC.length + 1 + SALT_BYTES + NONCE_BYTES;

export interface BackupResult {
  success: boolean;
  filepath: string;
  sizeBytes: number;
}

export interface RestoreResult {
  success: boolean;
  restoredPath: string;
  secretCount: number;
}

export interface ExportResult {
  success: boolean;
  entryCount: number;
  output: string;
}

export type ImportConflictStrategy = 'skip' | 'overwrite' | 'rename';

export interface ImportDuplicate {
  path: string;
  strategy: ImportConflictStrategy;
}

export interface ImportResult {
  success: boolean;
  imported: number;
  skipped: number;
  overwritten: number;
  renamed: number;
  errors: string[];
}

export interface EnvEntry {
  key: string;
  value: string;
}

/**
 * Create an encrypted backup of the vault database.
 *
 * The backup is encrypted with a key derived from the master passphrase
 * using a fresh salt, making it safe to store in cloud storage or git.
 *
 * @param vaultDbPath - Path to the vault SQLite database
 * @param backupPath  - Destination path for the backup file
 * @param passphrase  - Master passphrase (used to encrypt the backup)
 */
export function createBackup(
  vaultDbPath: string,
  backupPath: string,
  passphrase: string,
): BackupResult {
  if (!fs.existsSync(vaultDbPath)) {
    throw new Error(`Vault database not found: ${vaultDbPath}`);
  }

  if (!passphrase || passphrase.length === 0) {
    throw new Error('Passphrase cannot be empty');
  }

  // Read the raw SQLite database file
  const dbData = fs.readFileSync(vaultDbPath);

  // Generate a fresh salt for this backup
  const salt = generateSalt();

  // Derive encryption key from passphrase
  const key = deriveMasterKey(passphrase, salt);

  try {
    // Encrypt the entire database
    const { ciphertext, nonce } = encrypt(dbData, key);

    // Build the backup file: magic + version + salt + nonce + ciphertext
    const header = Buffer.alloc(BACKUP_MAGIC.length + 1);
    BACKUP_MAGIC.copy(header, 0);
    header.writeUInt8(BACKUP_VERSION, BACKUP_MAGIC.length);

    const backup = Buffer.concat([header, salt, nonce, ciphertext]);

    // Ensure output directory exists
    const dir = path.dirname(backupPath);
    if (dir && !fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(backupPath, backup);

    return {
      success: true,
      filepath: backupPath,
      sizeBytes: backup.length,
    };
  } finally {
    secureZero(key);
  }
}

/**
 * Restore a vault from an encrypted backup file.
 *
 * The backup is decrypted using the master passphrase and written to
 * the target vault path. The original vault at restorePath is replaced.
 *
 * @param backupPath  - Path to the encrypted backup file
 * @param restorePath - Destination path for the restored vault database
 * @param passphrase  - Master passphrase (used to decrypt the backup)
 */
export function restoreBackup(
  backupPath: string,
  restorePath: string,
  passphrase: string,
): RestoreResult {
  if (!fs.existsSync(backupPath)) {
    throw new Error(`Backup file not found: ${backupPath}`);
  }

  if (!passphrase || passphrase.length === 0) {
    throw new Error('Passphrase cannot be empty');
  }

  const backupData = fs.readFileSync(backupPath);

  // Validate minimum size
  if (backupData.length < BACKUP_HEADER_SIZE) {
    throw new Error('Invalid backup file: too small');
  }

  // Validate magic bytes
  const magic = backupData.subarray(0, BACKUP_MAGIC.length);
  if (!magic.equals(BACKUP_MAGIC)) {
    throw new Error('Invalid backup file: wrong magic bytes (not an hq-vault backup)');
  }

  // Read version
  const version = backupData.readUInt8(BACKUP_MAGIC.length);
  if (version !== BACKUP_VERSION) {
    throw new Error(`Unsupported backup version: ${version} (expected ${BACKUP_VERSION})`);
  }

  // Extract salt, nonce, and ciphertext
  let offset = BACKUP_MAGIC.length + 1;
  const salt = backupData.subarray(offset, offset + SALT_BYTES);
  offset += SALT_BYTES;
  const nonce = backupData.subarray(offset, offset + NONCE_BYTES);
  offset += NONCE_BYTES;
  const ciphertext = backupData.subarray(offset);

  // Derive decryption key
  const key = deriveMasterKey(passphrase, Buffer.from(salt));

  let dbData: Buffer;
  try {
    dbData = decrypt(Buffer.from(ciphertext), Buffer.from(nonce), key);
  } catch {
    secureZero(key);
    throw new Error('Failed to decrypt backup: invalid passphrase or corrupted file');
  }

  secureZero(key);

  // Write the decrypted database to the restore path
  const dir = path.dirname(restorePath);
  if (dir && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Remove WAL and SHM files if they exist (clean restore)
  const walPath = restorePath + '-wal';
  const shmPath = restorePath + '-shm';
  if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);

  fs.writeFileSync(restorePath, dbData);

  // Open the restored vault to verify and count secrets
  const vault = new VaultEngine(restorePath);
  let secretCount = 0;
  try {
    vault.unlock(passphrase);
    const entries = vault.list();
    secretCount = entries.length;
  } finally {
    vault.close();
  }

  return {
    success: true,
    restoredPath: restorePath,
    secretCount,
  };
}

/**
 * Export all secrets from the vault as .env format.
 *
 * Requires the vault to be unlocked (caller provides an unlocked VaultEngine).
 * Secret paths are converted to environment variable names:
 * - Slashes become underscores
 * - Dashes become underscores
 * - Dots become underscores
 * - Result is uppercased
 *
 * @param vault - An unlocked VaultEngine instance
 * @param prefix - Optional prefix filter (only export secrets matching this prefix)
 */
export function exportEnv(
  vault: VaultEngine,
  prefix?: string,
): ExportResult {
  if (!vault.isUnlocked) {
    throw new Error('Vault is locked. Unlock it first.');
  }

  const entries = vault.list(prefix);
  const lines: string[] = [];

  for (const entry of entries) {
    const secret = vault.get(entry.path);
    if (!secret) continue;

    // Convert path to env var name
    const varName = pathToEnvName(entry.path, prefix);
    if (!varName) continue;

    // Escape the value for .env format
    const escaped = secret.value
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n');

    // Add description as comment if present
    if (entry.metadata?.description) {
      lines.push(`# ${entry.metadata.description}`);
    }

    lines.push(`${varName}="${escaped}"`);
  }

  const output = lines.join('\n') + (lines.length > 0 ? '\n' : '');

  return {
    success: true,
    entryCount: entries.length,
    output,
  };
}

/**
 * Convert a vault secret path to an environment variable name.
 *
 * Examples:
 * - "aws/dev/access-key"      -> "AWS_DEV_ACCESS_KEY"
 * - "slack/indigo/bot-token"   -> "SLACK_INDIGO_BOT_TOKEN"
 * - With prefix "aws/": "aws/dev/access-key" -> "DEV_ACCESS_KEY"
 */
export function pathToEnvName(secretPath: string, prefix?: string): string {
  let relative = secretPath;
  if (prefix && relative.startsWith(prefix)) {
    relative = relative.slice(prefix.length);
  }
  // Remove leading slash if any
  if (relative.startsWith('/')) {
    relative = relative.slice(1);
  }
  return relative
    .replace(/[/\-\.]/g, '_')
    .toUpperCase();
}

/**
 * Parse a .env file into key-value entries.
 *
 * Supports:
 * - KEY=value (unquoted)
 * - KEY="value" (double-quoted, with escape sequences)
 * - KEY='value' (single-quoted, literal)
 * - Comments (# ...) and blank lines are skipped
 * - export KEY=value prefix is stripped
 */
export function parseEnvFile(content: string): EnvEntry[] {
  const entries: EnvEntry[] = [];
  const lines = content.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue;

    // Strip "export " prefix
    const cleaned = line.startsWith('export ') ? line.slice(7) : line;

    // Find the first = sign
    const eqIdx = cleaned.indexOf('=');
    if (eqIdx === -1) continue;

    const key = cleaned.slice(0, eqIdx).trim();
    let value = cleaned.slice(eqIdx + 1);

    if (!key) continue;

    // Parse value based on quoting
    if (value.startsWith('"') && value.endsWith('"')) {
      // Double-quoted: process escape sequences
      value = value.slice(1, -1)
        .replace(/\\n/g, '\n')
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\');
    } else if (value.startsWith("'") && value.endsWith("'")) {
      // Single-quoted: literal
      value = value.slice(1, -1);
    } else {
      // Unquoted: trim
      value = value.trim();
    }

    entries.push({ key, value });
  }

  return entries;
}

/**
 * Convert an environment variable name to a vault secret path.
 *
 * Examples:
 * - "AWS_ACCESS_KEY" -> "aws/access-key"
 * - "SLACK_BOT_TOKEN" -> "slack/bot-token"
 *
 * Heuristic: underscores become slashes for the first N segments,
 * remaining underscores become dashes. Since we can't perfectly
 * reverse the transformation, we use a simple approach:
 * all underscores become slashes and the whole thing is lowercased.
 *
 * Users can provide a prefix to prepend.
 */
export function envNameToPath(envName: string, prefix?: string): string {
  const lower = envName.toLowerCase().replace(/_/g, '/');
  return prefix ? `${prefix}${lower}` : lower;
}

/**
 * Import secrets from a .env file into the vault.
 *
 * @param vault - An unlocked VaultEngine instance
 * @param envContent - Content of the .env file
 * @param defaultStrategy - Default strategy for duplicate handling
 * @param prefix - Optional prefix to prepend to imported paths
 * @param perPathStrategies - Per-path override strategies for specific duplicates
 */
export function importEnv(
  vault: VaultEngine,
  envContent: string,
  defaultStrategy: ImportConflictStrategy = 'skip',
  prefix?: string,
  perPathStrategies?: Map<string, ImportConflictStrategy>,
): ImportResult {
  if (!vault.isUnlocked) {
    throw new Error('Vault is locked. Unlock it first.');
  }

  const entries = parseEnvFile(envContent);
  const result: ImportResult = {
    success: true,
    imported: 0,
    skipped: 0,
    overwritten: 0,
    renamed: 0,
    errors: [],
  };

  for (const entry of entries) {
    const secretPath = envNameToPath(entry.key, prefix);

    try {
      const existing = vault.get(secretPath);
      const strategy = perPathStrategies?.get(secretPath) ?? defaultStrategy;

      if (existing) {
        // Duplicate detected
        switch (strategy) {
          case 'skip':
            result.skipped++;
            continue;

          case 'overwrite':
            vault.store(secretPath, entry.value, { type: 'api-key', description: `Imported from .env` });
            result.overwritten++;
            break;

          case 'rename': {
            // Find an unused name by appending a counter
            let counter = 1;
            let renamedPath = `${secretPath}-imported-${counter}`;
            while (vault.get(renamedPath) !== null) {
              counter++;
              renamedPath = `${secretPath}-imported-${counter}`;
            }
            vault.store(renamedPath, entry.value, { type: 'api-key', description: `Imported from .env (renamed from ${secretPath})` });
            result.renamed++;
            break;
          }
        }
      } else {
        // No duplicate — import directly
        vault.store(secretPath, entry.value, { type: 'api-key', description: 'Imported from .env' });
        result.imported++;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      result.errors.push(`${entry.key}: ${message}`);
    }
  }

  if (result.errors.length > 0) {
    result.success = false;
  }

  return result;
}

/**
 * Detect duplicate paths that would occur during an import.
 *
 * Returns a list of paths that already exist in the vault.
 */
export function detectImportDuplicates(
  vault: VaultEngine,
  envContent: string,
  prefix?: string,
): string[] {
  if (!vault.isUnlocked) {
    throw new Error('Vault is locked. Unlock it first.');
  }

  const entries = parseEnvFile(envContent);
  const duplicates: string[] = [];

  for (const entry of entries) {
    const secretPath = envNameToPath(entry.key, prefix);
    const existing = vault.get(secretPath);
    if (existing) {
      duplicates.push(secretPath);
    }
  }

  return duplicates;
}
