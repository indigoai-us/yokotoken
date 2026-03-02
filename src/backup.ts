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
 */
export async function createBackup(
  vaultDbPath: string,
  backupPath: string,
  passphrase: string,
): Promise<BackupResult> {
  if (!fs.existsSync(vaultDbPath)) {
    throw new Error(`Vault database not found: ${vaultDbPath}`);
  }

  if (!passphrase || passphrase.length === 0) {
    throw new Error('Passphrase cannot be empty');
  }

  // Read the raw SQLite database file
  const dbData = fs.readFileSync(vaultDbPath);

  // Generate a fresh salt for this backup
  const salt = await generateSalt();

  // Derive encryption key from passphrase
  const key = await deriveMasterKey(passphrase, salt);

  try {
    // Encrypt the entire database
    const { ciphertext, nonce } = await encrypt(dbData, key);

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
    await secureZero(key);
  }
}

/**
 * Restore a vault from an encrypted backup file.
 */
export async function restoreBackup(
  backupPath: string,
  restorePath: string,
  passphrase: string,
): Promise<RestoreResult> {
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
  const key = await deriveMasterKey(passphrase, Buffer.from(salt));

  let dbData: Buffer;
  try {
    dbData = await decrypt(Buffer.from(ciphertext), Buffer.from(nonce), key);
  } catch {
    await secureZero(key);
    throw new Error('Failed to decrypt backup: invalid passphrase or corrupted file');
  }

  await secureZero(key);

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
  const vault = await VaultEngine.open(restorePath);
  let secretCount = 0;
  try {
    await vault.unlock(passphrase);
    const entries = vault.list();
    secretCount = entries.length;
  } finally {
    await vault.close();
  }

  return {
    success: true,
    restoredPath: restorePath,
    secretCount,
  };
}

/**
 * Export all secrets from the vault as .env format.
 */
export async function exportEnv(
  vault: VaultEngine,
  prefix?: string,
): Promise<ExportResult> {
  if (!vault.isUnlocked) {
    throw new Error('Vault is locked. Unlock it first.');
  }

  const entries = vault.list(prefix);
  const lines: string[] = [];

  for (const entry of entries) {
    const secret = await vault.get(entry.path);
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
 */
export function pathToEnvName(secretPath: string, prefix?: string): string {
  let relative = secretPath;
  if (prefix && relative.startsWith(prefix)) {
    relative = relative.slice(prefix.length);
  }
  if (relative.startsWith('/')) {
    relative = relative.slice(1);
  }
  return relative
    .replace(/[/\-\.]/g, '_')
    .toUpperCase();
}

/**
 * Parse a .env file into key-value entries.
 */
export function parseEnvFile(content: string): EnvEntry[] {
  const entries: EnvEntry[] = [];
  const lines = content.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (!line || line.startsWith('#')) continue;

    const cleaned = line.startsWith('export ') ? line.slice(7) : line;

    const eqIdx = cleaned.indexOf('=');
    if (eqIdx === -1) continue;

    const key = cleaned.slice(0, eqIdx).trim();
    let value = cleaned.slice(eqIdx + 1);

    if (!key) continue;

    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1)
        .replace(/\\n/g, '\n')
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\');
    } else if (value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1);
    } else {
      value = value.trim();
    }

    entries.push({ key, value });
  }

  return entries;
}

/**
 * Convert an environment variable name to a vault secret path.
 */
export function envNameToPath(envName: string, prefix?: string): string {
  const lower = envName.toLowerCase().replace(/_/g, '/');
  return prefix ? `${prefix}${lower}` : lower;
}

/**
 * Import secrets from a .env file into the vault.
 */
export async function importEnv(
  vault: VaultEngine,
  envContent: string,
  defaultStrategy: ImportConflictStrategy = 'skip',
  prefix?: string,
  perPathStrategies?: Map<string, ImportConflictStrategy>,
): Promise<ImportResult> {
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
      const existing = await vault.get(secretPath);
      const strategy = perPathStrategies?.get(secretPath) ?? defaultStrategy;

      if (existing) {
        switch (strategy) {
          case 'skip':
            result.skipped++;
            continue;

          case 'overwrite':
            await vault.store(secretPath, entry.value, { type: 'api-key', description: `Imported from .env` });
            result.overwritten++;
            break;

          case 'rename': {
            let counter = 1;
            let renamedPath = `${secretPath}-imported-${counter}`;
            while ((await vault.get(renamedPath)) !== null) {
              counter++;
              renamedPath = `${secretPath}-imported-${counter}`;
            }
            await vault.store(renamedPath, entry.value, { type: 'api-key', description: `Imported from .env (renamed from ${secretPath})` });
            result.renamed++;
            break;
          }
        }
      } else {
        await vault.store(secretPath, entry.value, { type: 'api-key', description: 'Imported from .env' });
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
 */
export async function detectImportDuplicates(
  vault: VaultEngine,
  envContent: string,
  prefix?: string,
): Promise<string[]> {
  if (!vault.isUnlocked) {
    throw new Error('Vault is locked. Unlock it first.');
  }

  const entries = parseEnvFile(envContent);
  const duplicates: string[] = [];

  for (const entry of entries) {
    const secretPath = envNameToPath(entry.key, prefix);
    const existing = await vault.get(secretPath);
    if (existing) {
      duplicates.push(secretPath);
    }
  }

  return duplicates;
}
