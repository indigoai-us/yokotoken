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

import { VaultDatabase } from './db.js';
import {
  deriveMasterKey,
  encrypt,
  decrypt,
  generateSalt,
  secureZero,
  SALT_BYTES,
} from './crypto.js';

export interface SecretMetadata {
  type?: string;
  description?: string;
}

export interface SecretEntry {
  path: string;
  value: string;
  metadata: SecretMetadata;
  createdAt: string;
  updatedAt: string;
}

export interface SecretListEntry {
  path: string;
  metadata: SecretMetadata;
  createdAt: string;
  updatedAt: string;
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

  constructor(dbPath: string) {
    this.vaultPath = dbPath;
    this.db = new VaultDatabase(dbPath);
  }

  /**
   * Initialize a new vault with a passphrase.
   * Generates a random salt and derives the master key.
   *
   * Throws if the vault is already initialized (has a salt).
   */
  init(passphrase: string): void {
    const existingSalt = this.db.getMeta('salt');
    if (existingSalt) {
      throw new Error(
        'Vault is already initialized. Use unlock() to access it.'
      );
    }

    const salt = generateSalt();
    this.db.setMeta('salt', salt);
    this.db.setMeta('version', '1');

    // Derive and hold the master key
    this.masterKey = deriveMasterKey(passphrase, salt);

    // Store a verification entry so we can validate passphrases on unlock
    const verifyPlaintext = Buffer.from('hq-vault-ok', 'utf-8');
    const { ciphertext, nonce } = encrypt(verifyPlaintext, this.masterKey);
    this.db.storeSecret('__vault_verify__', ciphertext, nonce, 'system', 'Vault verification entry');
  }

  /**
   * Unlock the vault by deriving the master key from the passphrase.
   *
   * Validates the passphrase by attempting to decrypt a verification entry
   * stored during init().
   */
  unlock(passphrase: string): void {
    const salt = this.db.getMeta('salt');
    if (!salt) {
      throw new Error('Vault is not initialized. Run init() first.');
    }
    if (salt.length !== SALT_BYTES) {
      throw new Error('Corrupt vault: invalid salt length');
    }

    const candidateKey = deriveMasterKey(passphrase, salt);

    // Verify the passphrase against the verification entry stored during init()
    const verifyRow = this.db.getSecretRow('__vault_verify__');
    if (!verifyRow) {
      secureZero(candidateKey);
      throw new Error('Corrupt vault: missing verification entry');
    }

    try {
      const decrypted = decrypt(
        verifyRow.encrypted_value,
        verifyRow.nonce,
        candidateKey,
      );
      const text = decrypted.toString('utf-8');
      if (text !== 'hq-vault-ok') {
        secureZero(candidateKey);
        throw new Error('Invalid passphrase');
      }
    } catch (err) {
      secureZero(candidateKey);
      if (err instanceof Error && err.message === 'Invalid passphrase') {
        throw err;
      }
      throw new Error('Invalid passphrase');
    }

    // Wipe old key if any
    if (this.masterKey) {
      secureZero(this.masterKey);
    }
    this.masterKey = candidateKey;
  }

  /**
   * Lock the vault by securely wiping the master key from memory.
   */
  lock(): void {
    if (this.masterKey) {
      secureZero(this.masterKey);
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
   *
   * The value is encrypted with XChaCha20-Poly1305 before storage.
   * If a secret already exists at the path, it will be overwritten.
   */
  store(
    secretPath: string,
    value: string,
    metadata?: SecretMetadata,
  ): void {
    const key = this.requireUnlocked();
    this.validatePath(secretPath);

    const plaintext = Buffer.from(value, 'utf-8');
    const { ciphertext, nonce } = encrypt(plaintext, key);

    this.db.storeSecret(
      secretPath,
      ciphertext,
      nonce,
      metadata?.type,
      metadata?.description,
    );
  }

  /**
   * Retrieve and decrypt a secret at the given path.
   *
   * Returns null if no secret exists at the path.
   * Throws if decryption fails (should not happen with correct key).
   */
  get(secretPath: string): SecretEntry | null {
    const key = this.requireUnlocked();
    this.validatePath(secretPath);

    const row = this.db.getSecretRow(secretPath);
    if (!row) {
      return null;
    }

    const decrypted = decrypt(row.encrypted_value, row.nonce, key);

    return {
      path: row.path,
      value: decrypted.toString('utf-8'),
      metadata: {
        type: row.secret_type ?? undefined,
        description: row.description ?? undefined,
      },
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  /**
   * List secrets, optionally filtered by path prefix.
   *
   * Returns metadata only — NOT decrypted values.
   */
  list(prefix?: string): SecretListEntry[] {
    this.requireUnlocked();

    const rows = this.db.listSecrets(prefix);
    return rows
      .filter(row => row.path !== '__vault_verify__')
      .map(row => ({
        path: row.path,
        metadata: {
          type: row.secret_type ?? undefined,
          description: row.description ?? undefined,
        },
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }));
  }

  /**
   * Delete a secret at the given path.
   *
   * Returns true if the secret was deleted, false if it didn't exist.
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
    // Subtract 1 for the __vault_verify__ entry if it exists
    const hasVerify = this.db.hasSecret('__vault_verify__');
    const userSecretCount = hasVerify ? totalCount - 1 : totalCount;

    return {
      initialized: this.isInitialized,
      locked: !this.isUnlocked,
      secretCount: userSecretCount,
      vaultPath: this.vaultPath,
    };
  }

  /**
   * Close the vault, securely wiping the key and closing the database.
   */
  close(): void {
    this.lock();
    this.db.close();
  }

  /**
   * Validate a secret path.
   * Paths must be non-empty, not start/end with slashes, and not contain
   * consecutive slashes or the reserved __vault prefix.
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
