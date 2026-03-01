/**
 * Crypto module for hq-vault.
 *
 * Uses libsodium-wrappers-sumo (WASM build) for:
 * - Argon2id key derivation from passphrase
 * - XChaCha20-Poly1305 authenticated encryption
 *
 * All functions that use sodium are async because libsodium-wrappers
 * requires an async initialization step (`await sodium.ready`).
 */

import sodium from 'libsodium-wrappers-sumo';

/** Whether sodium has been initialized. */
let sodiumReady = false;

/** Ensure sodium WASM is loaded before any operations. */
async function ensureSodium(): Promise<void> {
  if (!sodiumReady) {
    await sodium.ready;
    sodiumReady = true;
  }
}

// Re-export constants — these are safe to access synchronously after module load.
// We use literal values matching libsodium constants to keep them synchronous.
export const SALT_BYTES = 16;   // crypto_pwhash_SALTBYTES
export const KEY_BYTES = 32;    // crypto_aead_xchacha20poly1305_ietf_KEYBYTES
export const NONCE_BYTES = 24;  // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
export const MAC_BYTES = 16;    // crypto_aead_xchacha20poly1305_ietf_ABYTES

/**
 * Generate a cryptographically random salt for key derivation.
 */
export async function generateSalt(): Promise<Buffer> {
  await ensureSodium();
  const salt = sodium.randombytes_buf(SALT_BYTES);
  return Buffer.from(salt);
}

/**
 * Derive a 32-byte master key from a passphrase using Argon2id.
 *
 * Parameters match PRD requirements:
 * - opslimit = 3 (MODERATE)
 * - memlimit = 256MB (MODERATE)
 * - algorithm = Argon2id v1.3
 */
export async function deriveMasterKey(passphrase: string, salt: Buffer): Promise<Buffer> {
  if (!passphrase || passphrase.length === 0) {
    throw new Error('Passphrase cannot be empty');
  }
  if (salt.length !== SALT_BYTES) {
    throw new Error(`Salt must be ${SALT_BYTES} bytes, got ${salt.length}`);
  }

  await ensureSodium();

  const key = sodium.crypto_pwhash(
    KEY_BYTES,
    passphrase,
    new Uint8Array(salt),
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,  // 3
    sodium.crypto_pwhash_MEMLIMIT_MODERATE,   // 256MB
    sodium.crypto_pwhash_ALG_ARGON2ID13,      // Argon2id
  );

  return Buffer.from(key);
}

/**
 * Encrypt plaintext using XChaCha20-Poly1305.
 *
 * Returns an object containing the ciphertext (with appended auth tag) and
 * the random nonce used. Both are needed for decryption.
 */
export async function encrypt(
  plaintext: Buffer,
  key: Buffer,
): Promise<{ ciphertext: Buffer; nonce: Buffer }> {
  if (key.length !== KEY_BYTES) {
    throw new Error(`Key must be ${KEY_BYTES} bytes, got ${key.length}`);
  }

  await ensureSodium();

  const nonce = sodium.randombytes_buf(NONCE_BYTES);

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    new Uint8Array(plaintext),
    null,   // no additional data
    null,   // nsec (unused, always null)
    nonce,
    new Uint8Array(key),
  );

  return {
    ciphertext: Buffer.from(ciphertext),
    nonce: Buffer.from(nonce),
  };
}

/**
 * Decrypt ciphertext using XChaCha20-Poly1305.
 *
 * Throws if:
 * - The key is wrong (authentication tag verification fails)
 * - The ciphertext has been tampered with
 * - The nonce doesn't match
 */
export async function decrypt(
  ciphertext: Buffer,
  nonce: Buffer,
  key: Buffer,
): Promise<Buffer> {
  if (key.length !== KEY_BYTES) {
    throw new Error(`Key must be ${KEY_BYTES} bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`Nonce must be ${NONCE_BYTES} bytes, got ${nonce.length}`);
  }
  if (ciphertext.length < MAC_BYTES) {
    throw new Error('Ciphertext is too short to contain an authentication tag');
  }

  await ensureSodium();

  try {
    const message = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,        // nsec (unused, always null)
      new Uint8Array(ciphertext),
      null,        // no additional data
      new Uint8Array(nonce),
      new Uint8Array(key),
    );

    return Buffer.from(message);
  } catch {
    throw new Error('Decryption failed: invalid key or corrupted ciphertext');
  }
}

/**
 * Securely zero out a buffer containing sensitive data (keys, plaintexts).
 */
export async function secureZero(buf: Buffer): Promise<void> {
  await ensureSodium();
  sodium.memzero(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
}

/**
 * Ensure sodium is loaded. Utility for other modules that need to call
 * sodium directly (e.g., identity.ts for Ed25519).
 */
export { ensureSodium };
