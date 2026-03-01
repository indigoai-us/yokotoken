/**
 * Crypto module for hq-vault.
 *
 * Uses sodium-native (libsodium C bindings) for:
 * - Argon2id key derivation from passphrase
 * - XChaCha20-Poly1305 authenticated encryption
 */

import sodium from 'sodium-native';

// Re-export constants for external use
export const SALT_BYTES = sodium.crypto_pwhash_SALTBYTES; // 16
export const KEY_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32
export const NONCE_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
export const MAC_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16

/**
 * Generate a cryptographically random salt for key derivation.
 */
export function generateSalt(): Buffer {
  const salt = Buffer.alloc(SALT_BYTES);
  sodium.randombytes_buf(salt);
  return salt;
}

/**
 * Derive a 32-byte master key from a passphrase using Argon2id.
 *
 * Parameters match PRD requirements:
 * - opslimit = 3 (MODERATE)
 * - memlimit = 256MB (MODERATE)
 * - algorithm = Argon2id v1.3
 */
export function deriveMasterKey(passphrase: string, salt: Buffer): Buffer {
  if (!passphrase || passphrase.length === 0) {
    throw new Error('Passphrase cannot be empty');
  }
  if (salt.length !== SALT_BYTES) {
    throw new Error(`Salt must be ${SALT_BYTES} bytes, got ${salt.length}`);
  }

  const key = Buffer.alloc(KEY_BYTES);
  const passwordBuf = Buffer.from(passphrase, 'utf-8');

  sodium.crypto_pwhash(
    key,
    passwordBuf,
    salt,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,  // 3
    sodium.crypto_pwhash_MEMLIMIT_MODERATE,   // 256MB
    sodium.crypto_pwhash_ALG_ARGON2ID13,      // Argon2id
  );

  return key;
}

/**
 * Encrypt plaintext using XChaCha20-Poly1305.
 *
 * Returns an object containing the ciphertext (with appended auth tag) and
 * the random nonce used. Both are needed for decryption.
 */
export function encrypt(
  plaintext: Buffer,
  key: Buffer,
): { ciphertext: Buffer; nonce: Buffer } {
  if (key.length !== KEY_BYTES) {
    throw new Error(`Key must be ${KEY_BYTES} bytes, got ${key.length}`);
  }

  const nonce = Buffer.alloc(NONCE_BYTES);
  sodium.randombytes_buf(nonce);

  // ciphertext = encrypted message + MAC tag
  const ciphertext = Buffer.alloc(plaintext.length + MAC_BYTES);

  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    ciphertext,
    plaintext,
    null,   // no additional data
    null,   // nsec (unused, always null)
    nonce,
    key,
  );

  return { ciphertext, nonce };
}

/**
 * Decrypt ciphertext using XChaCha20-Poly1305.
 *
 * Throws if:
 * - The key is wrong (authentication tag verification fails)
 * - The ciphertext has been tampered with
 * - The nonce doesn't match
 */
export function decrypt(
  ciphertext: Buffer,
  nonce: Buffer,
  key: Buffer,
): Buffer {
  if (key.length !== KEY_BYTES) {
    throw new Error(`Key must be ${KEY_BYTES} bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`Nonce must be ${NONCE_BYTES} bytes, got ${nonce.length}`);
  }
  if (ciphertext.length < MAC_BYTES) {
    throw new Error('Ciphertext is too short to contain an authentication tag');
  }

  const message = Buffer.alloc(ciphertext.length - MAC_BYTES);

  try {
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      message,
      null,        // nsec (unused, always null)
      ciphertext,
      null,        // no additional data
      nonce,
      key,
    );
  } catch {
    throw new Error('Decryption failed: invalid key or corrupted ciphertext');
  }

  return message;
}

/**
 * Securely zero out a buffer containing sensitive data (keys, plaintexts).
 */
export function secureZero(buf: Buffer): void {
  sodium.sodium_memzero(buf);
}
