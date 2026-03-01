/**
 * Unit tests for the crypto module.
 *
 * Verifies:
 * - Key derivation produces consistent keys for same passphrase+salt
 * - Different passphrases produce different keys
 * - Encryption roundtrip (encrypt then decrypt recovers plaintext)
 * - Wrong key decryption fails
 * - Empty passphrase rejection
 * - Edge cases (empty plaintext, large data)
 */

import { describe, it, expect } from 'vitest';
import {
  deriveMasterKey,
  encrypt,
  decrypt,
  generateSalt,
  secureZero,
  SALT_BYTES,
  KEY_BYTES,
  NONCE_BYTES,
  MAC_BYTES,
} from '../src/crypto.js';

describe('crypto', () => {
  describe('generateSalt', () => {
    it('should generate a salt of correct length', () => {
      const salt = generateSalt();
      expect(salt.length).toBe(SALT_BYTES);
    });

    it('should generate different salts each time', () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();
      expect(salt1.equals(salt2)).toBe(false);
    });
  });

  describe('deriveMasterKey', () => {
    it('should derive a 32-byte key', () => {
      const salt = generateSalt();
      const key = deriveMasterKey('test-passphrase', salt);
      expect(key.length).toBe(KEY_BYTES);
    });

    it('should produce the same key for the same passphrase and salt', () => {
      const salt = generateSalt();
      const key1 = deriveMasterKey('my-passphrase', salt);
      const key2 = deriveMasterKey('my-passphrase', salt);
      expect(key1.equals(key2)).toBe(true);
    });

    it('should produce different keys for different passphrases', () => {
      const salt = generateSalt();
      const key1 = deriveMasterKey('passphrase-one', salt);
      const key2 = deriveMasterKey('passphrase-two', salt);
      expect(key1.equals(key2)).toBe(false);
    });

    it('should produce different keys for different salts', () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();
      const key1 = deriveMasterKey('same-passphrase', salt1);
      const key2 = deriveMasterKey('same-passphrase', salt2);
      expect(key1.equals(key2)).toBe(false);
    });

    it('should reject empty passphrase', () => {
      const salt = generateSalt();
      expect(() => deriveMasterKey('', salt)).toThrow('Passphrase cannot be empty');
    });

    it('should reject incorrect salt length', () => {
      const badSalt = Buffer.alloc(8);
      expect(() => deriveMasterKey('test', badSalt)).toThrow(`Salt must be ${SALT_BYTES} bytes`);
    });
  });

  describe('encrypt / decrypt roundtrip', () => {
    let key: Buffer;

    // Use a fixed salt to avoid deriving a new key for every test
    // (Argon2id is intentionally slow)
    const salt = generateSalt();

    it('setup: derive a key (slow due to Argon2id)', () => {
      key = deriveMasterKey('roundtrip-test-passphrase', salt);
      expect(key.length).toBe(KEY_BYTES);
    });

    it('should encrypt and decrypt a simple string', () => {
      const plaintext = Buffer.from('hello, vault!', 'utf-8');
      const { ciphertext, nonce } = encrypt(plaintext, key);

      // Ciphertext should be plaintext.length + MAC_BYTES
      expect(ciphertext.length).toBe(plaintext.length + MAC_BYTES);
      // Nonce should be correct length
      expect(nonce.length).toBe(NONCE_BYTES);
      // Ciphertext should differ from plaintext
      expect(ciphertext.slice(0, plaintext.length).equals(plaintext)).toBe(false);

      const decrypted = decrypt(ciphertext, nonce, key);
      expect(decrypted.toString('utf-8')).toBe('hello, vault!');
    });

    it('should handle empty plaintext', () => {
      const plaintext = Buffer.from('', 'utf-8');
      const { ciphertext, nonce } = encrypt(plaintext, key);
      expect(ciphertext.length).toBe(MAC_BYTES); // just the auth tag

      const decrypted = decrypt(ciphertext, nonce, key);
      expect(decrypted.toString('utf-8')).toBe('');
    });

    it('should handle binary data', () => {
      const plaintext = Buffer.from([0x00, 0xff, 0x42, 0x13, 0x37]);
      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, nonce, key);
      expect(decrypted.equals(plaintext)).toBe(true);
    });

    it('should handle large data', () => {
      const plaintext = Buffer.alloc(100_000, 'A');
      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, nonce, key);
      expect(decrypted.equals(plaintext)).toBe(true);
    });

    it('should handle unicode strings', () => {
      const text = 'Emoji: 🔐🗝️ | CJK: 密码 | Cyrillic: пароль';
      const plaintext = Buffer.from(text, 'utf-8');
      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, nonce, key);
      expect(decrypted.toString('utf-8')).toBe(text);
    });

    it('should produce different ciphertexts for the same plaintext (random nonce)', () => {
      const plaintext = Buffer.from('same-message', 'utf-8');
      const result1 = encrypt(plaintext, key);
      const result2 = encrypt(plaintext, key);
      // Different nonces
      expect(result1.nonce.equals(result2.nonce)).toBe(false);
      // Different ciphertexts
      expect(result1.ciphertext.equals(result2.ciphertext)).toBe(false);
    });
  });

  describe('wrong key rejection', () => {
    it('should fail to decrypt with the wrong key', () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();
      const correctKey = deriveMasterKey('correct-passphrase', salt1);
      const wrongKey = deriveMasterKey('wrong-passphrase', salt2);

      const plaintext = Buffer.from('secret-data', 'utf-8');
      const { ciphertext, nonce } = encrypt(plaintext, correctKey);

      expect(() => decrypt(ciphertext, nonce, wrongKey)).toThrow(
        'Decryption failed'
      );
    });
  });

  describe('tamper detection', () => {
    it('should fail if ciphertext is modified', () => {
      const salt = generateSalt();
      const key = deriveMasterKey('tamper-test', salt);
      const plaintext = Buffer.from('tamper-proof-data', 'utf-8');
      const { ciphertext, nonce } = encrypt(plaintext, key);

      // Flip a byte in the ciphertext
      const tampered = Buffer.from(ciphertext);
      tampered[0] ^= 0xff;

      expect(() => decrypt(tampered, nonce, key)).toThrow('Decryption failed');
    });
  });

  describe('secureZero', () => {
    it('should zero out a buffer', () => {
      const buf = Buffer.from('sensitive-data', 'utf-8');
      expect(buf.toString('utf-8')).toBe('sensitive-data');

      secureZero(buf);

      // Every byte should be zero
      for (let i = 0; i < buf.length; i++) {
        expect(buf[i]).toBe(0);
      }
    });
  });

  describe('input validation', () => {
    it('should reject wrong key length for encrypt', () => {
      const shortKey = Buffer.alloc(16);
      const plaintext = Buffer.from('test');
      expect(() => encrypt(plaintext, shortKey)).toThrow(`Key must be ${KEY_BYTES} bytes`);
    });

    it('should reject wrong key length for decrypt', () => {
      const shortKey = Buffer.alloc(16);
      const ciphertext = Buffer.alloc(32);
      const nonce = Buffer.alloc(NONCE_BYTES);
      expect(() => decrypt(ciphertext, nonce, shortKey)).toThrow(`Key must be ${KEY_BYTES} bytes`);
    });

    it('should reject wrong nonce length for decrypt', () => {
      const key = Buffer.alloc(KEY_BYTES);
      const ciphertext = Buffer.alloc(32);
      const badNonce = Buffer.alloc(12);
      expect(() => decrypt(ciphertext, badNonce, key)).toThrow(`Nonce must be ${NONCE_BYTES} bytes`);
    });

    it('should reject ciphertext shorter than MAC', () => {
      const key = Buffer.alloc(KEY_BYTES);
      const nonce = Buffer.alloc(NONCE_BYTES);
      const shortCiphertext = Buffer.alloc(MAC_BYTES - 1);
      expect(() => decrypt(shortCiphertext, nonce, key)).toThrow('too short');
    });
  });
});
