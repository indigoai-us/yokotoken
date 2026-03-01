/**
 * Unit tests for the database layer.
 *
 * Tests the SQLite storage operations in isolation (no crypto).
 * Uses an in-memory temp directory per test to avoid file conflicts.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { VaultDatabase } from '../src/db.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('VaultDatabase', () => {
  let db: VaultDatabase;
  let tmpDir: string;
  let dbPath: string;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-test-'));
    dbPath = path.join(tmpDir, 'test-vault.db');
    db = await VaultDatabase.open(dbPath);
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('metadata', () => {
    it('should store and retrieve metadata', () => {
      const salt = Buffer.from('0123456789abcdef');
      db.setMeta('salt', salt);
      const retrieved = db.getMeta('salt');
      expect(retrieved).not.toBeNull();
      expect(retrieved!.equals(salt)).toBe(true);
    });

    it('should return null for missing metadata', () => {
      const result = db.getMeta('nonexistent');
      expect(result).toBeNull();
    });

    it('should update existing metadata', () => {
      db.setMeta('version', '1');
      db.setMeta('version', '2');
      const result = db.getMeta('version');
      expect(result!.toString('utf-8')).toBe('2');
    });
  });

  describe('secret CRUD', () => {
    const sampleEncrypted = Buffer.from('encrypted-data');
    const sampleNonce = Buffer.from('nonce-value-here');

    it('should store and retrieve a secret', () => {
      db.storeSecret('aws/dev/access-key', sampleEncrypted, sampleNonce, 'api-key', 'AWS dev key');
      const row = db.getSecretRow('aws/dev/access-key');

      expect(row).not.toBeNull();
      expect(row!.path).toBe('aws/dev/access-key');
      expect(row!.encrypted_value.equals(sampleEncrypted)).toBe(true);
      expect(row!.nonce.equals(sampleNonce)).toBe(true);
      expect(row!.secret_type).toBe('api-key');
      expect(row!.description).toBe('AWS dev key');
      expect(row!.created_at).toBeTruthy();
      expect(row!.updated_at).toBeTruthy();
    });

    it('should return null for nonexistent secret', () => {
      const row = db.getSecretRow('does/not/exist');
      expect(row).toBeNull();
    });

    it('should update an existing secret', () => {
      db.storeSecret('slack/token', sampleEncrypted, sampleNonce, 'oauth-token');
      const newEncrypted = Buffer.from('new-encrypted-data');
      const newNonce = Buffer.from('new-nonce-value!');
      db.storeSecret('slack/token', newEncrypted, newNonce);

      const row = db.getSecretRow('slack/token');
      expect(row!.encrypted_value.equals(newEncrypted)).toBe(true);
      expect(row!.nonce.equals(newNonce)).toBe(true);
      // Type should be preserved from first insert
      expect(row!.secret_type).toBe('oauth-token');
    });

    it('should delete a secret', () => {
      db.storeSecret('temp/secret', sampleEncrypted, sampleNonce);
      expect(db.hasSecret('temp/secret')).toBe(true);

      const deleted = db.deleteSecret('temp/secret');
      expect(deleted).toBe(true);
      expect(db.hasSecret('temp/secret')).toBe(false);
    });

    it('should return false when deleting nonexistent secret', () => {
      const deleted = db.deleteSecret('nonexistent');
      expect(deleted).toBe(false);
    });
  });

  describe('listing and counting', () => {
    beforeEach(() => {
      const enc = Buffer.from('enc');
      const nonce = Buffer.from('nonce');
      db.storeSecret('aws/dev/access-key', enc, nonce, 'api-key');
      db.storeSecret('aws/dev/secret-key', enc, nonce, 'api-key');
      db.storeSecret('aws/prod/access-key', enc, nonce, 'api-key');
      db.storeSecret('slack/indigo/bot-token', enc, nonce, 'oauth-token');
      db.storeSecret('slack/indigo/user-token', enc, nonce, 'oauth-token');
      db.storeSecret('github/pat', enc, nonce, 'api-key');
    });

    it('should list all secrets', () => {
      const all = db.listSecrets();
      expect(all.length).toBe(6);
    });

    it('should filter by prefix', () => {
      const awsDev = db.listSecrets('aws/dev/');
      expect(awsDev.length).toBe(2);
      expect(awsDev.map(r => r.path)).toContain('aws/dev/access-key');
      expect(awsDev.map(r => r.path)).toContain('aws/dev/secret-key');
    });

    it('should filter by broader prefix', () => {
      const allAws = db.listSecrets('aws/');
      expect(allAws.length).toBe(3);
    });

    it('should filter by slack prefix', () => {
      const slackSecrets = db.listSecrets('slack/');
      expect(slackSecrets.length).toBe(2);
    });

    it('should return empty for non-matching prefix', () => {
      const none = db.listSecrets('nonexistent/');
      expect(none.length).toBe(0);
    });

    it('should list secrets in sorted order', () => {
      const all = db.listSecrets();
      const paths = all.map(r => r.path);
      expect(paths).toEqual([...paths].sort());
    });

    it('should count secrets', () => {
      expect(db.countSecrets()).toBe(6);
    });

    it('should check existence', () => {
      expect(db.hasSecret('aws/dev/access-key')).toBe(true);
      expect(db.hasSecret('aws/dev/nonexistent')).toBe(false);
    });
  });

  describe('database file', () => {
    it('should create the database file on construction', () => {
      expect(fs.existsSync(dbPath)).toBe(true);
    });

    it('should create parent directories if needed', async () => {
      const deepPath = path.join(tmpDir, 'deep', 'nested', 'vault.db');
      const deepDb = await VaultDatabase.open(deepPath);
      expect(fs.existsSync(deepPath)).toBe(true);
      deepDb.close();
    });
  });
});
