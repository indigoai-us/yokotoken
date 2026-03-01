/**
 * Integration tests for the VaultEngine.
 *
 * Verifies the full lifecycle:
 * - Vault initialization with passphrase
 * - Unlock / lock cycle
 * - Secret storage with encryption roundtrip
 * - Wrong passphrase rejection
 * - Path-based secret organization
 * - Edge cases and error handling
 *
 * Note: Tests are grouped to minimize Argon2id key derivation calls (each
 * takes ~1s at MODERATE settings with 256MB memory). We use beforeAll where
 * possible and consolidate related assertions into single test cases.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { VaultEngine } from '../src/vault.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-master-passphrase-2026';

describe('VaultEngine — initialization', () => {
  let vault: VaultEngine;
  let tmpDir: string;
  let dbPath: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-init-'));
    dbPath = path.join(tmpDir, 'vault.db');
    vault = new VaultEngine(dbPath);
  });

  afterAll(() => {
    try { vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should initialize a new vault and create the database file', () => {
    vault.init(PASSPHRASE);
    expect(vault.isInitialized).toBe(true);
    expect(vault.isUnlocked).toBe(true);
    expect(fs.existsSync(dbPath)).toBe(true);
  });

  it('should reject double initialization', () => {
    expect(() => vault.init(PASSPHRASE)).toThrow('already initialized');
  });
});

describe('VaultEngine — unlock / lock', () => {
  let vault: VaultEngine;
  let tmpDir: string;
  let dbPath: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-lock-'));
    dbPath = path.join(tmpDir, 'vault.db');
    vault = new VaultEngine(dbPath);
    vault.init(PASSPHRASE);
    vault.store('test/setup', 'setup-value');
    vault.lock();
  });

  afterAll(() => {
    try { vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should reject wrong passphrase', () => {
    expect(() => vault.unlock('wrong-passphrase')).toThrow('Invalid passphrase');
    expect(vault.isUnlocked).toBe(false);
  });

  it('should fail operations when locked', () => {
    expect(() => vault.store('test/locked', 'value')).toThrow('Vault is locked');
    expect(() => vault.get('test/locked')).toThrow('Vault is locked');
    expect(() => vault.list()).toThrow('Vault is locked');
    expect(() => vault.delete('test/locked')).toThrow('Vault is locked');
  });

  it('should unlock with correct passphrase and access stored secrets', () => {
    vault.unlock(PASSPHRASE);
    expect(vault.isUnlocked).toBe(true);
    const entry = vault.get('test/setup');
    expect(entry).not.toBeNull();
    expect(entry!.value).toBe('setup-value');
  });

  it('should lock and become inaccessible again', () => {
    vault.lock();
    expect(vault.isUnlocked).toBe(false);
    expect(() => vault.get('test/setup')).toThrow('Vault is locked');
  });
});

describe('VaultEngine — encryption roundtrip', () => {
  let vault: VaultEngine;
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-roundtrip-'));
    const dbPath = path.join(tmpDir, 'vault.db');
    vault = new VaultEngine(dbPath);
    vault.init(PASSPHRASE);
  });

  afterAll(() => {
    try { vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should store and retrieve a simple secret', () => {
    vault.store('api/key', 'sk-1234567890abcdef');
    const entry = vault.get('api/key');
    expect(entry).not.toBeNull();
    expect(entry!.value).toBe('sk-1234567890abcdef');
    expect(entry!.path).toBe('api/key');
  });

  it('should store and retrieve with metadata', () => {
    vault.store('slack/token', 'xoxb-1234', {
      type: 'oauth-token',
      description: 'Slack bot token for Indigo workspace',
    });
    const entry = vault.get('slack/token');
    expect(entry!.value).toBe('xoxb-1234');
    expect(entry!.metadata.type).toBe('oauth-token');
    expect(entry!.metadata.description).toBe('Slack bot token for Indigo workspace');
  });

  it('should return null for nonexistent secret', () => {
    const entry = vault.get('does/not/exist');
    expect(entry).toBeNull();
  });

  it('should handle empty, special, unicode, and multi-line values', () => {
    // Empty
    vault.store('empty/value', '');
    expect(vault.get('empty/value')!.value).toBe('');

    // Special characters
    const special = 'p@$$w0rd!#%^&*(){}[]|\\:";\'<>,.?/~`';
    vault.store('special/chars', special);
    expect(vault.get('special/chars')!.value).toBe(special);

    // Unicode
    const unicode = '密码 пароль 🔐🗝️ مفتاح';
    vault.store('unicode/password', unicode);
    expect(vault.get('unicode/password')!.value).toBe(unicode);

    // Multi-line
    const multiline = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/yGFz
ygDQPF6dMluSVnQoYy8=
-----END RSA PRIVATE KEY-----`;
    vault.store('certs/private-key', multiline, { type: 'certificate' });
    expect(vault.get('certs/private-key')!.value).toBe(multiline);
  });

  it('should handle large values', () => {
    const large = 'x'.repeat(100_000);
    vault.store('large/secret', large);
    expect(vault.get('large/secret')!.value).toBe(large);
  });

  it('should overwrite existing secret', () => {
    vault.store('mutable/key', 'version-1');
    vault.store('mutable/key', 'version-2');
    expect(vault.get('mutable/key')!.value).toBe('version-2');
  });
});

describe('VaultEngine — path-based organization', () => {
  let vault: VaultEngine;
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-paths-'));
    const dbPath = path.join(tmpDir, 'vault.db');
    vault = new VaultEngine(dbPath);
    vault.init(PASSPHRASE);
    vault.store('aws/dev/access-key', 'AKIA-dev-123', { type: 'api-key' });
    vault.store('aws/dev/secret-key', 'secret-dev-456', { type: 'api-key' });
    vault.store('aws/prod/access-key', 'AKIA-prod-789', { type: 'api-key' });
    vault.store('slack/indigo/bot-token', 'xoxb-bot', { type: 'oauth-token' });
    vault.store('slack/indigo/user-token', 'xoxp-user', { type: 'oauth-token' });
    vault.store('github/pat', 'ghp_xxxxx', { type: 'api-key' });
  });

  afterAll(() => {
    try { vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should list all secrets and filter by prefix', () => {
    const all = vault.list();
    expect(all.length).toBe(6);

    // By specific prefix
    const awsDev = vault.list('aws/dev/');
    expect(awsDev.length).toBe(2);
    expect(awsDev.map(e => e.path)).toContain('aws/dev/access-key');
    expect(awsDev.map(e => e.path)).toContain('aws/dev/secret-key');

    // Broader prefix
    expect(vault.list('aws/').length).toBe(3);
    expect(vault.list('slack/').length).toBe(2);

    // Non-matching
    expect(vault.list('nonexistent/').length).toBe(0);
  });

  it('should not include __vault_verify__ in list and should not expose values', () => {
    const all = vault.list();
    const paths = all.map(e => e.path);
    expect(paths).not.toContain('__vault_verify__');

    for (const entry of all) {
      expect('value' in entry).toBe(false);
    }
  });

  it('should get individual secrets with correct values', () => {
    const entry = vault.get('aws/dev/access-key');
    expect(entry!.value).toBe('AKIA-dev-123');
    expect(entry!.metadata.type).toBe('api-key');
  });

  it('should delete a secret and handle nonexistent deletes', () => {
    expect(vault.delete('github/pat')).toBe(true);
    expect(vault.get('github/pat')).toBeNull();
    expect(vault.list().length).toBe(5);
    expect(vault.delete('nonexistent')).toBe(false);
  });
});

describe('VaultEngine — vault status', () => {
  let vault: VaultEngine;
  let tmpDir: string;
  let dbPath: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-status-'));
    dbPath = path.join(tmpDir, 'vault.db');
  });

  afterAll(() => {
    try { vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should report status for uninitialized vault', () => {
    vault = new VaultEngine(dbPath);
    const status = vault.status();
    expect(status.initialized).toBe(false);
    expect(status.locked).toBe(true);
    expect(status.secretCount).toBe(0);
    expect(status.vaultPath).toBe(dbPath);
  });

  it('should report correct status after init and after storing secrets', () => {
    vault.init(PASSPHRASE);
    let status = vault.status();
    expect(status.initialized).toBe(true);
    expect(status.locked).toBe(false);
    expect(status.secretCount).toBe(0);

    vault.store('a/secret', 'value-1');
    vault.store('b/secret', 'value-2');
    status = vault.status();
    expect(status.secretCount).toBe(2);

    vault.lock();
    status = vault.status();
    expect(status.locked).toBe(true);
  });
});

describe('VaultEngine — path validation', () => {
  let vault: VaultEngine;
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-validation-'));
    const dbPath = path.join(tmpDir, 'vault.db');
    vault = new VaultEngine(dbPath);
    vault.init(PASSPHRASE);
  });

  afterAll(() => {
    try { vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should reject invalid paths', () => {
    expect(() => vault.store('', 'value')).toThrow('cannot be empty');
    expect(() => vault.store('   ', 'value')).toThrow('cannot be empty');
    expect(() => vault.store('/leading/slash', 'value')).toThrow('must not start or end with /');
    expect(() => vault.store('trailing/slash/', 'value')).toThrow('must not start or end with /');
    expect(() => vault.store('double//slash', 'value')).toThrow('consecutive slashes');
    expect(() => vault.store('__vault_test', 'value')).toThrow('reserved');
    expect(() => vault.delete('__vault_verify__')).toThrow('reserved');
  });

  it('should accept valid paths', () => {
    expect(() => vault.store('simple', 'v')).not.toThrow();
    expect(() => vault.store('a/b', 'v')).not.toThrow();
    expect(() => vault.store('a/b/c/d/e', 'v')).not.toThrow();
    expect(() => vault.store('with-dashes', 'v')).not.toThrow();
    expect(() => vault.store('with_underscores', 'v')).not.toThrow();
    expect(() => vault.store('with.dots', 'v')).not.toThrow();
  });
});

describe('VaultEngine — cross-session persistence', () => {
  let tmpDir: string;
  let dbPath: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-persist-'));
    dbPath = path.join(tmpDir, 'vault.db');
  });

  afterAll(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should persist secrets across vault instances', () => {
    // Session 1: init and store
    const vault1 = new VaultEngine(dbPath);
    vault1.init(PASSPHRASE);
    vault1.store('persistent/secret', 'survive-restart', { type: 'api-key' });
    vault1.close();

    // Session 2: reopen and verify
    const vault2 = new VaultEngine(dbPath);
    vault2.unlock(PASSPHRASE);
    const entry = vault2.get('persistent/secret');
    expect(entry!.value).toBe('survive-restart');
    expect(entry!.metadata.type).toBe('api-key');
    vault2.close();
  });

  it('should reject wrong passphrase on reopen', () => {
    const vault3 = new VaultEngine(dbPath);
    expect(() => vault3.unlock('wrong-passphrase')).toThrow('Invalid passphrase');
    vault3.close();
  });
});
