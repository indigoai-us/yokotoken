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

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-init-'));
    dbPath = path.join(tmpDir, 'vault.db');
    vault = await VaultEngine.open(dbPath);
  });

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should initialize a new vault and create the database file', async () => {
    await vault.init(PASSPHRASE);
    expect(vault.isInitialized).toBe(true);
    expect(vault.isUnlocked).toBe(true);
    expect(fs.existsSync(dbPath)).toBe(true);
  });

  it('should reject double initialization', async () => {
    await expect(vault.init(PASSPHRASE)).rejects.toThrow('already initialized');
  });
});

describe('VaultEngine — unlock / lock', () => {
  let vault: VaultEngine;
  let tmpDir: string;
  let dbPath: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-lock-'));
    dbPath = path.join(tmpDir, 'vault.db');
    vault = await VaultEngine.open(dbPath);
    await vault.init(PASSPHRASE);
    await vault.store('test/setup', 'setup-value');
    await vault.lock();
  });

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should reject wrong passphrase', async () => {
    await expect(vault.unlock('wrong-passphrase')).rejects.toThrow('Invalid passphrase');
    expect(vault.isUnlocked).toBe(false);
  });

  it('should fail operations when locked', async () => {
    await expect(vault.store('test/locked', 'value')).rejects.toThrow('Vault is locked');
    await expect(vault.get('test/locked')).rejects.toThrow('Vault is locked');
    expect(() => vault.list()).toThrow('Vault is locked');
    expect(() => vault.delete('test/locked')).toThrow('Vault is locked');
  });

  it('should unlock with correct passphrase and access stored secrets', async () => {
    await vault.unlock(PASSPHRASE);
    expect(vault.isUnlocked).toBe(true);
    const entry = await vault.get('test/setup');
    expect(entry).not.toBeNull();
    expect(entry!.value).toBe('setup-value');
  });

  it('should lock and become inaccessible again', async () => {
    await vault.lock();
    expect(vault.isUnlocked).toBe(false);
    await expect(vault.get('test/setup')).rejects.toThrow('Vault is locked');
  });
});

describe('VaultEngine — encryption roundtrip', () => {
  let vault: VaultEngine;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-roundtrip-'));
    const dbPath = path.join(tmpDir, 'vault.db');
    vault = await VaultEngine.open(dbPath);
    await vault.init(PASSPHRASE);
  });

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should store and retrieve a simple secret', async () => {
    await vault.store('api/key', 'sk-1234567890abcdef');
    const entry = await vault.get('api/key');
    expect(entry).not.toBeNull();
    expect(entry!.value).toBe('sk-1234567890abcdef');
    expect(entry!.path).toBe('api/key');
  });

  it('should store and retrieve with metadata', async () => {
    await vault.store('slack/token', 'xoxb-1234', {
      type: 'oauth-token',
      description: 'Slack bot token for Indigo workspace',
    });
    const entry = await vault.get('slack/token');
    expect(entry!.value).toBe('xoxb-1234');
    expect(entry!.metadata.type).toBe('oauth-token');
    expect(entry!.metadata.description).toBe('Slack bot token for Indigo workspace');
  });

  it('should return null for nonexistent secret', async () => {
    const entry = await vault.get('does/not/exist');
    expect(entry).toBeNull();
  });

  it('should handle empty, special, unicode, and multi-line values', async () => {
    // Empty
    await vault.store('empty/value', '');
    expect((await vault.get('empty/value'))!.value).toBe('');

    // Special characters
    const special = 'p@$$w0rd!#%^&*(){}[]|\\:";\'<>,.?/~`';
    await vault.store('special/chars', special);
    expect((await vault.get('special/chars'))!.value).toBe(special);

    // Unicode
    const unicode = '密码 пароль 🔐🗝️ مفتاح';
    await vault.store('unicode/password', unicode);
    expect((await vault.get('unicode/password'))!.value).toBe(unicode);

    // Multi-line
    const multiline = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/yGFz
ygDQPF6dMluSVnQoYy8=
-----END RSA PRIVATE KEY-----`;
    await vault.store('certs/private-key', multiline, { type: 'certificate' });
    expect((await vault.get('certs/private-key'))!.value).toBe(multiline);
  });

  it('should handle large values', async () => {
    const large = 'x'.repeat(100_000);
    await vault.store('large/secret', large);
    expect((await vault.get('large/secret'))!.value).toBe(large);
  });

  it('should overwrite existing secret', async () => {
    await vault.store('mutable/key', 'version-1');
    await vault.store('mutable/key', 'version-2');
    expect((await vault.get('mutable/key'))!.value).toBe('version-2');
  });
});

describe('VaultEngine — path-based organization', () => {
  let vault: VaultEngine;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-paths-'));
    const dbPath = path.join(tmpDir, 'vault.db');
    vault = await VaultEngine.open(dbPath);
    await vault.init(PASSPHRASE);
    await vault.store('aws/dev/access-key', 'AKIA-dev-123', { type: 'api-key' });
    await vault.store('aws/dev/secret-key', 'secret-dev-456', { type: 'api-key' });
    await vault.store('aws/prod/access-key', 'AKIA-prod-789', { type: 'api-key' });
    await vault.store('slack/indigo/bot-token', 'xoxb-bot', { type: 'oauth-token' });
    await vault.store('slack/indigo/user-token', 'xoxp-user', { type: 'oauth-token' });
    await vault.store('github/pat', 'ghp_xxxxx', { type: 'api-key' });
  });

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
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

  it('should get individual secrets with correct values', async () => {
    const entry = await vault.get('aws/dev/access-key');
    expect(entry!.value).toBe('AKIA-dev-123');
    expect(entry!.metadata.type).toBe('api-key');
  });

  it('should delete a secret and handle nonexistent deletes', async () => {
    expect(vault.delete('github/pat')).toBe(true);
    expect(await vault.get('github/pat')).toBeNull();
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

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should report status for uninitialized vault', async () => {
    vault = await VaultEngine.open(dbPath);
    const status = vault.status();
    expect(status.initialized).toBe(false);
    expect(status.locked).toBe(true);
    expect(status.secretCount).toBe(0);
    expect(status.vaultPath).toBe(dbPath);
  });

  it('should report correct status after init and after storing secrets', async () => {
    await vault.init(PASSPHRASE);
    let status = vault.status();
    expect(status.initialized).toBe(true);
    expect(status.locked).toBe(false);
    expect(status.secretCount).toBe(0);

    await vault.store('a/secret', 'value-1');
    await vault.store('b/secret', 'value-2');
    status = vault.status();
    expect(status.secretCount).toBe(2);

    await vault.lock();
    status = vault.status();
    expect(status.locked).toBe(true);
  });
});

describe('VaultEngine — path validation', () => {
  let vault: VaultEngine;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-validation-'));
    const dbPath = path.join(tmpDir, 'vault.db');
    vault = await VaultEngine.open(dbPath);
    await vault.init(PASSPHRASE);
  });

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should reject invalid paths', async () => {
    await expect(vault.store('', 'value')).rejects.toThrow('cannot be empty');
    await expect(vault.store('   ', 'value')).rejects.toThrow('cannot be empty');
    await expect(vault.store('/leading/slash', 'value')).rejects.toThrow('must not start or end with /');
    await expect(vault.store('trailing/slash/', 'value')).rejects.toThrow('must not start or end with /');
    await expect(vault.store('double//slash', 'value')).rejects.toThrow('consecutive slashes');
    await expect(vault.store('__vault_test', 'value')).rejects.toThrow('reserved');
    expect(() => vault.delete('__vault_verify__')).toThrow('reserved');
  });

  it('should accept valid paths', async () => {
    await vault.store('simple', 'v');
    await vault.store('a/b', 'v');
    await vault.store('a/b/c/d/e', 'v');
    await vault.store('with-dashes', 'v');
    await vault.store('with_underscores', 'v');
    await vault.store('with.dots', 'v');
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

  it('should persist secrets across vault instances', async () => {
    // Session 1: init and store
    const vault1 = await VaultEngine.open(dbPath);
    await vault1.init(PASSPHRASE);
    await vault1.store('persistent/secret', 'survive-restart', { type: 'api-key' });
    await vault1.close();

    // Session 2: reopen and verify
    const vault2 = await VaultEngine.open(dbPath);
    await vault2.unlock(PASSPHRASE);
    const entry = await vault2.get('persistent/secret');
    expect(entry!.value).toBe('survive-restart');
    expect(entry!.metadata.type).toBe('api-key');
    await vault2.close();
  });

  it('should reject wrong passphrase on reopen', async () => {
    const vault3 = await VaultEngine.open(dbPath);
    await expect(vault3.unlock('wrong-passphrase')).rejects.toThrow('Invalid passphrase');
    await vault3.close();
  });
});
