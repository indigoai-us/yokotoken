/**
 * Tests for vault backup and migration (US-011).
 *
 * Coverage:
 * - Encrypted backup creation
 * - Backup restore with passphrase verification
 * - Invalid backup handling (wrong passphrase, corrupted file, wrong format)
 * - Export secrets as .env format
 * - Import secrets from .env files
 * - Duplicate detection and conflict strategies (skip, overwrite, rename)
 * - .env parsing (quoted, unquoted, comments, export prefix, escape sequences)
 * - Path conversion helpers (pathToEnvName, envNameToPath)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { VaultEngine } from '../src/vault.js';
import {
  createBackup,
  restoreBackup,
  exportEnv,
  importEnv,
  parseEnvFile,
  pathToEnvName,
  envNameToPath,
  detectImportDuplicates,
  BACKUP_MAGIC,
  BACKUP_VERSION,
  BACKUP_HEADER_SIZE,
} from '../src/backup.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'backup-test-passphrase-2026';

// ─── Path conversion helpers ─────────────────────────────────────────

describe('pathToEnvName', () => {
  it('should convert vault paths to env var names', () => {
    expect(pathToEnvName('aws/dev/access-key')).toBe('AWS_DEV_ACCESS_KEY');
    expect(pathToEnvName('slack/indigo/bot-token')).toBe('SLACK_INDIGO_BOT_TOKEN');
    expect(pathToEnvName('github/pat')).toBe('GITHUB_PAT');
    expect(pathToEnvName('simple')).toBe('SIMPLE');
    expect(pathToEnvName('with.dots')).toBe('WITH_DOTS');
  });

  it('should strip prefix before converting', () => {
    expect(pathToEnvName('aws/dev/access-key', 'aws/')).toBe('DEV_ACCESS_KEY');
    expect(pathToEnvName('slack/indigo/bot-token', 'slack/indigo/')).toBe('BOT_TOKEN');
  });

  it('should handle empty paths and edge cases', () => {
    expect(pathToEnvName('')).toBe('');
    expect(pathToEnvName('a')).toBe('A');
    expect(pathToEnvName('a/b/c/d/e')).toBe('A_B_C_D_E');
  });
});

describe('envNameToPath', () => {
  it('should convert env var names to vault paths', () => {
    expect(envNameToPath('AWS_ACCESS_KEY')).toBe('aws/access/key');
    expect(envNameToPath('SLACK_BOT_TOKEN')).toBe('slack/bot/token');
    expect(envNameToPath('SIMPLE')).toBe('simple');
  });

  it('should prepend prefix when provided', () => {
    expect(envNameToPath('ACCESS_KEY', 'aws/dev/')).toBe('aws/dev/access/key');
    expect(envNameToPath('TOKEN', 'slack/')).toBe('slack/token');
  });
});

// ─── .env parsing ────────────────────────────────────────────────────

describe('parseEnvFile', () => {
  it('should parse basic KEY=value entries', () => {
    const content = 'KEY1=value1\nKEY2=value2\n';
    const entries = parseEnvFile(content);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toEqual({ key: 'KEY1', value: 'value1' });
    expect(entries[1]).toEqual({ key: 'KEY2', value: 'value2' });
  });

  it('should parse double-quoted values with escape sequences', () => {
    const content = 'KEY="hello\\nworld"\nPASS="p@ss\\"word"\n';
    const entries = parseEnvFile(content);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toEqual({ key: 'KEY', value: 'hello\nworld' });
    expect(entries[1]).toEqual({ key: 'PASS', value: 'p@ss"word' });
  });

  it('should parse single-quoted values as literal', () => {
    const content = "KEY='hello\\nworld'\n";
    const entries = parseEnvFile(content);
    expect(entries).toHaveLength(1);
    // Single quotes = literal, no escape processing
    expect(entries[0]).toEqual({ key: 'KEY', value: 'hello\\nworld' });
  });

  it('should skip comments and blank lines', () => {
    const content = '# This is a comment\n\nKEY=value\n   \n# Another comment\nKEY2=value2\n';
    const entries = parseEnvFile(content);
    expect(entries).toHaveLength(2);
    expect(entries[0].key).toBe('KEY');
    expect(entries[1].key).toBe('KEY2');
  });

  it('should strip "export " prefix', () => {
    const content = 'export KEY1=value1\nexport KEY2="value2"\n';
    const entries = parseEnvFile(content);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toEqual({ key: 'KEY1', value: 'value1' });
    expect(entries[1]).toEqual({ key: 'KEY2', value: 'value2' });
  });

  it('should handle values with = signs', () => {
    const content = 'URL=https://example.com?a=1&b=2\n';
    const entries = parseEnvFile(content);
    expect(entries).toHaveLength(1);
    expect(entries[0].value).toBe('https://example.com?a=1&b=2');
  });

  it('should handle empty values', () => {
    const content = 'EMPTY=\n';
    const entries = parseEnvFile(content);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual({ key: 'EMPTY', value: '' });
  });

  it('should skip lines without = sign', () => {
    const content = 'NOEQ\nKEY=value\n';
    const entries = parseEnvFile(content);
    expect(entries).toHaveLength(1);
    expect(entries[0].key).toBe('KEY');
  });

  it('should handle backslash escaping in double quotes', () => {
    const content = 'KEY="path\\\\to\\\\file"\n';
    const entries = parseEnvFile(content);
    expect(entries).toHaveLength(1);
    expect(entries[0].value).toBe('path\\to\\file');
  });
});

// ─── Encrypted backup / restore ──────────────────────────────────────

describe('createBackup', () => {
  let tmpDir: string;
  let vaultPath: string;
  let backupPath: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-backup-create-'));
    vaultPath = path.join(tmpDir, 'vault.db');
    backupPath = path.join(tmpDir, 'backup.hqvb');

    // Create and populate a vault
    const vault = await VaultEngine.open(vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('aws/access-key', 'AKIA1234', { type: 'api-key' });
    await vault.store('aws/secret-key', 'secret5678', { type: 'api-key' });
    await vault.store('slack/token', 'xoxb-abcd', { type: 'oauth-token', description: 'Slack bot' });
    await vault.close();
  });

  afterAll(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should create an encrypted backup file', async () => {
    const result = await createBackup(vaultPath, backupPath, PASSPHRASE);
    expect(result.success).toBe(true);
    expect(result.filepath).toBe(backupPath);
    expect(result.sizeBytes).toBeGreaterThan(0);
    expect(fs.existsSync(backupPath)).toBe(true);
  });

  it('should write correct magic bytes and version', () => {
    const data = fs.readFileSync(backupPath);
    const magic = data.subarray(0, 4);
    expect(magic.equals(BACKUP_MAGIC)).toBe(true);
    expect(data.readUInt8(4)).toBe(BACKUP_VERSION);
  });

  it('should produce an encrypted file that is not the raw SQLite database', () => {
    const backupData = fs.readFileSync(backupPath);
    const vaultData = fs.readFileSync(vaultPath);
    // The backup should be larger (header + encryption overhead)
    expect(backupData.length).toBeGreaterThan(vaultData.length);
    // Should NOT start with SQLite magic "SQLite format 3"
    const sqliteMagic = Buffer.from('SQLite format 3');
    const contentAfterHeader = backupData.subarray(BACKUP_HEADER_SIZE);
    expect(contentAfterHeader.subarray(0, sqliteMagic.length).equals(sqliteMagic)).toBe(false);
  });

  it('should throw if vault database does not exist', async () => {
    await expect(createBackup('/nonexistent/vault.db', backupPath, PASSPHRASE)).rejects.toThrow('not found');
  });

  it('should throw if passphrase is empty', async () => {
    await expect(createBackup(vaultPath, backupPath, '')).rejects.toThrow('empty');
  });

  it('should create output directory if it does not exist', async () => {
    const nestedPath = path.join(tmpDir, 'nested', 'dir', 'backup.hqvb');
    const result = await createBackup(vaultPath, nestedPath, PASSPHRASE);
    expect(result.success).toBe(true);
    expect(fs.existsSync(nestedPath)).toBe(true);
  });
});

describe('restoreBackup', () => {
  let tmpDir: string;
  let vaultPath: string;
  let backupPath: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-backup-restore-'));
    vaultPath = path.join(tmpDir, 'vault.db');
    backupPath = path.join(tmpDir, 'backup.hqvb');

    // Create and populate a vault
    const vault = await VaultEngine.open(vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('aws/access-key', 'AKIA1234', { type: 'api-key' });
    await vault.store('aws/secret-key', 'secret5678', { type: 'api-key' });
    await vault.store('slack/token', 'xoxb-abcd', { type: 'oauth-token', description: 'Slack bot' });
    await vault.close();

    // Create backup
    await createBackup(vaultPath, backupPath, PASSPHRASE);
  });

  afterAll(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should restore vault from backup and recover all secrets', async () => {
    const restorePath = path.join(tmpDir, 'restored.db');
    const result = await restoreBackup(backupPath, restorePath, PASSPHRASE);

    expect(result.success).toBe(true);
    expect(result.secretCount).toBe(3);
    expect(fs.existsSync(restorePath)).toBe(true);

    // Verify the restored vault contains the correct secrets
    const vault = await VaultEngine.open(restorePath);
    await vault.unlock(PASSPHRASE);

    const accessKey = await vault.get('aws/access-key');
    expect(accessKey).not.toBeNull();
    expect(accessKey!.value).toBe('AKIA1234');
    expect(accessKey!.metadata.type).toBe('api-key');

    const slackToken = await vault.get('slack/token');
    expect(slackToken).not.toBeNull();
    expect(slackToken!.value).toBe('xoxb-abcd');
    expect(slackToken!.metadata.description).toBe('Slack bot');

    await vault.close();
  });

  it('should fail with wrong passphrase', async () => {
    const restorePath = path.join(tmpDir, 'bad-restore.db');
    await expect(restoreBackup(backupPath, restorePath, 'wrong-passphrase')).rejects.toThrow(
      'Failed to decrypt backup'
    );
    // Should not leave a file behind on failure
    expect(fs.existsSync(restorePath)).toBe(false);
  });

  it('should fail with nonexistent backup file', async () => {
    const restorePath = path.join(tmpDir, 'nope.db');
    await expect(restoreBackup('/nonexistent/backup.hqvb', restorePath, PASSPHRASE)).rejects.toThrow(
      'not found'
    );
  });

  it('should fail with corrupted backup file', async () => {
    const corruptPath = path.join(tmpDir, 'corrupt.hqvb');
    fs.writeFileSync(corruptPath, Buffer.from('HQVB\x01garbage-data-not-encrypted'));
    const restorePath = path.join(tmpDir, 'from-corrupt.db');
    await expect(restoreBackup(corruptPath, restorePath, PASSPHRASE)).rejects.toThrow();
  });

  it('should fail with wrong magic bytes', async () => {
    const badPath = path.join(tmpDir, 'bad-magic.dat');
    const data = Buffer.alloc(100);
    data.write('XXXX', 0, 'ascii');
    fs.writeFileSync(badPath, data);
    const restorePath = path.join(tmpDir, 'from-bad-magic.db');
    await expect(restoreBackup(badPath, restorePath, PASSPHRASE)).rejects.toThrow('wrong magic bytes');
  });

  it('should fail with too-small file', async () => {
    const smallPath = path.join(tmpDir, 'too-small.hqvb');
    fs.writeFileSync(smallPath, Buffer.from('HQ'));
    const restorePath = path.join(tmpDir, 'from-small.db');
    await expect(restoreBackup(smallPath, restorePath, PASSPHRASE)).rejects.toThrow('too small');
  });

  it('should fail with unsupported version', async () => {
    const badVersionPath = path.join(tmpDir, 'bad-version.hqvb');
    const data = Buffer.alloc(BACKUP_HEADER_SIZE + 100);
    BACKUP_MAGIC.copy(data, 0);
    data.writeUInt8(0xFF, 4); // bad version
    fs.writeFileSync(badVersionPath, data);
    const restorePath = path.join(tmpDir, 'from-bad-version.db');
    await expect(restoreBackup(badVersionPath, restorePath, PASSPHRASE)).rejects.toThrow('Unsupported backup version');
  });

  it('should overwrite existing vault when restoring', async () => {
    // First create a vault at the target path
    const targetPath = path.join(tmpDir, 'overwrite-target.db');
    const oldVault = await VaultEngine.open(targetPath);
    await oldVault.init('different-passphrase');
    await oldVault.store('old/secret', 'old-value');
    await oldVault.close();

    // Restore over it
    const result = await restoreBackup(backupPath, targetPath, PASSPHRASE);
    expect(result.success).toBe(true);
    expect(result.secretCount).toBe(3);

    // Verify old secrets are gone, new secrets are present
    const vault = await VaultEngine.open(targetPath);
    await vault.unlock(PASSPHRASE);
    expect(await vault.get('old/secret')).toBeNull();
    expect((await vault.get('aws/access-key'))!.value).toBe('AKIA1234');
    await vault.close();
  });

  it('should create output directory if it does not exist', async () => {
    const nestedPath = path.join(tmpDir, 'deep', 'nested', 'restored.db');
    const result = await restoreBackup(backupPath, nestedPath, PASSPHRASE);
    expect(result.success).toBe(true);
    expect(fs.existsSync(nestedPath)).toBe(true);
  });
});

// ─── Backup roundtrip ────────────────────────────────────────────────

describe('backup roundtrip — full cycle', () => {
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-backup-roundtrip-'));
  });

  afterAll(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should preserve all secrets through backup and restore cycle', async () => {
    const vaultPath = path.join(tmpDir, 'original.db');
    const backupPath = path.join(tmpDir, 'roundtrip.hqvb');
    const restorePath = path.join(tmpDir, 'roundtrip-restored.db');

    // Create original vault with diverse secrets
    const vault = await VaultEngine.open(vaultPath);
    await vault.init(PASSPHRASE);
    await vault.store('simple', 'value');
    await vault.store('nested/deep/path', 'deep-value');
    await vault.store('unicode/key', '\u5bc6\u7801 \u043f\u0430\u0440\u043e\u043b\u044c');
    await vault.store('multiline/cert', '-----BEGIN CERT-----\nMIIEow...\n-----END CERT-----');
    await vault.store('empty/val', '');
    await vault.store('special/chars', 'p@$$w0rd!#%^&*()');
    await vault.close();

    // Backup
    const backupResult = await createBackup(vaultPath, backupPath, PASSPHRASE);
    expect(backupResult.success).toBe(true);

    // Restore to new location
    const restoreResult = await restoreBackup(backupPath, restorePath, PASSPHRASE);
    expect(restoreResult.success).toBe(true);
    expect(restoreResult.secretCount).toBe(6);

    // Verify every secret matches
    const restored = await VaultEngine.open(restorePath);
    await restored.unlock(PASSPHRASE);

    expect((await restored.get('simple'))!.value).toBe('value');
    expect((await restored.get('nested/deep/path'))!.value).toBe('deep-value');
    expect((await restored.get('unicode/key'))!.value).toBe('\u5bc6\u7801 \u043f\u0430\u0440\u043e\u043b\u044c');
    expect((await restored.get('multiline/cert'))!.value).toBe('-----BEGIN CERT-----\nMIIEow...\n-----END CERT-----');
    expect((await restored.get('empty/val'))!.value).toBe('');
    expect((await restored.get('special/chars'))!.value).toBe('p@$$w0rd!#%^&*()');

    await restored.close();
  });
});

// ─── Export .env ─────────────────────────────────────────────────────

describe('exportEnv', () => {
  let vault: VaultEngine;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-export-'));
    const dbPath = path.join(tmpDir, 'vault.db');
    vault = await VaultEngine.open(dbPath);
    await vault.init(PASSPHRASE);
    await vault.store('aws/access-key', 'AKIA1234', { type: 'api-key' });
    await vault.store('aws/secret-key', 'secret5678', { type: 'api-key' });
    await vault.store('slack/bot-token', 'xoxb-abcd', { type: 'oauth-token', description: 'Slack bot token' });
    await vault.store('db/password', 'p@ss"word\nnewline', { type: 'password' });
  });

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should export all secrets as .env format', async () => {
    const result = await exportEnv(vault);
    expect(result.success).toBe(true);
    expect(result.entryCount).toBe(4);
    expect(result.output).toContain('AWS_ACCESS_KEY="AKIA1234"');
    expect(result.output).toContain('AWS_SECRET_KEY="secret5678"');
    expect(result.output).toContain('SLACK_BOT_TOKEN="xoxb-abcd"');
  });

  it('should escape special characters in values', async () => {
    const result = await exportEnv(vault);
    // Double quotes and newlines should be escaped
    expect(result.output).toContain('DB_PASSWORD="p@ss\\"word\\n');
  });

  it('should include description as comment', async () => {
    const result = await exportEnv(vault);
    expect(result.output).toContain('# Slack bot token');
  });

  it('should filter by prefix', async () => {
    const result = await exportEnv(vault, 'aws/');
    expect(result.entryCount).toBe(2);
    expect(result.output).toContain('ACCESS_KEY="AKIA1234"');
    expect(result.output).toContain('SECRET_KEY="secret5678"');
    expect(result.output).not.toContain('SLACK');
  });

  it('should throw if vault is locked', async () => {
    await vault.lock();
    await expect(exportEnv(vault)).rejects.toThrow('locked');
    await vault.unlock(PASSPHRASE);
  });

  it('should return empty output when no secrets match prefix', async () => {
    const result = await exportEnv(vault, 'nonexistent/');
    expect(result.entryCount).toBe(0);
    expect(result.output).toBe('');
  });
});

// ─── Import .env ─────────────────────────────────────────────────────

describe('importEnv', () => {
  let vault: VaultEngine;
  let tmpDir: string;
  let dbPath: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-import-'));
    dbPath = path.join(tmpDir, 'vault.db');
  });

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should import secrets from .env content', async () => {
    vault = await VaultEngine.open(dbPath);
    await vault.init(PASSPHRASE);

    const envContent = `
API_KEY=sk-1234567890
SECRET_TOKEN=ghp-abcdef
DB_HOST=localhost
`;

    const result = await importEnv(vault, envContent);
    expect(result.success).toBe(true);
    expect(result.imported).toBe(3);
    expect(result.skipped).toBe(0);

    // Verify secrets were stored
    expect((await vault.get('api/key'))!.value).toBe('sk-1234567890');
    expect((await vault.get('secret/token'))!.value).toBe('ghp-abcdef');
    expect((await vault.get('db/host'))!.value).toBe('localhost');
  });

  it('should import with prefix', async () => {
    const envContent = 'REGION=us-east-1\n';
    const result = await importEnv(vault, envContent, 'skip', 'myapp/');
    expect(result.imported).toBe(1);
    expect((await vault.get('myapp/region'))!.value).toBe('us-east-1');
  });

  it('should skip duplicates with skip strategy', async () => {
    // 'api/key' already exists from the previous test
    const envContent = 'API_KEY=new-value\nNEW_KEY=fresh-value\n';
    const result = await importEnv(vault, envContent, 'skip');
    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(1);
    // Original value should be preserved
    expect((await vault.get('api/key'))!.value).toBe('sk-1234567890');
    expect((await vault.get('new/key'))!.value).toBe('fresh-value');
  });

  it('should overwrite duplicates with overwrite strategy', async () => {
    const envContent = 'API_KEY=overwritten-value\n';
    const result = await importEnv(vault, envContent, 'overwrite');
    expect(result.overwritten).toBe(1);
    expect(result.imported).toBe(0);
    expect((await vault.get('api/key'))!.value).toBe('overwritten-value');
  });

  it('should rename duplicates with rename strategy', async () => {
    const envContent = 'API_KEY=renamed-value\n';
    const result = await importEnv(vault, envContent, 'rename');
    expect(result.renamed).toBe(1);
    expect(result.imported).toBe(0);
    // Original should be untouched
    expect((await vault.get('api/key'))!.value).toBe('overwritten-value');
    // Renamed version should exist
    expect((await vault.get('api/key-imported-1'))!.value).toBe('renamed-value');
  });

  it('should handle multiple renames for the same path', async () => {
    const envContent = 'API_KEY=renamed-again\n';
    const result = await importEnv(vault, envContent, 'rename');
    expect(result.renamed).toBe(1);
    // -imported-1 already exists, so should use -imported-2
    expect((await vault.get('api/key-imported-2'))!.value).toBe('renamed-again');
  });

  it('should throw if vault is locked', async () => {
    await vault.lock();
    await expect(importEnv(vault, 'KEY=value')).rejects.toThrow('locked');
    await vault.unlock(PASSPHRASE);
  });

  it('should handle empty .env content', async () => {
    const result = await importEnv(vault, '');
    expect(result.success).toBe(true);
    expect(result.imported).toBe(0);
  });

  it('should handle .env with only comments', async () => {
    const result = await importEnv(vault, '# Just a comment\n# Another one\n');
    expect(result.success).toBe(true);
    expect(result.imported).toBe(0);
  });
});

// ─── detectImportDuplicates ──────────────────────────────────────────

describe('detectImportDuplicates', () => {
  let vault: VaultEngine;
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-detect-dupes-'));
    const dbPath = path.join(tmpDir, 'vault.db');
    vault = await VaultEngine.open(dbPath);
    await vault.init(PASSPHRASE);
    await vault.store('aws/key', 'AKIA1234');
    await vault.store('slack/token', 'xoxb-abcd');
  });

  afterAll(async () => {
    try { await vault.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should detect duplicates', async () => {
    const envContent = 'AWS_KEY=new\nSLACK_TOKEN=new\nNEW_SECRET=value\n';
    const duplicates = await detectImportDuplicates(vault, envContent);
    expect(duplicates).toHaveLength(2);
    expect(duplicates).toContain('aws/key');
    expect(duplicates).toContain('slack/token');
  });

  it('should return empty array when no duplicates', async () => {
    const envContent = 'BRAND_NEW=value\n';
    const duplicates = await detectImportDuplicates(vault, envContent);
    expect(duplicates).toHaveLength(0);
  });

  it('should detect duplicates with prefix', async () => {
    const envContent = 'KEY=new\n';
    const duplicates = await detectImportDuplicates(vault, envContent, 'aws/');
    expect(duplicates).toHaveLength(1);
    expect(duplicates[0]).toBe('aws/key');
  });

  it('should throw if vault is locked', async () => {
    await vault.lock();
    await expect(detectImportDuplicates(vault, 'KEY=value')).rejects.toThrow('locked');
    await vault.unlock(PASSPHRASE);
  });
});

// ─── Import from exported .env (full cycle) ──────────────────────────

describe('export-import roundtrip', () => {
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-export-import-'));
  });

  afterAll(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should preserve values through export then import cycle', async () => {
    // Create source vault
    const srcPath = path.join(tmpDir, 'source.db');
    const src = await VaultEngine.open(srcPath);
    await src.init(PASSPHRASE);
    await src.store('config/api-key', 'sk-test-key-12345');
    await src.store('config/db-password', 'p@$$word!');
    await src.store('config/jwt-secret', 'super-secret-jwt-256');

    // Export
    const exported = await exportEnv(src, 'config/');
    expect(exported.entryCount).toBe(3);
    await src.close();

    // Create target vault
    const tgtPath = path.join(tmpDir, 'target.db');
    const tgt = await VaultEngine.open(tgtPath);
    await tgt.init(PASSPHRASE);

    // Import (using prefix to reconstruct paths)
    const result = await importEnv(tgt, exported.output, 'skip', 'config/');
    expect(result.imported).toBe(3);

    // Verify
    expect((await tgt.get('config/api/key'))!.value).toBe('sk-test-key-12345');
    expect((await tgt.get('config/db/password'))!.value).toBe('p@$$word!');
    expect((await tgt.get('config/jwt/secret'))!.value).toBe('super-secret-jwt-256');

    await tgt.close();
  });
});

// ─── Backup constants ────────────────────────────────────────────────

describe('backup constants', () => {
  it('should have correct magic bytes', () => {
    expect(BACKUP_MAGIC.toString('ascii')).toBe('HQVB');
    expect(BACKUP_MAGIC.length).toBe(4);
  });

  it('should have version 1', () => {
    expect(BACKUP_VERSION).toBe(1);
  });

  it('should have correct header size (4 + 1 + 16 + 24 = 45)', () => {
    expect(BACKUP_HEADER_SIZE).toBe(45);
  });
});
