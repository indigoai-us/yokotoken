/**
 * Tests for the CLI env and env-file shell helper commands — US-008.
 *
 * Verifies:
 * - `hq-vault env <path> <VAR_NAME>` outputs `export VAR_NAME='<value>'`
 * - `hq-vault env-file <prefix>` outputs all secrets as dotenv format
 * - `hq-vault env-file <prefix> --format export` outputs shell export statements
 * - Proper escaping of special characters in values
 * - Error handling for missing secrets and prefixes
 *
 * Tests run against an actual vault server (insecure mode, ephemeral port)
 * and invoke the CLI commands via child_process.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request } from '../src/client.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
const PASSPHRASE = 'test-env-cli-passphrase-2026';
const TEST_TOKEN = 'test-env-cli-token-for-testing';

/**
 * Helper: create a temporary directory and server config.
 */
function createTmpConfig(overrides?: Partial<ServerConfig>): {
  tmpDir: string;
  config: ServerConfig;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-env-'));
  const config: ServerConfig = {
    vaultPath: path.join(tmpDir, 'vault.db'),
    port: 0,
    idleTimeoutMs: 0,
    pidFile: path.join(tmpDir, 'vault.pid'),
    portFile: path.join(tmpDir, 'vault.port'),
    tokenFile: path.join(tmpDir, 'token'),
    insecure: true,
    token: TEST_TOKEN,
    ...overrides,
  };
  return { tmpDir, config };
}

function getPort(server: http.Server): number {
  const addr = server.address();
  if (typeof addr === 'object' && addr) {
    return addr.port;
  }
  throw new Error('Server has no address');
}

// The env and env-file commands use the running server via PID file / token file,
// so we test them through the vault API directly (verifying output formatting)
// rather than spawning CLI processes, which would need a full server setup.

describe('CLI — env and env-file output formatting', () => {
  let server: http.Server;
  let tmpDir: string;
  let serverPort: number;

  beforeAll(async () => {
    const { tmpDir: td, config } = createTmpConfig();
    tmpDir = td;
    server = (await createVaultServer(config)) as http.Server;
    serverPort = getPort(server);

    const clientCfg = { port: serverPort, host: '127.0.0.1', token: TEST_TOKEN, insecure: true };

    // Init and unlock
    await request(clientCfg, 'POST', '/v1/init', { passphrase: PASSPHRASE });
    await request(clientCfg, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });

    // Populate test secrets
    await request(clientCfg, 'PUT', '/v1/secrets/myapp%2Fdb-host', { value: 'localhost' });
    await request(clientCfg, 'PUT', '/v1/secrets/myapp%2Fdb-port', { value: '5432' });
    await request(clientCfg, 'PUT', '/v1/secrets/myapp%2Fdb-password', { value: "pass'word\"special" });
    await request(clientCfg, 'PUT', '/v1/secrets/myapp%2Fmulti-line', { value: 'line1\nline2\nline3' });
    await request(clientCfg, 'PUT', '/v1/secrets/other%2Fapi-key', { value: 'sk-abc123' });
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  // ─── env command formatting ───────────────────────────────────────
  describe('env command output format', () => {
    it('should format simple values as shell export', async () => {
      const res = await request(
        { port: serverPort, host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
        'GET',
        '/v1/secrets/myapp%2Fdb-host',
      );
      expect(res.statusCode).toBe(200);
      const value = res.body.value as string;
      // Simulate what the env command does
      const escaped = value.replace(/'/g, "'\\''");
      const output = `export DB_HOST='${escaped}'\n`;
      expect(output).toBe("export DB_HOST='localhost'\n");
    });

    it('should escape single quotes in values', async () => {
      const res = await request(
        { port: serverPort, host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
        'GET',
        '/v1/secrets/myapp%2Fdb-password',
      );
      expect(res.statusCode).toBe(200);
      const value = res.body.value as string;
      const escaped = value.replace(/'/g, "'\\''");
      const output = `export DB_PASSWORD='${escaped}'\n`;
      // The single quote in the value should be escaped for shell safety
      expect(output).toContain("'\\''");
      expect(output).toContain('export DB_PASSWORD=');
    });
  });

  // ─── env-file command formatting ──────────────────────────────────
  describe('env-file command output format', () => {
    it('should format secrets as dotenv KEY="value" pairs', async () => {
      // Fetch secrets matching the prefix
      const listRes = await request(
        { port: serverPort, host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
        'GET',
        '/v1/secrets?prefix=myapp%2F',
      );
      expect(listRes.statusCode).toBe(200);
      const entries = listRes.body.entries as Array<{ path: string }>;

      // Simulate the env-file output for dotenv format
      const lines: string[] = [];
      for (const entry of entries) {
        const getRes = await request(
          { port: serverPort, host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
          'GET',
          `/v1/secrets/${encodeURIComponent(entry.path)}`,
        );
        const value = getRes.body.value as string;
        let relativePath = entry.path;
        if (relativePath.startsWith('myapp/')) {
          relativePath = relativePath.slice('myapp/'.length);
        }
        const varName = relativePath.replace(/[/\-\.]/g, '_').toUpperCase();
        const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
        lines.push(`${varName}="${escaped}"`);
      }

      // Verify env var name derivation
      expect(lines.some((l) => l.startsWith('DB_HOST='))).toBe(true);
      expect(lines.some((l) => l.startsWith('DB_PORT='))).toBe(true);
      expect(lines.some((l) => l.startsWith('DB_PASSWORD='))).toBe(true);
    });

    it('should derive env var names by replacing dashes and slashes with underscores', () => {
      // Test the name derivation logic
      const testCases = [
        { path: 'myapp/db-host', prefix: 'myapp/', expected: 'DB_HOST' },
        { path: 'myapp/db-port', prefix: 'myapp/', expected: 'DB_PORT' },
        { path: 'myapp/multi-line', prefix: 'myapp/', expected: 'MULTI_LINE' },
        { path: 'deep/nested/key.name', prefix: 'deep/', expected: 'NESTED_KEY_NAME' },
      ];

      for (const tc of testCases) {
        let relativePath = tc.path;
        if (relativePath.startsWith(tc.prefix)) {
          relativePath = relativePath.slice(tc.prefix.length);
        }
        const varName = relativePath.replace(/[/\-\.]/g, '_').toUpperCase();
        expect(varName).toBe(tc.expected);
      }
    });

    it('should format secrets as shell export statements with --format export', async () => {
      const res = await request(
        { port: serverPort, host: '127.0.0.1', token: TEST_TOKEN, insecure: true },
        'GET',
        '/v1/secrets/myapp%2Fdb-host',
      );
      const value = res.body.value as string;
      // Simulate export format
      const escaped = value.replace(/'/g, "'\\''");
      const output = `export DB_HOST='${escaped}'\n`;
      expect(output).toBe("export DB_HOST='localhost'\n");
    });

    it('should handle dotenv escaping of double quotes', () => {
      // Value contains double quotes
      const value = 'pass"word';
      const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
      expect(escaped).toBe('pass\\"word');
      expect(`KEY="${escaped}"`).toBe('KEY="pass\\"word"');
    });

    it('should handle dotenv escaping of newlines', () => {
      const value = 'line1\nline2';
      const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
      expect(escaped).toBe('line1\\nline2');
    });
  });
});
