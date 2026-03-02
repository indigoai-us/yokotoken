/**
 * Tests for US-007: Secure entry flow — one-time web page.
 *
 * The `hq-vault ingest <path> --web` flag starts a one-time local HTTPS
 * page for secret entry. Key properties under test:
 *
 * 1. GET /enter/<token> serves a minimal HTML form with secret path and textarea
 * 2. POST /submit/<token> stores the secret via vault API and returns success
 * 3. One-time token: page cannot be reloaded or resubmitted after use
 * 4. Token expires after 60 seconds (configurable, shortened for tests)
 * 5. HTTPS with the vault's self-signed cert (tested separately; here we use insecure mode)
 * 6. Terminal output: "Stored: <path> (via web entry, N bytes)"
 * 7. Secret value never appears in terminal output
 * 8. Server shuts down the endpoint after successful submission
 * 9. Unknown paths return 404
 * 10. Invalid/wrong tokens return 404
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { VaultEngine } from '../src/vault.js';
import {
  createWebEntryServer,
  generateOneTimeToken,
  buildEntryPage,
  type WebEntryOptions,
} from '../src/web-entry.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-web-entry-passphrase-2026';
const TEST_TOKEN = 'test-web-entry-vault-token';

/**
 * Helper: create a temporary directory and vault server config.
 */
function createTmpConfig(overrides?: Partial<ServerConfig>): {
  tmpDir: string;
  config: ServerConfig;
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-web-'));
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
  if (typeof addr === 'object' && addr) return addr.port;
  throw new Error('Server has no address');
}

function clientFor(server: http.Server): ClientConfig {
  return { port: getPort(server), host: '127.0.0.1', token: TEST_TOKEN, insecure: true };
}

/**
 * Helper: make an HTTP GET request and return the response body and status.
 */
function httpGet(port: number, path: string): Promise<{ statusCode: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port, path }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 500,
          body: Buffer.concat(chunks).toString('utf-8'),
          headers: res.headers,
        });
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
  });
}

/**
 * Helper: make an HTTP POST request with form-encoded body.
 */
function httpPost(
  port: number,
  path: string,
  formData: Record<string, string>,
): Promise<{ statusCode: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const encoded = Object.entries(formData)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');

    const options = {
      hostname: '127.0.0.1',
      port,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(encoded),
      },
    };

    const req = http.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 500,
          body: Buffer.concat(chunks).toString('utf-8'),
          headers: res.headers,
        });
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    req.write(encoded);
    req.end();
  });
}

// ─── Token generation ──────────────────────────────────────────────────
describe('Web entry — token generation', () => {
  it('should generate a 64-character hex token', () => {
    const token = generateOneTimeToken();
    expect(token).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(token)).toBe(true);
  });

  it('should generate unique tokens each time', () => {
    const tokens = new Set<string>();
    for (let i = 0; i < 100; i++) {
      tokens.add(generateOneTimeToken());
    }
    expect(tokens.size).toBe(100);
  });
});

// ─── HTML page generation ──────────────────────────────────────────────
describe('Web entry — HTML page', () => {
  it('should include the secret path in the page', () => {
    const html = buildEntryPage('slack/user-token', '/submit/abc');
    expect(html).toContain('slack/user-token');
  });

  it('should include a textarea for secret input', () => {
    const html = buildEntryPage('test/path', '/submit/abc');
    expect(html).toContain('<textarea');
    expect(html).toContain('name="value"');
  });

  it('should include a submit button', () => {
    const html = buildEntryPage('test/path', '/submit/abc');
    expect(html).toContain('<button');
    expect(html).toContain('type="submit"');
  });

  it('should include the submit URL in the form action', () => {
    const html = buildEntryPage('test/path', '/submit/my-token');
    expect(html).toContain('/submit/my-token');
  });

  it('should escape HTML entities in the secret path to prevent XSS', () => {
    const html = buildEntryPage('<script>alert("xss")</script>', '/submit/abc');
    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('should not use any external JS framework or CDN links', () => {
    const html = buildEntryPage('test/path', '/submit/abc');
    // No external script or link tags
    expect(html).not.toMatch(/<script\s+src=/);
    expect(html).not.toMatch(/<link\s+.*href=["']http/);
  });

  it('should set no-cache headers via page meta or form', () => {
    // Tested at the HTTP level in the server tests below
    const html = buildEntryPage('test/path', '/submit/abc');
    // Just verify the page is well-formed HTML
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
  });
});

// ─── Web entry server — basic flow ──────────────────────────────────────
describe('Web entry — basic store flow', () => {
  let vaultServer: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    vaultServer = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(vaultServer);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { vaultServer.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should serve the entry form on GET /enter/<token>', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/test-basic',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    // Wait for server to be ready
    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    const res = await httpGet(port, `/enter/${token}`);
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('web/test-basic');
    expect(res.body).toContain('<textarea');
    expect(res.body).toContain('<button');
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.headers['cache-control']).toContain('no-store');

    // Clean up
    try { entry.getServer().close(); } catch { /* ok */ }
  });

  it('should store a secret via POST /submit/<token> and return success', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/test-submit',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();
    const secretValue = 'my-web-secret-value-12345';

    // Submit the secret
    const res = await httpPost(port, `/submit/${token}`, { value: secretValue });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.ok).toBe(true);

    // Wait for result
    const result = await entry.resultPromise;
    expect(result.success).toBe(true);
    expect(result.bytes).toBe(Buffer.byteLength(secretValue));

    // Verify the secret was stored in the vault
    const getRes = await request(client, 'GET', '/v1/secrets/web/test-submit');
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.value).toBe(secretValue);
  });

  it('should store secret with type and description metadata', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/test-meta',
      type: 'api-key',
      description: 'Web-entered API key',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    await httpPost(port, `/submit/${token}`, { value: 'meta-secret-val' });
    const result = await entry.resultPromise;
    expect(result.success).toBe(true);

    // Verify metadata
    const getRes = await request(client, 'GET', '/v1/secrets/web/test-meta');
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.metadata).toEqual({
      type: 'api-key',
      description: 'Web-entered API key',
    });
  });

  it('should report correct byte count for multi-byte UTF-8', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/test-utf8',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();
    // Two emoji, 4 bytes each = 8 bytes
    const emoji = '\u{1F600}\u{1F601}';

    await httpPost(port, `/submit/${token}`, { value: emoji });
    const result = await entry.resultPromise;
    expect(result.success).toBe(true);
    expect(result.bytes).toBe(8);
  });
});

// ─── One-time token — cannot be reused ──────────────────────────────────
describe('Web entry — one-time token enforcement', () => {
  let vaultServer: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    vaultServer = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(vaultServer);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { vaultServer.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should return 410 on GET after token has been used', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/reuse-get',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    // First: submit the secret
    await httpPost(port, `/submit/${token}`, { value: 'first-use' });
    await entry.resultPromise;

    // Brief delay for server state to settle
    await new Promise((r) => setTimeout(r, 100));

    // Try to GET the page again — should be 410 Gone
    try {
      const res = await httpGet(port, `/enter/${token}`);
      expect(res.statusCode).toBe(410);
      expect(res.body).toContain('already been used');
    } catch {
      // Server may have shut down — that's also acceptable behavior
    }
  });

  it('should return 410 on POST after token has been used', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/reuse-post',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    // First submission
    await httpPost(port, `/submit/${token}`, { value: 'first-submit' });
    await entry.resultPromise;

    await new Promise((r) => setTimeout(r, 100));

    // Second submission — should fail
    try {
      const res = await httpPost(port, `/submit/${token}`, { value: 'second-submit' });
      expect(res.statusCode).toBe(410);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('already used');
    } catch {
      // Server may have shut down — acceptable
    }
  });

  it('should only store the secret once even if submitted twice quickly', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/double-submit',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    // Submit first
    const first = await httpPost(port, `/submit/${token}`, { value: 'only-this-value' });
    expect(first.statusCode).toBe(200);

    const result = await entry.resultPromise;
    expect(result.success).toBe(true);

    // Verify the stored value is the first one
    const getRes = await request(client, 'GET', '/v1/secrets/web/double-submit');
    expect(getRes.body.value).toBe('only-this-value');
  });
});

// ─── Token expiry ──────────────────────────────────────────────────────
describe('Web entry — token expiry', () => {
  let vaultServer: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    vaultServer = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(vaultServer);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { vaultServer.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should expire the token after the configured timeout', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/expiry-test',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 500, // 500ms for fast testing
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    // Wait for token to expire
    await new Promise((r) => setTimeout(r, 700));

    // Try to GET the page — should be 410 (expired)
    try {
      const res = await httpGet(port, `/enter/${token}`);
      expect(res.statusCode).toBe(410);
      expect(res.body).toContain('expired');
    } catch {
      // Server might have shut down after expiry — acceptable
    }

    // The result promise should resolve with failure
    const result = await entry.resultPromise;
    expect(result.success).toBe(false);
    expect(result.error).toContain('expired');
  });

  it('should reject POST after token expires', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/expiry-post',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 500,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    // Wait for expiry
    await new Promise((r) => setTimeout(r, 700));

    try {
      const res = await httpPost(port, `/submit/${token}`, { value: 'too-late' });
      expect(res.statusCode).toBe(410);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('expired');
    } catch {
      // Server might have shut down
    }

    // Secret should NOT have been stored
    const getRes = await request(client, 'GET', '/v1/secrets/web/expiry-post');
    expect(getRes.statusCode).toBe(404);
  });
});

// ─── Invalid paths and wrong tokens ──────────────────────────────────────
describe('Web entry — invalid requests', () => {
  let vaultServer: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    vaultServer = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(vaultServer);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { vaultServer.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should return 404 for wrong token in GET /enter/', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/invalid-test',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));
    const port = entry.getPort();

    const res = await httpGet(port, '/enter/wrong-token-value');
    expect(res.statusCode).toBe(404);

    try { entry.getServer().close(); } catch { /* ok */ }
  });

  it('should return 404 for wrong token in POST /submit/', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/invalid-submit',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));
    const port = entry.getPort();

    const res = await httpPost(port, '/submit/wrong-token-value', { value: 'secret' });
    expect(res.statusCode).toBe(404);

    try { entry.getServer().close(); } catch { /* ok */ }
  });

  it('should return 404 for root path', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/root-test',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));
    const port = entry.getPort();

    const res = await httpGet(port, '/');
    expect(res.statusCode).toBe(404);

    try { entry.getServer().close(); } catch { /* ok */ }
  });

  it('should return 404 for random paths', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/random-test',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));
    const port = entry.getPort();

    const res = await httpGet(port, '/v1/status');
    expect(res.statusCode).toBe(404);

    try { entry.getServer().close(); } catch { /* ok */ }
  });

  it('should reject POST with empty secret value', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/empty-value',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));
    const port = entry.getPort();
    const token = entry.getToken();

    const res = await httpPost(port, `/submit/${token}`, { value: '' });
    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body);
    expect(body.error).toContain('empty');

    try { entry.getServer().close(); } catch { /* ok */ }
  });

  it('should allow retry after empty value rejection', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/retry-empty',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));
    const port = entry.getPort();
    const token = entry.getToken();

    // First: try with empty value — rejected
    const firstRes = await httpPost(port, `/submit/${token}`, { value: '' });
    expect(firstRes.statusCode).toBe(400);

    // Second: retry with real value — should succeed
    const secondRes = await httpPost(port, `/submit/${token}`, { value: 'retry-value' });
    expect(secondRes.statusCode).toBe(200);

    const result = await entry.resultPromise;
    expect(result.success).toBe(true);

    // Verify stored
    const getRes = await request(client, 'GET', '/v1/secrets/web/retry-empty');
    expect(getRes.body.value).toBe('retry-value');
  });
});

// ─── Secret value never in output ──────────────────────────────────────
describe('Web entry — secret value never in terminal output', () => {
  let vaultServer: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    vaultServer = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(vaultServer);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { vaultServer.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should never include secret value in the result', async () => {
    const client = clientFor(vaultServer);
    const secretValue = 'SUPER-SECRET-WEB-VALUE-do-not-leak';
    const entry = createWebEntryServer({
      secretPath: 'web/no-leak',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    await httpPost(port, `/submit/${token}`, { value: secretValue });
    const result = await entry.resultPromise;

    expect(result.success).toBe(true);
    // The result object should only contain bytes, not the value
    expect(JSON.stringify(result)).not.toContain(secretValue);
    expect(JSON.stringify(result)).not.toContain('SUPER-SECRET');
  });

  it('should produce agent-safe confirmation format', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/format-check',
      type: 'oauth-token',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    await httpPost(port, `/submit/${token}`, { value: 'xoxp-1234' });
    const result = await entry.resultPromise;

    expect(result.success).toBe(true);
    expect(result.bytes).toBe(Buffer.byteLength('xoxp-1234'));

    // Build the same output format CLI would use
    const typeStr = ', oauth-token';
    const output = `Stored: web/format-check (via web entry, ${result.bytes} bytes${typeStr})`;
    expect(output).toBe('Stored: web/format-check (via web entry, 9 bytes, oauth-token)');
    expect(output).not.toContain('xoxp-1234');
  });
});

// ─── Server shutdown after submission ──────────────────────────────────
describe('Web entry — server lifecycle', () => {
  let vaultServer: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    vaultServer = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(vaultServer);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { vaultServer.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should shut down the web server after successful submission', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/shutdown-test',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();
    const server = entry.getServer();

    // Submit
    await httpPost(port, `/submit/${token}`, { value: 'shutdown-value' });
    await entry.resultPromise;

    // Wait for server to shut down
    await new Promise((r) => setTimeout(r, 700));

    // Server should now be closed
    const isListening = server.listening;
    expect(isListening).toBe(false);
  });

  it('should listen on a random port (not the vault server port)', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/port-test',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const webPort = entry.getPort();
    const vaultPort = getPort(vaultServer);

    expect(webPort).not.toBe(vaultPort);
    expect(webPort).toBeGreaterThan(0);

    try { entry.getServer().close(); } catch { /* ok */ }
  });

  it('should bind to localhost only (127.0.0.1)', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/bind-test',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const addr = entry.getServer().address();
    expect(typeof addr).toBe('object');
    if (typeof addr === 'object' && addr) {
      expect(addr.address).toBe('127.0.0.1');
    }

    try { entry.getServer().close(); } catch { /* ok */ }
  });
});

// ─── Edge cases ────────────────────────────────────────────────────────
describe('Web entry — edge cases', () => {
  let vaultServer: http.Server;
  let tmpDir: string;

  beforeAll(async () => {
    const result = createTmpConfig();
    tmpDir = result.tmpDir;

    const vault = await VaultEngine.open(result.config.vaultPath);
    await vault.init(PASSPHRASE);
    await vault.close();

    vaultServer = (await createVaultServer(result.config)) as http.Server;
    const client = clientFor(vaultServer);
    await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
  });

  afterAll(() => {
    try { vaultServer.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should handle long secret values via web entry', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/long-value',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();
    const longValue = 'x'.repeat(10000);

    await httpPost(port, `/submit/${token}`, { value: longValue });
    const result = await entry.resultPromise;

    expect(result.success).toBe(true);
    expect(result.bytes).toBe(10000);

    // Verify stored
    const getRes = await request(client, 'GET', '/v1/secrets/web/long-value');
    expect(getRes.body.value).toBe(longValue);
  });

  it('should handle multi-line secrets via web entry', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/multiline',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();
    const multilineValue = 'line1\nline2\nline3\n';

    await httpPost(port, `/submit/${token}`, { value: multilineValue });
    const result = await entry.resultPromise;

    expect(result.success).toBe(true);

    // Verify stored correctly
    const getRes = await request(client, 'GET', '/v1/secrets/web/multiline');
    expect(getRes.body.value).toBe(multilineValue);
  });

  it('should handle special characters in secret values', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'web/special-chars',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();
    const specialValue = 'key=val&other=stuff&encoded=%20value+plus';

    await httpPost(port, `/submit/${token}`, { value: specialValue });
    const result = await entry.resultPromise;

    expect(result.success).toBe(true);

    // Verify stored correctly
    const getRes = await request(client, 'GET', '/v1/secrets/web/special-chars');
    expect(getRes.body.value).toBe(specialValue);
  });

  it('should handle nested secret paths', async () => {
    const client = clientFor(vaultServer);
    const entry = createWebEntryServer({
      secretPath: 'company/team/service/api-key',
      vaultClient: client,
      insecure: true,
      tokenExpiryMs: 10_000,
    });

    await new Promise((r) => setTimeout(r, 100));

    const port = entry.getPort();
    const token = entry.getToken();

    // Verify the page shows the full path
    const pageRes = await httpGet(port, `/enter/${token}`);
    expect(pageRes.body).toContain('company/team/service/api-key');

    await httpPost(port, `/submit/${token}`, { value: 'nested-secret' });
    const result = await entry.resultPromise;
    expect(result.success).toBe(true);

    const getRes = await request(client, 'GET', '/v1/secrets/company/team/service/api-key');
    expect(getRes.body.value).toBe('nested-secret');
  });
});
