/**
 * Tests for TLS certificate generation and HTTPS server — US-004.
 *
 * Covers:
 * - Self-signed certificate generation
 * - Certificate is valid and usable by HTTPS server
 * - Certificate files are persisted and reused
 * - Server starts with HTTPS and serves requests
 * - Client connects with rejectUnauthorized: false (self-signed)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  generateSelfSignedCert,
  ensureCerts,
  certsExist,
  type TlsCertPaths,
  type TlsCertData,
} from '../src/tls.js';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';
import { VaultEngine } from '../src/vault.js';
import https from 'node:https';
import tls from 'node:tls';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const PASSPHRASE = 'test-tls-passphrase-2026';
const TEST_TOKEN = 'test-tls-token-for-testing';

// ─── Certificate generation ──────────────────────────────────────────

describe('TLS — certificate generation', () => {
  let certData: TlsCertData;

  beforeAll(() => {
    certData = generateSelfSignedCert();
  });

  it('should generate a PEM-encoded certificate', () => {
    expect(certData.cert).toContain('-----BEGIN CERTIFICATE-----');
    expect(certData.cert).toContain('-----END CERTIFICATE-----');
  });

  it('should generate a PEM-encoded private key', () => {
    expect(certData.key).toContain('-----BEGIN PRIVATE KEY-----');
    expect(certData.key).toContain('-----END PRIVATE KEY-----');
  });

  it('should generate a certificate usable by Node.js TLS', () => {
    // Verify Node.js can create a secure context with the cert
    const ctx = tls.createSecureContext({
      cert: certData.cert,
      key: certData.key,
    });
    expect(ctx).toBeTruthy();
  });

  it('should generate a unique certificate each time', () => {
    const cert2 = generateSelfSignedCert();
    // Private keys should differ
    expect(certData.key).not.toBe(cert2.key);
  });
});

// ─── Certificate file persistence ────────────────────────────────────

describe('TLS — certificate file persistence', () => {
  let tmpDir: string;
  let certPaths: TlsCertPaths;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-tls-'));
    certPaths = {
      certFile: path.join(tmpDir, 'server.crt'),
      keyFile: path.join(tmpDir, 'server.key'),
    };
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should report certs do not exist initially', () => {
    expect(certsExist(certPaths)).toBe(false);
  });

  it('should generate and persist certs with ensureCerts', () => {
    const data = ensureCerts(certPaths);
    expect(data.cert).toContain('-----BEGIN CERTIFICATE-----');
    expect(data.key).toContain('-----BEGIN PRIVATE KEY-----');
    expect(certsExist(certPaths)).toBe(true);
  });

  it('should reuse existing certs on second call', () => {
    const data1 = ensureCerts(certPaths);
    const data2 = ensureCerts(certPaths);
    // Same cert and key should be returned
    expect(data1.cert).toBe(data2.cert);
    expect(data1.key).toBe(data2.key);
  });
});

// ─── HTTPS server ────────────────────────────────────────────────────

describe('TLS — HTTPS server', () => {
  let server: https.Server;
  let tmpDir: string;
  let port: number;
  let certData: TlsCertData;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-https-'));
    certData = generateSelfSignedCert();

    const config: ServerConfig = {
      vaultPath: path.join(tmpDir, 'vault.db'),
      port: 0,
      idleTimeoutMs: 0,
      pidFile: path.join(tmpDir, 'vault.pid'),
      portFile: path.join(tmpDir, 'vault.port'),
      tokenFile: path.join(tmpDir, 'token'),
      token: TEST_TOKEN,
      tlsCertData: certData,
      // insecure NOT set — server should use HTTPS
    };

    const vault = new VaultEngine(config.vaultPath);
    vault.init(PASSPHRASE);
    vault.close();

    server = await createVaultServer(config) as https.Server;
    const addr = server.address();
    port = typeof addr === 'object' && addr ? addr.port : 0;
  });

  afterAll(() => {
    try { server.close(); } catch { /* ok */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('should serve HTTPS requests', async () => {
    const client: ClientConfig = {
      port,
      host: '127.0.0.1',
      token: TEST_TOKEN,
      insecure: false, // Use HTTPS
      rejectUnauthorized: false, // Accept self-signed cert
    };

    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(200);
    expect(res.body.initialized).toBe(true);
    expect(res.body.locked).toBe(true);
  });

  it('should reject unauthorized HTTPS requests', async () => {
    const client: ClientConfig = {
      port,
      host: '127.0.0.1',
      // No token
      insecure: false,
      rejectUnauthorized: false,
    };

    const res = await request(client, 'GET', '/v1/status');
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('should handle full CRUD over HTTPS', async () => {
    const client: ClientConfig = {
      port,
      host: '127.0.0.1',
      token: TEST_TOKEN,
      insecure: false,
      rejectUnauthorized: false,
    };

    // Unlock
    const unlockRes = await request(client, 'POST', '/v1/unlock', { passphrase: PASSPHRASE });
    expect(unlockRes.statusCode).toBe(200);

    // Store
    const storeRes = await request(client, 'PUT', '/v1/secrets/https/test', {
      value: 'https-secret-value',
    });
    expect(storeRes.statusCode).toBe(200);

    // Get
    const getRes = await request(client, 'GET', '/v1/secrets/https/test');
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.value).toBe('https-secret-value');

    // Delete
    const delRes = await request(client, 'DELETE', '/v1/secrets/https/test');
    expect(delRes.statusCode).toBe(200);

    // Lock
    const lockRes = await request(client, 'POST', '/v1/lock');
    expect(lockRes.statusCode).toBe(200);
  });
});
