/**
 * Network vault client — US-006.
 *
 * Provides a high-level client for connecting to a remote vault server with
 * automatic challenge-response authentication using Ed25519 keypairs.
 *
 * Features:
 * - Auto challenge-response auth using local private key
 * - Session token caching with auto-refresh on 401
 * - Falls back to HQ_VAULT_TOKEN if set (existing behavior)
 * - Supports HQ_VAULT_URL, HQ_VAULT_IDENTITY, HQ_VAULT_KEY_FILE,
 *   HQ_VAULT_PRIVATE_KEY, HQ_VAULT_CA_CERT env vars
 * - Custom CA certificate support for self-signed server certs
 * - Clear connection error messages
 *
 * Usage:
 *   const client = new NetworkVaultClient({ url: 'https://vault.example.com:13100' });
 *   const res = await client.request('GET', '/v1/secrets/my-key');
 */

import https from 'node:https';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { readConfig } from './config.js';

// ─── Types ──────────────────────────────────────────────────────────

export interface NetworkClientConfig {
  /** Vault server URL (overrides HQ_VAULT_URL and config file). */
  url?: string;
  /** Bearer token for token-based auth (overrides HQ_VAULT_TOKEN). */
  token?: string;
  /** Identity name for challenge-response auth (overrides HQ_VAULT_IDENTITY). */
  identity?: string;
  /** Path to Ed25519 private key file (overrides HQ_VAULT_KEY_FILE). */
  keyFile?: string;
  /** Base64-encoded Ed25519 private key (overrides HQ_VAULT_PRIVATE_KEY). */
  privateKey?: string;
  /** Path to custom CA certificate (overrides HQ_VAULT_CA_CERT). */
  caCert?: string;
  /** Request timeout in milliseconds (default: 10000). */
  timeout?: number;
  /** If true, skip TLS certificate validation. */
  rejectUnauthorized?: boolean;
}

export interface NetworkClientResponse {
  statusCode: number;
  body: Record<string, unknown>;
}

/** Cached session state. */
interface SessionCache {
  token: string;
  expiresAt: number; // Unix ms
}

// ─── Constants ──────────────────────────────────────────────────────

const DEFAULT_URL = 'https://localhost:13100';
const DEFAULT_TIMEOUT = 10000;
/** Re-auth buffer: refresh session 60s before expiry. */
const SESSION_REFRESH_BUFFER_MS = 60 * 1000;

// ─── NetworkVaultClient ─────────────────────────────────────────────

/**
 * Client for connecting to a remote (or local) vault server.
 *
 * Supports two auth modes:
 * 1. Token-based: Uses a static bearer token (HQ_VAULT_TOKEN or config.token)
 * 2. Identity-based: Uses Ed25519 challenge-response auth with session token caching
 *
 * Identity-based auth is preferred when identity + key are configured.
 * Falls back to token-based auth if only a token is available.
 */
export class NetworkVaultClient {
  private url: string;
  private token: string | undefined;
  private identity: string | undefined;
  private keyFile: string | undefined;
  private privateKeyBase64: string | undefined;
  private caCert: string | undefined;
  private caCertData: string | undefined;
  private timeout: number;
  private rejectUnauthorized: boolean | undefined;
  private sessionCache: SessionCache | null = null;
  private authenticating: Promise<string> | null = null;

  constructor(config?: NetworkClientConfig) {
    // Load persistent config as baseline
    const persistedConfig = readConfig();

    // Resolve settings: explicit config > env vars > persisted config > defaults
    this.url =
      config?.url ||
      process.env.HQ_VAULT_URL ||
      persistedConfig.remote_url ||
      DEFAULT_URL;

    this.token =
      config?.token ||
      process.env.HQ_VAULT_TOKEN ||
      undefined;

    this.identity =
      config?.identity ||
      process.env.HQ_VAULT_IDENTITY ||
      persistedConfig.identity ||
      undefined;

    this.keyFile =
      config?.keyFile ||
      process.env.HQ_VAULT_KEY_FILE ||
      persistedConfig.key_file ||
      undefined;

    this.privateKeyBase64 =
      config?.privateKey ||
      process.env.HQ_VAULT_PRIVATE_KEY ||
      undefined;

    this.caCert =
      config?.caCert ||
      process.env.HQ_VAULT_CA_CERT ||
      persistedConfig.ca_cert ||
      undefined;

    this.timeout = config?.timeout ?? DEFAULT_TIMEOUT;
    this.rejectUnauthorized = config?.rejectUnauthorized;

    // Eagerly load CA cert data if path is provided
    if (this.caCert) {
      this.caCertData = this.loadCaCert(this.caCert);
    }
  }

  /**
   * Whether identity-based auth is configured.
   */
  get hasIdentityAuth(): boolean {
    return !!(this.identity && (this.keyFile || this.privateKeyBase64));
  }

  /**
   * Whether any auth method is configured.
   */
  get hasAuth(): boolean {
    return !!(this.token || this.hasIdentityAuth);
  }

  /**
   * Send an authenticated request to the vault server.
   *
   * For identity-based auth:
   * - Automatically performs challenge-response on first request
   * - Caches session token for subsequent requests
   * - Re-authenticates on 401 (expired session)
   *
   * For token-based auth:
   * - Uses the static bearer token directly
   */
  async request(
    method: string,
    urlPath: string,
    body?: Record<string, unknown>,
  ): Promise<NetworkClientResponse> {
    const authToken = await this.getAuthToken();

    const res = await this.rawRequest(method, urlPath, body, authToken);

    // If we got 401 and have identity auth, re-authenticate and retry
    if (res.statusCode === 401 && this.hasIdentityAuth) {
      this.sessionCache = null; // Clear cached session
      const newToken = await this.authenticate();
      return this.rawRequest(method, urlPath, body, newToken);
    }

    return res;
  }

  /**
   * Get the current auth token, authenticating if needed.
   */
  private async getAuthToken(): Promise<string | undefined> {
    // Token-based auth takes precedence if no identity auth is configured
    if (!this.hasIdentityAuth) {
      return this.token;
    }

    // Check cached session
    if (this.sessionCache) {
      const now = Date.now();
      if (now < this.sessionCache.expiresAt - SESSION_REFRESH_BUFFER_MS) {
        return this.sessionCache.token;
      }
      // Session expired or about to expire, re-authenticate
      this.sessionCache = null;
    }

    return this.authenticate();
  }

  /**
   * Perform challenge-response authentication.
   *
   * 1. Load the private key from file or env var
   * 2. Request a challenge nonce from the server
   * 3. Sign the nonce with the private key
   * 4. Send signature + public key to verify endpoint
   * 5. Cache the resulting session token
   *
   * Deduplicates concurrent auth attempts.
   */
  async authenticate(): Promise<string> {
    // Deduplicate concurrent auth attempts
    if (this.authenticating) {
      return this.authenticating;
    }

    this.authenticating = this.doAuthenticate();
    try {
      return await this.authenticating;
    } finally {
      this.authenticating = null;
    }
  }

  private async doAuthenticate(): Promise<string> {
    if (!this.identity) {
      throw new NetworkClientError(
        'No identity configured for authentication. Set HQ_VAULT_IDENTITY or use config set identity.',
        'NO_IDENTITY',
      );
    }

    // Load private key
    const privateKeyBase64 = this.loadPrivateKey();
    let secretKey: Buffer;
    try {
      secretKey = Buffer.from(privateKeyBase64, 'base64');
    } catch {
      throw new NetworkClientError(
        'Invalid private key encoding. Expected base64-encoded Ed25519 secret key.',
        'INVALID_KEY',
      );
    }

    // Dynamically import sodium for Ed25519 operations
    const sodium = (await import('libsodium-wrappers-sumo')).default;
    await sodium.ready;

    if (secretKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
      throw new NetworkClientError(
        `Invalid private key length: expected ${sodium.crypto_sign_SECRETKEYBYTES} bytes, got ${secretKey.length}`,
        'INVALID_KEY',
      );
    }

    // Extract public key from private key
    const publicKey = Buffer.from(sodium.crypto_sign_ed25519_sk_to_pk(new Uint8Array(secretKey)));
    const publicKeyBase64 = publicKey.toString('base64');

    try {
      // Step 1: Request challenge
      const challengeRes = await this.rawRequest('POST', '/v1/auth/challenge', {
        identity_id: this.identity,
      });

      if (challengeRes.statusCode !== 200) {
        const errorMsg = (challengeRes.body.error as string) || 'Unknown error';
        throw new NetworkClientError(
          `Challenge request failed: ${errorMsg}`,
          'AUTH_CHALLENGE_FAILED',
          challengeRes.statusCode,
        );
      }

      const challengeNonce = Buffer.from(
        challengeRes.body.challenge as string,
        'base64url',
      );
      const challengeId = challengeRes.body.challenge_id as string;

      // Step 2: Sign the challenge nonce
      const signature = Buffer.from(
        sodium.crypto_sign_detached(new Uint8Array(challengeNonce), new Uint8Array(secretKey))
      );
      const signatureBase64url = signature.toString('base64url');

      // Step 3: Verify and get session token
      const verifyRes = await this.rawRequest('POST', '/v1/auth/verify', {
        challenge_id: challengeId,
        identity_id: this.identity,
        signature: signatureBase64url,
        public_key: publicKeyBase64,
      });

      if (verifyRes.statusCode !== 200) {
        const errorMsg = (verifyRes.body.error as string) || 'Unknown error';
        throw new NetworkClientError(
          `Authentication failed: ${errorMsg}`,
          'AUTH_VERIFY_FAILED',
          verifyRes.statusCode,
        );
      }

      const sessionToken = verifyRes.body.session_token as string;
      const expiresIn = verifyRes.body.expires_in as number;

      // Cache the session
      this.sessionCache = {
        token: sessionToken,
        expiresAt: Date.now() + expiresIn * 1000,
      };

      return sessionToken;
    } finally {
      // Zero out the secret key
      sodium.memzero(secretKey);
    }
  }

  /**
   * Load the Ed25519 private key from file or env var.
   */
  loadPrivateKey(): string {
    // Direct base64 key takes precedence
    if (this.privateKeyBase64) {
      return this.privateKeyBase64;
    }

    if (!this.keyFile) {
      throw new NetworkClientError(
        'No private key configured. Set HQ_VAULT_KEY_FILE, HQ_VAULT_PRIVATE_KEY, or use config set key-file.',
        'NO_KEY',
      );
    }

    const resolvedPath = path.resolve(this.keyFile);
    if (!fs.existsSync(resolvedPath)) {
      throw new NetworkClientError(
        `Private key file not found: ${resolvedPath}`,
        'KEY_FILE_NOT_FOUND',
      );
    }

    try {
      return fs.readFileSync(resolvedPath, 'utf-8').trim();
    } catch (err) {
      throw new NetworkClientError(
        `Failed to read private key file: ${err instanceof Error ? err.message : String(err)}`,
        'KEY_FILE_READ_ERROR',
      );
    }
  }

  /**
   * Load CA certificate from file.
   */
  private loadCaCert(certPath: string): string {
    const resolvedPath = path.resolve(certPath);
    if (!fs.existsSync(resolvedPath)) {
      throw new NetworkClientError(
        `CA certificate file not found: ${resolvedPath}`,
        'CA_CERT_NOT_FOUND',
      );
    }

    try {
      return fs.readFileSync(resolvedPath, 'utf-8');
    } catch (err) {
      throw new NetworkClientError(
        `Failed to read CA certificate: ${err instanceof Error ? err.message : String(err)}`,
        'CA_CERT_READ_ERROR',
      );
    }
  }

  /**
   * Send a raw HTTP(S) request to the vault server.
   */
  private rawRequest(
    method: string,
    urlPath: string,
    body?: Record<string, unknown>,
    authToken?: string,
  ): Promise<NetworkClientResponse> {
    return new Promise((resolve, reject) => {
      let parsed: URL;
      try {
        parsed = new URL(urlPath, this.url);
      } catch {
        reject(
          new NetworkClientError(
            `Invalid vault URL: ${this.url}. Expected format: https://vault.example.com:13100`,
            'INVALID_URL',
          ),
        );
        return;
      }

      const payload = body ? JSON.stringify(body) : undefined;
      const isHttps = parsed.protocol === 'https:';
      const defaultPort = isHttps ? 443 : 80;
      const port = parsed.port ? parseInt(parsed.port, 10) : defaultPort;

      const headers: Record<string, string> = {};
      if (payload) {
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = String(Buffer.byteLength(payload));
      }
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      const requestPath = parsed.pathname + (parsed.search || '');

      const options: https.RequestOptions = {
        hostname: parsed.hostname,
        port,
        path: requestPath,
        method,
        headers,
        timeout: this.timeout,
      };

      if (isHttps) {
        // TLS options
        if (this.rejectUnauthorized !== undefined) {
          options.rejectUnauthorized = this.rejectUnauthorized;
        } else if (this.caCertData) {
          // If custom CA cert is provided, use it and enable validation
          options.ca = this.caCertData;
          options.rejectUnauthorized = true;
        } else {
          // Default: don't reject for self-signed certs (local dev)
          options.rejectUnauthorized = false;
        }
      }

      const transport = isHttps ? https : http;

      const req = transport.request(options, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          try {
            const responseBody = JSON.parse(raw);
            resolve({
              statusCode: res.statusCode || 500,
              body: responseBody,
            });
          } catch {
            resolve({
              statusCode: res.statusCode || 500,
              body: { error: 'Invalid response from server', raw },
            });
          }
        });
      });

      req.on('error', (err) => {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === 'ECONNREFUSED') {
          reject(
            new NetworkClientError(
              `Cannot connect to vault server at ${this.url}. Is the server running?`,
              'CONNECTION_REFUSED',
            ),
          );
        } else if (code === 'ENOTFOUND') {
          reject(
            new NetworkClientError(
              `Cannot resolve vault server hostname: ${parsed.hostname}. Check your remote-url configuration.`,
              'HOST_NOT_FOUND',
            ),
          );
        } else if (code === 'ECONNRESET') {
          reject(
            new NetworkClientError(
              `Connection to vault server was reset. The server may have closed the connection.`,
              'CONNECTION_RESET',
            ),
          );
        } else if (
          code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
          code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
          code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
          (err.message && err.message.includes('self-signed'))
        ) {
          reject(
            new NetworkClientError(
              `TLS certificate verification failed for ${this.url}. ` +
                'If the server uses a self-signed certificate, set HQ_VAULT_CA_CERT to the CA cert path, ' +
                'or use --ca-cert flag.',
              'TLS_CERT_ERROR',
            ),
          );
        } else {
          reject(
            new NetworkClientError(
              `Failed to connect to vault server: ${err.message}`,
              'CONNECTION_ERROR',
            ),
          );
        }
      });

      req.on('timeout', () => {
        req.destroy();
        reject(
          new NetworkClientError(
            `Connection to vault server at ${this.url} timed out after ${this.timeout}ms.`,
            'TIMEOUT',
          ),
        );
      });

      if (payload) {
        req.write(payload);
      }
      req.end();
    });
  }

  /**
   * Clear the cached session token (forces re-authentication on next request).
   */
  clearSession(): void {
    this.sessionCache = null;
  }

  /**
   * Get the resolved vault URL.
   */
  getUrl(): string {
    return this.url;
  }

  /**
   * Get the resolved identity name (if configured).
   */
  getIdentity(): string | undefined {
    return this.identity;
  }
}

// ─── Error ──────────────────────────────────────────────────────────

/**
 * Error class for network client errors.
 */
export class NetworkClientError extends Error {
  /** Error code for programmatic handling. */
  public readonly code: string;
  /** HTTP status code if from server response. */
  public readonly statusCode?: number;

  constructor(message: string, code: string, statusCode?: number) {
    super(message);
    this.name = 'NetworkClientError';
    this.code = code;
    this.statusCode = statusCode;
  }
}
