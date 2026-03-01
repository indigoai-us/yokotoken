/**
 * Vault server — holds the master key in memory and serves lock/unlock/status
 * requests via a local HTTPS server bound to localhost only.
 *
 * The server runs as the "vault daemon" and is the only process that ever
 * holds the decryption key. CLI commands communicate with it via HTTPS on
 * a localhost port.
 *
 * Features:
 * - Holds master key in memory while unlocked
 * - Auto-lock after configurable idle timeout (default: 30 minutes)
 * - Localhost-only binding (never exposed to network)
 * - PID file for process management
 * - HTTPS with self-signed certificates (US-004)
 * - Bearer token authentication on all endpoints (US-004)
 * - Rate limiting on failed auth attempts (US-004)
 */

import https from 'node:https';
import http from 'node:http';
import { VaultEngine } from './vault.js';
import fs from 'node:fs';
import path from 'node:path';
import {
  generateToken,
  writeTokenFile,
  validateBearerToken,
  RateLimiter,
  type RateLimitConfig,
} from './auth.js';
import { ensureCerts, type TlsCertPaths, type TlsCertData } from './tls.js';
import { TokenManager } from './tokens.js';
import { VaultDatabase } from './db.js';
import { AuditLogger } from './audit.js';
import { IdentityDatabase, getDefaultIdentityDbPath } from './identity.js';
import { parseScope, checkAccess, filterAccessiblePaths } from './scoping.js';
import { NetworkAuthenticator } from './network-auth.js';
import { AccessRequestManager } from './access-requests.js';

export interface ServerConfig {
  vaultPath: string;
  port: number;
  idleTimeoutMs: number;
  pidFile: string;
  portFile: string;
  tokenFile?: string;
  tlsCertPaths?: TlsCertPaths;
  tlsCertData?: TlsCertData;
  rateLimitConfig?: Partial<RateLimitConfig>;
  /** If true, skip TLS and use plain HTTP (for testing only). */
  insecure?: boolean;
  /** Provide a pre-set token instead of generating one. */
  token?: string;
  /** Custom audit log path (defaults to ~/.hq-vault/audit.log). */
  auditLogPath?: string;
  /** Path to the identity database (for scope-based access control). */
  identityDbPath?: string;
  /** Challenge TTL in ms for network auth (default: 60s). */
  challengeTtlMs?: number;
  /** Session token TTL in ms for network auth (default: 1h). */
  sessionTtlMs?: number;
  /** If true, enable network mode: bind to 0.0.0.0, require TLS and identity auth. */
  network?: boolean;
  /** Bind address override. Defaults to '127.0.0.1' for local, '0.0.0.0' for network. */
  bindAddress?: string;
  /** Custom TLS certificate file path (for CA-signed certs). */
  tlsCertFile?: string;
  /** Custom TLS key file path (for CA-signed certs). */
  tlsKeyFile?: string;
}

export const DEFAULT_PORT = 13100;
export const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Get the default vault directory path.
 * Respects HQ_VAULT_DIR environment variable for testing and custom deployments.
 */
export function getVaultDir(): string {
  if (process.env.HQ_VAULT_DIR) {
    return process.env.HQ_VAULT_DIR;
  }
  const home = process.env.HOME || process.env.USERPROFILE || '';
  return path.join(home, '.hq-vault');
}

/**
 * Get the default vault database path.
 */
export function getDefaultVaultPath(): string {
  return path.join(getVaultDir(), 'vault.db');
}

/**
 * Get the default PID file path.
 */
export function getDefaultPidFile(): string {
  return path.join(getVaultDir(), 'vault.pid');
}

/**
 * Get the default port file path.
 */
export function getDefaultPortFile(): string {
  return path.join(getVaultDir(), 'vault.port');
}

interface ServerState {
  vault: VaultEngine;
  idleTimer: ReturnType<typeof setTimeout> | null;
  idleTimeoutMs: number;
  lastActivity: number;
  boundPort: number;
  /** Bootstrap/admin token (from file). Always accepted for backward compat. */
  token: string;
  rateLimiter: RateLimiter;
  /** Token manager for database-backed multi-token system (US-005). */
  tokenManager: TokenManager;
  /** Token database connection (separate from VaultEngine's). */
  tokenDb: VaultDatabase;
  /** Audit logger for recording access and auth events. */
  auditLogger: AuditLogger;
  /** Identity database for scope-based access control (optional). */
  identityDb: IdentityDatabase | null;
  /** Network authenticator for challenge-response auth (US-003). */
  networkAuth: NetworkAuthenticator | null;
  /** Access request manager (US-004). */
  accessRequestManager: AccessRequestManager | null;
  /** Whether the server is running in network mode. */
  networkMode: boolean;
}

/**
 * Reset the auto-lock idle timer.
 */
function resetIdleTimer(state: ServerState): void {
  if (state.idleTimer) {
    clearTimeout(state.idleTimer);
    state.idleTimer = null;
  }
  state.lastActivity = Date.now();

  if (state.vault.isUnlocked && state.idleTimeoutMs > 0) {
    state.idleTimer = setTimeout(() => {
      if (state.vault.isUnlocked) {
        state.vault.lock();
        process.stderr.write('[hq-vault] Auto-locked after idle timeout\n');
      }
    }, state.idleTimeoutMs);
    // Don't prevent process exit
    state.idleTimer.unref();
  }
}

/**
 * Parse JSON body from an incoming request.
 */
function parseBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      try {
        const body = Buffer.concat(chunks).toString('utf-8');
        if (!body || body.trim().length === 0) {
          resolve({});
        } else {
          resolve(JSON.parse(body));
        }
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Send a JSON response.
 */
function sendJson(res: http.ServerResponse, statusCode: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

/**
 * Get the client IP from a request, normalizing IPv6-mapped IPv4 addresses.
 */
function getClientIp(req: http.IncomingMessage): string {
  const addr = req.socket.remoteAddress || 'unknown';
  // Normalize ::ffff:127.0.0.1 to 127.0.0.1
  if (addr.startsWith('::ffff:')) {
    return addr.slice(7);
  }
  return addr;
}

/**
 * Create the request handler function for the vault server.
 * This is separated from server creation for testability.
 */
function createRequestHandler(config: ServerConfig, state: ServerState) {
  return async (req: http.IncomingMessage, res: http.ServerResponse) => {
    const clientIp = getClientIp(req);

    // In local mode, only allow localhost connections
    if (!state.networkMode) {
      const remoteAddr = req.socket.remoteAddress;
      if (remoteAddr !== '127.0.0.1' && remoteAddr !== '::1' && remoteAddr !== '::ffff:127.0.0.1') {
        sendJson(res, 403, { error: 'Forbidden' });
        return;
      }
    }

    // In network mode, log remote IP for all requests
    if (state.networkMode) {
      process.stderr.write(`[hq-vault] ${req.method} ${req.url} from ${clientIp}\n`);
    }

    // ── Health endpoint (no auth required, no information leakage) ──
    const healthUrl = new URL(req.url || '/', `https://localhost:${config.port}`);
    if (req.method === 'GET' && healthUrl.pathname === '/v1/health') {
      sendJson(res, 200, {
        status: 'ok',
        version: '0.1.0',
        mode: state.networkMode ? 'network' : 'local',
      });
      return;
    }

    // ── Rate limit check ──────────────────────────────────────────
    const lockoutMs = state.rateLimiter.isLocked(clientIp);
    if (lockoutMs > 0) {
      sendJson(res, 429, { error: 'Too many failed attempts. Try again later.' });
      return;
    }

    // ── Network auth endpoints (unauthenticated — challenge-response flow) ──
    const url0 = new URL(req.url || '/', `https://localhost:${config.port}`);
    const pathname0 = url0.pathname;

    // POST /v1/auth/challenge — Issue a challenge nonce (no token needed)
    if (req.method === 'POST' && pathname0 === '/v1/auth/challenge') {
      if (!state.networkAuth) {
        sendJson(res, 501, { error: 'Network authentication is not configured (no identity database)' });
        return;
      }

      try {
        const body = await parseBody(req);
        const identityId = body.identity_id as string | undefined;
        if (!identityId || typeof identityId !== 'string') {
          sendJson(res, 400, { error: 'identity_id is required' });
          return;
        }

        const challenge = state.networkAuth.issueChallenge(identityId);
        if (!challenge) {
          // Don't reveal whether the identity exists — just return a generic error
          // But rate-limit to prevent enumeration
          state.rateLimiter.recordFailure(clientIp);
          sendJson(res, 400, { error: 'Unable to issue challenge' });
          return;
        }

        // Audit: log challenge issued (US-007)
        const identity = state.identityDb?.getIdentity(identityId);
        state.auditLogger.logNetworkEvent('auth.challenge', {
          ip: clientIp,
          identity_id: identityId,
          identity_name: identity?.name ?? null,
          mode: 'network',
          detail: `challenge_id=${challenge.challenge_id}`,
        });

        sendJson(res, 200, challenge);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to issue challenge';
        sendJson(res, 500, { error: message });
      }
      return;
    }

    // POST /v1/auth/verify — Verify a signed challenge and get a session token
    if (req.method === 'POST' && pathname0 === '/v1/auth/verify') {
      if (!state.networkAuth) {
        sendJson(res, 501, { error: 'Network authentication is not configured (no identity database)' });
        return;
      }

      try {
        const body = await parseBody(req);
        const challengeId = body.challenge_id as string | undefined;
        const identityId = body.identity_id as string | undefined;
        const signature = body.signature as string | undefined;
        const publicKey = body.public_key as string | undefined;

        if (!challengeId || typeof challengeId !== 'string') {
          sendJson(res, 400, { error: 'challenge_id is required' });
          return;
        }
        if (!identityId || typeof identityId !== 'string') {
          sendJson(res, 400, { error: 'identity_id is required' });
          return;
        }
        if (!signature || typeof signature !== 'string') {
          sendJson(res, 400, { error: 'signature is required' });
          return;
        }
        if (!publicKey || typeof publicKey !== 'string') {
          sendJson(res, 400, { error: 'public_key is required' });
          return;
        }

        const result = state.networkAuth.verifyChallenge(
          challengeId,
          identityId,
          signature,
          publicKey,
        );

        if (!result.success) {
          const identity = state.identityDb?.getIdentity(identityId!);
          state.auditLogger.logAuthFailure(clientIp, `network auth: ${result.error}`, {
            identity_id: identityId,
            identity_name: identity?.name ?? null,
            mode: 'network',
          });
          const nowLocked = state.rateLimiter.recordFailure(clientIp);
          if (nowLocked) {
            sendJson(res, 429, { error: 'Too many failed attempts. Try again later.' });
          } else {
            sendJson(res, 401, { error: result.error || 'Authentication failed' });
          }
          return;
        }

        // Auth succeeded — clear failure history
        state.rateLimiter.recordSuccess(clientIp);
        const verifiedIdentity = state.identityDb?.getIdentity(result.identity_id!);
        state.auditLogger.logNetworkEvent('auth.success', {
          ip: clientIp,
          identity_id: result.identity_id,
          identity_name: verifiedIdentity?.name ?? null,
          mode: 'network',
          detail: `session created`,
        });

        sendJson(res, 200, {
          ok: true,
          session_token: result.session_token,
          expires_in: result.expires_in,
          identity_id: result.identity_id,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to verify challenge';
        sendJson(res, 500, { error: message });
      }
      return;
    }

    // ── Access request endpoints (unauthenticated — agents use these before having access) ──

    // POST /v1/access-requests — Submit an access request
    if (req.method === 'POST' && pathname0 === '/v1/access-requests') {
      if (!state.accessRequestManager) {
        sendJson(res, 501, { error: 'Access requests are not configured (no identity database)' });
        return;
      }

      try {
        const body = await parseBody(req);
        const identityId = body.identity_id as string | undefined;
        const org = body.org as string | undefined;
        const project = body.project as string | undefined;
        const roleRequested = body.role_requested as string | undefined;
        const justification = body.justification as string | undefined;

        if (!identityId || typeof identityId !== 'string') {
          sendJson(res, 400, { error: 'identity_id is required' });
          return;
        }
        if (!org || typeof org !== 'string') {
          sendJson(res, 400, { error: 'org is required' });
          return;
        }
        if (!roleRequested || typeof roleRequested !== 'string') {
          sendJson(res, 400, { error: 'role_requested is required' });
          return;
        }
        if (!justification || typeof justification !== 'string') {
          sendJson(res, 400, { error: 'justification is required' });
          return;
        }

        const accessReq = state.accessRequestManager.createRequest({
          identity_id: identityId,
          org,
          project: project || null,
          role_requested: roleRequested as 'admin' | 'member' | 'readonly',
          justification,
        });

        // Audit: log access request creation (US-007)
        const reqIdentity = state.identityDb?.getIdentity(identityId);
        state.auditLogger.logNetworkEvent('access_request.created', {
          ip: clientIp,
          identity_id: identityId,
          identity_name: reqIdentity?.name ?? null,
          org,
          project: project || null,
          mode: 'network',
          detail: `request_id=${accessReq.request_id}, role=${roleRequested}`,
        });

        sendJson(res, 201, {
          request_id: accessReq.request_id,
          status: accessReq.status,
          created_at: accessReq.created_at,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to create access request';
        sendJson(res, 400, { error: message });
      }
      return;
    }

    // GET /v1/access-requests/:id — Poll access request status
    if (req.method === 'GET' && pathname0.startsWith('/v1/access-requests/')) {
      if (!state.accessRequestManager) {
        sendJson(res, 501, { error: 'Access requests are not configured (no identity database)' });
        return;
      }

      try {
        const requestId = decodeURIComponent(pathname0.slice('/v1/access-requests/'.length));
        if (!requestId) {
          sendJson(res, 400, { error: 'Request ID is required' });
          return;
        }

        const request = state.accessRequestManager.getRequest(requestId);
        if (!request) {
          sendJson(res, 404, { error: `Access request '${requestId}' not found` });
          return;
        }

        // Check and update expiry status
        if (request.status === 'pending' && state.accessRequestManager.isExpired(request)) {
          state.accessRequestManager.cleanExpired();
          const updated = state.accessRequestManager.getRequest(requestId);
          if (updated) {
            sendJson(res, 200, updated);
            return;
          }
        }

        sendJson(res, 200, request);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to get access request';
        sendJson(res, 500, { error: message });
      }
      return;
    }

    // ── Bearer token auth ─────────────────────────────────────────
    const authHeader = req.headers['authorization'] as string | undefined;

    // Extract the raw bearer token from the header
    let bearerToken: string | null = null;
    if (authHeader) {
      const parts = authHeader.split(' ');
      if (parts.length === 2 && parts[0] === 'Bearer') {
        bearerToken = parts[1];
      }
    }

    // Try bootstrap token first (disabled in network mode), then managed tokens
    let authOk = false;
    let authenticatedTokenName = 'bootstrap';
    let isBootstrapToken = false;
    let authenticatedIdentityId: string | null = null;
    if (!state.networkMode && bearerToken && validateBearerToken(authHeader, state.token)) {
      authOk = true;
      authenticatedTokenName = 'bootstrap';
      isBootstrapToken = true;
    } else if (bearerToken) {
      // Try managed token validation (US-005)
      const result = state.tokenManager.validate(bearerToken);
      if (result.valid) {
        authOk = true;
        authenticatedTokenName = result.tokenName || 'unknown';
        authenticatedIdentityId = result.identityId ?? null;
      } else if (result.reason === 'expired') {
        // Expired tokens return 401
        state.auditLogger.logAuthFailure(clientIp, `token expired: ${result.tokenName || 'unknown'}`);
        const nowLocked = state.rateLimiter.recordFailure(clientIp);
        if (nowLocked) {
          sendJson(res, 429, { error: 'Too many failed attempts. Try again later.' });
        } else {
          sendJson(res, 401, { error: 'Unauthorized' });
        }
        return;
      } else if (result.reason === 'max_uses_exceeded') {
        // Max-uses-exceeded tokens return 401
        state.auditLogger.logAuthFailure(clientIp, `max uses exceeded: ${result.tokenName || 'unknown'}`);
        const nowLocked = state.rateLimiter.recordFailure(clientIp);
        if (nowLocked) {
          sendJson(res, 429, { error: 'Too many failed attempts. Try again later.' });
        } else {
          sendJson(res, 401, { error: 'Unauthorized' });
        }
        return;
      }
    }

    // Try network auth session token (US-003)
    if (!authOk && bearerToken && state.networkAuth) {
      const sessionResult = state.networkAuth.validateSession(bearerToken);
      if (sessionResult.valid && sessionResult.session) {
        authOk = true;
        authenticatedTokenName = `session:${sessionResult.session.identity_id}`;
        authenticatedIdentityId = sessionResult.session.identity_id;
      }
    }

    if (!authOk) {
      state.auditLogger.logAuthFailure(clientIp, 'invalid token');
      const nowLocked = state.rateLimiter.recordFailure(clientIp);
      if (nowLocked) {
        sendJson(res, 429, { error: 'Too many failed attempts. Try again later.' });
      } else {
        // Return 401 with no information leakage
        sendJson(res, 401, { error: 'Unauthorized' });
      }
      return;
    }

    // Auth succeeded — clear any failure history
    state.rateLimiter.recordSuccess(clientIp);

    try {
      const url = new URL(req.url || '/', `https://localhost:${config.port}`);
      const pathname = url.pathname;

      // POST /v1/init — Initialize a new vault
      if (req.method === 'POST' && pathname === '/v1/init') {
        const body = await parseBody(req);
        const passphrase = body.passphrase as string;
        const force = body.force as boolean;

        if (!passphrase || typeof passphrase !== 'string') {
          sendJson(res, 400, { error: 'Passphrase is required' });
          return;
        }

        if (state.vault.isInitialized && !force) {
          sendJson(res, 409, { error: 'Vault is already initialized. Use --force to reinitialize.' });
          return;
        }

        if (state.vault.isInitialized && force) {
          // Close the existing vault and token manager DB before deleting files
          state.vault.close();
          try { state.tokenDb.close(); } catch { /* ok */ }
          if (fs.existsSync(config.vaultPath)) {
            fs.unlinkSync(config.vaultPath);
            // Also remove WAL and SHM files if they exist
            const walPath = config.vaultPath + '-wal';
            const shmPath = config.vaultPath + '-shm';
            if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
            if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
          }
          state.vault = new VaultEngine(config.vaultPath);
          // Recreate token manager with fresh DB connection
          state.tokenDb = new VaultDatabase(config.vaultPath);
          state.tokenManager = new TokenManager(state.tokenDb);
        }

        state.vault.init(passphrase);
        resetIdleTimer(state);
        sendJson(res, 200, {
          ok: true,
          message: 'Vault initialized and unlocked',
          vaultPath: config.vaultPath,
        });
        return;
      }

      // POST /v1/unlock — Unlock the vault
      if (req.method === 'POST' && pathname === '/v1/unlock') {
        const body = await parseBody(req);
        const passphrase = body.passphrase as string;

        if (!passphrase || typeof passphrase !== 'string') {
          sendJson(res, 400, { error: 'Passphrase is required' });
          return;
        }

        if (!state.vault.isInitialized) {
          sendJson(res, 400, { error: 'Vault is not initialized. Run `hq-vault init` first.' });
          return;
        }

        if (state.vault.isUnlocked) {
          resetIdleTimer(state);
          sendJson(res, 200, { ok: true, message: 'Vault is already unlocked' });
          return;
        }

        try {
          state.vault.unlock(passphrase);
          resetIdleTimer(state);
          sendJson(res, 200, { ok: true, message: 'Vault unlocked' });
        } catch {
          sendJson(res, 401, { error: 'Invalid passphrase' });
        }
        return;
      }

      // POST /v1/lock — Lock the vault
      if (req.method === 'POST' && pathname === '/v1/lock') {
        if (state.idleTimer) {
          clearTimeout(state.idleTimer);
          state.idleTimer = null;
        }
        state.vault.lock();
        sendJson(res, 200, { ok: true, message: 'Vault locked' });
        return;
      }

      // GET /v1/status — Get vault status
      if (req.method === 'GET' && pathname === '/v1/status') {
        resetIdleTimer(state);
        const status = state.vault.status();
        sendJson(res, 200, {
          ...status,
          serverRunning: true,
          port: state.boundPort,
          idleTimeoutMs: state.idleTimeoutMs,
          lastActivity: new Date(state.lastActivity).toISOString(),
          mode: state.networkMode ? 'network' : 'local',
        });
        return;
      }

      // ─── Secret management endpoints (US-003) ────────────────────────

      // PUT /v1/secrets/:path — Store a secret
      if (req.method === 'PUT' && pathname.startsWith('/v1/secrets/')) {
        const secretPath = decodeURIComponent(pathname.slice('/v1/secrets/'.length));
        if (!secretPath) {
          sendJson(res, 400, { error: 'Secret path is required' });
          return;
        }

        if (!state.vault.isUnlocked) {
          sendJson(res, 403, { error: 'Vault is locked. Unlock it first.' });
          return;
        }

        // ── Scope-based access control (US-002) ─────────────────────
        // Only enforced when: (a) not bootstrap token, (b) identity DB exists,
        // (c) the token is bound to an identity. Tokens without identity binding
        // retain full access for backward compatibility.
        if (!isBootstrapToken && state.identityDb && authenticatedIdentityId) {
          const scope = parseScope(secretPath);
          if (!scope.scoped) {
            sendJson(res, 403, { error: 'Unscoped secrets are only accessible via bootstrap token' });
            return;
          }
          const accessResult = checkAccess(state.identityDb, authenticatedIdentityId, secretPath, 'write');
          if (!accessResult.allowed) {
            sendJson(res, 403, { error: accessResult.reason });
            return;
          }
        }

        const body = await parseBody(req);
        const value = body.value as string | undefined;
        if (value === undefined || value === null || typeof value !== 'string') {
          sendJson(res, 400, { error: 'Secret value is required (string)' });
          return;
        }

        const metadata: Record<string, string | undefined> = {};
        if (body.type && typeof body.type === 'string') metadata.type = body.type;
        if (body.description && typeof body.description === 'string') metadata.description = body.description;
        if (body.expires_at && typeof body.expires_at === 'string') metadata.expires_at = body.expires_at;
        if (body.rotation_interval && typeof body.rotation_interval === 'string') metadata.rotation_interval = body.rotation_interval;

        try {
          state.vault.store(secretPath, value, metadata);
          resetIdleTimer(state);
          // Audit: log store operation (never log the secret value)
          state.auditLogger.logAccess('secret.store', {
            tokenName: authenticatedTokenName,
            secretPath,
            ip: clientIp,
            identity_id: authenticatedIdentityId,
            identity_name: authenticatedIdentityId ? state.identityDb?.getIdentity(authenticatedIdentityId)?.name : null,
            mode: state.networkMode ? 'network' : 'local',
          });
          sendJson(res, 200, {
            ok: true,
            path: secretPath,
            bytes: Buffer.byteLength(value, 'utf-8'),
            metadata,
          });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to store secret';
          sendJson(res, 400, { error: message });
        }
        return;
      }

      // GET /v1/secrets?prefix= — List secrets by prefix
      if (req.method === 'GET' && pathname === '/v1/secrets') {
        if (!state.vault.isUnlocked) {
          sendJson(res, 403, { error: 'Vault is locked. Unlock it first.' });
          return;
        }

        const url2 = new URL(req.url || '/', `https://localhost:${config.port}`);
        const prefix = url2.searchParams.get('prefix') || undefined;

        try {
          let entries = state.vault.list(prefix);

          // ── Scope-based filtering (US-002) ──────────────────────
          // Only filter when token is bound to an identity. Unbound tokens
          // retain full list access for backward compatibility.
          if (!isBootstrapToken && state.identityDb && authenticatedIdentityId) {
            const accessiblePaths = filterAccessiblePaths(
              state.identityDb,
              authenticatedIdentityId,
              entries.map(e => e.path),
            );
            const accessibleSet = new Set(accessiblePaths);
            entries = entries.filter(e => accessibleSet.has(e.path));
          }

          resetIdleTimer(state);
          // Audit: log list operation
          state.auditLogger.logAccess('secret.list', {
            tokenName: authenticatedTokenName,
            ip: clientIp,
            detail: prefix ? `prefix=${prefix}` : null,
            identity_id: authenticatedIdentityId,
            identity_name: authenticatedIdentityId ? state.identityDb?.getIdentity(authenticatedIdentityId)?.name : null,
            mode: state.networkMode ? 'network' : 'local',
          });
          sendJson(res, 200, { entries });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to list secrets';
          sendJson(res, 500, { error: message });
        }
        return;
      }

      // GET /v1/secrets/expiring?within=7d — List expiring secrets (US-009)
      if (req.method === 'GET' && pathname === '/v1/secrets/expiring') {
        if (!state.vault.isUnlocked) {
          sendJson(res, 403, { error: 'Vault is locked. Unlock it first.' });
          return;
        }

        const url3 = new URL(req.url || '/', `https://localhost:${config.port}`);
        const withinStr = url3.searchParams.get('within') || '7d';
        const { parseDuration } = await import('./vault.js');
        const withinMs = parseDuration(withinStr);
        if (!withinMs) {
          sendJson(res, 400, { error: `Invalid duration: ${withinStr}. Use e.g. 7d, 24h, 1w` });
          return;
        }

        try {
          const entries = state.vault.expiringSecrets(withinMs);
          resetIdleTimer(state);
          state.auditLogger.logAccess('secret.list', {
            tokenName: authenticatedTokenName,
            ip: clientIp,
            detail: `expiring within=${withinStr}`,
            identity_id: authenticatedIdentityId,
            identity_name: authenticatedIdentityId ? state.identityDb?.getIdentity(authenticatedIdentityId)?.name : null,
            mode: state.networkMode ? 'network' : 'local',
          });
          sendJson(res, 200, { entries });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to list expiring secrets';
          sendJson(res, 500, { error: message });
        }
        return;
      }

      // GET /v1/secrets/stale — List stale secrets (US-009)
      if (req.method === 'GET' && pathname === '/v1/secrets/stale') {
        if (!state.vault.isUnlocked) {
          sendJson(res, 403, { error: 'Vault is locked. Unlock it first.' });
          return;
        }

        try {
          const entries = state.vault.staleSecrets();
          resetIdleTimer(state);
          state.auditLogger.logAccess('secret.list', {
            tokenName: authenticatedTokenName,
            ip: clientIp,
            detail: 'stale secrets',
            identity_id: authenticatedIdentityId,
            identity_name: authenticatedIdentityId ? state.identityDb?.getIdentity(authenticatedIdentityId)?.name : null,
            mode: state.networkMode ? 'network' : 'local',
          });
          sendJson(res, 200, { entries });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to list stale secrets';
          sendJson(res, 500, { error: message });
        }
        return;
      }

      // GET /v1/secrets/:path — Get a decrypted secret
      if (req.method === 'GET' && pathname.startsWith('/v1/secrets/')) {
        const secretPath = decodeURIComponent(pathname.slice('/v1/secrets/'.length));
        if (!secretPath) {
          sendJson(res, 400, { error: 'Secret path is required' });
          return;
        }

        if (!state.vault.isUnlocked) {
          sendJson(res, 403, { error: 'Vault is locked. Unlock it first.' });
          return;
        }

        // ── Scope-based access control (US-002) ─────────────────────
        if (!isBootstrapToken && state.identityDb && authenticatedIdentityId) {
          const scope = parseScope(secretPath);
          if (!scope.scoped) {
            sendJson(res, 403, { error: 'Unscoped secrets are only accessible via bootstrap token' });
            return;
          }
          const accessResult = checkAccess(state.identityDb, authenticatedIdentityId, secretPath, 'read');
          if (!accessResult.allowed) {
            sendJson(res, 403, { error: accessResult.reason });
            return;
          }
        }

        try {
          const entry = state.vault.get(secretPath);
          resetIdleTimer(state);
          if (!entry) {
            sendJson(res, 404, { error: `Secret not found: ${secretPath}` });
            return;
          }
          // Audit: log get operation (never log the secret value)
          // Tag expired/stale accesses for audit visibility (US-009)
          const auditFields = {
            tokenName: authenticatedTokenName,
            secretPath,
            ip: clientIp,
            identity_id: authenticatedIdentityId,
            identity_name: authenticatedIdentityId ? state.identityDb?.getIdentity(authenticatedIdentityId)?.name : null,
            mode: (state.networkMode ? 'network' : 'local') as 'local' | 'network',
          };

          state.auditLogger.logAccess('secret.get', auditFields);

          if (entry.expired) {
            state.auditLogger.logAccess('secret.get.expired', {
              ...auditFields,
              detail: `expired at ${entry.metadata.expires_at}`,
            });
          }
          if (entry.stale) {
            state.auditLogger.logAccess('secret.get.stale', {
              ...auditFields,
              detail: `rotation_interval=${entry.metadata.rotation_interval}, last_rotated_at=${entry.metadata.last_rotated_at || entry.createdAt}`,
            });
          }

          sendJson(res, 200, {
            path: entry.path,
            value: entry.value,
            metadata: entry.metadata,
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            expired: entry.expired ?? false,
            stale: entry.stale ?? false,
          });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to get secret';
          sendJson(res, 500, { error: message });
        }
        return;
      }

      // DELETE /v1/secrets/:path — Delete a secret
      if (req.method === 'DELETE' && pathname.startsWith('/v1/secrets/')) {
        const secretPath = decodeURIComponent(pathname.slice('/v1/secrets/'.length));
        if (!secretPath) {
          sendJson(res, 400, { error: 'Secret path is required' });
          return;
        }

        if (!state.vault.isUnlocked) {
          sendJson(res, 403, { error: 'Vault is locked. Unlock it first.' });
          return;
        }

        // ── Scope-based access control (US-002) ─────────────────────
        if (!isBootstrapToken && state.identityDb && authenticatedIdentityId) {
          const scope = parseScope(secretPath);
          if (!scope.scoped) {
            sendJson(res, 403, { error: 'Unscoped secrets are only accessible via bootstrap token' });
            return;
          }
          const accessResult = checkAccess(state.identityDb, authenticatedIdentityId, secretPath, 'write');
          if (!accessResult.allowed) {
            sendJson(res, 403, { error: accessResult.reason });
            return;
          }
        }

        try {
          const deleted = state.vault.delete(secretPath);
          resetIdleTimer(state);
          if (!deleted) {
            sendJson(res, 404, { error: `Secret not found: ${secretPath}` });
            return;
          }
          // Audit: log delete operation
          state.auditLogger.logAccess('secret.delete', {
            tokenName: authenticatedTokenName,
            secretPath,
            ip: clientIp,
            identity_id: authenticatedIdentityId,
            identity_name: authenticatedIdentityId ? state.identityDb?.getIdentity(authenticatedIdentityId)?.name : null,
            mode: state.networkMode ? 'network' : 'local',
          });
          sendJson(res, 200, { ok: true, path: secretPath, message: 'Secret deleted' });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to delete secret';
          sendJson(res, 400, { error: message });
        }
        return;
      }

      // ─── Token management endpoints (US-005) ──────────────────────────

      // POST /v1/tokens — Create a new access token
      if (req.method === 'POST' && pathname === '/v1/tokens') {
        const body = await parseBody(req);
        const name = body.name as string | undefined;
        const ttl = body.ttl as string | undefined;
        const maxUses = body.max_uses as number | undefined;
        const identityId = body.identity_id as string | undefined;

        if (!name || typeof name !== 'string' || name.trim().length === 0) {
          sendJson(res, 400, { error: 'Token name is required' });
          return;
        }

        try {
          const result = state.tokenManager.create({
            name: name.trim(),
            ttl: ttl || null,
            maxUses: maxUses ?? null,
            identityId: identityId || null,
          });
          resetIdleTimer(state);
          sendJson(res, 201, {
            ok: true,
            token: result.token,
            metadata: result.metadata,
          });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to create token';
          sendJson(res, 400, { error: message });
        }
        return;
      }

      // GET /v1/tokens — List all tokens (metadata only)
      if (req.method === 'GET' && pathname === '/v1/tokens') {
        try {
          const tokens = state.tokenManager.list();
          resetIdleTimer(state);
          sendJson(res, 200, { tokens });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to list tokens';
          sendJson(res, 500, { error: message });
        }
        return;
      }

      // DELETE /v1/tokens/:name — Revoke a token
      if (req.method === 'DELETE' && pathname.startsWith('/v1/tokens/')) {
        const tokenName = decodeURIComponent(pathname.slice('/v1/tokens/'.length));
        if (!tokenName) {
          sendJson(res, 400, { error: 'Token name is required' });
          return;
        }

        try {
          const revoked = state.tokenManager.revoke(tokenName);
          resetIdleTimer(state);
          if (!revoked) {
            sendJson(res, 404, { error: `Token not found: ${tokenName}` });
            return;
          }
          sendJson(res, 200, { ok: true, name: tokenName, message: 'Token revoked' });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to revoke token';
          sendJson(res, 400, { error: message });
        }
        return;
      }

      // POST /v1/shutdown — Graceful shutdown
      if (req.method === 'POST' && pathname === '/v1/shutdown') {
        state.vault.lock();
        sendJson(res, 200, { ok: true, message: 'Server shutting down' });
        // Give response time to flush, then shut down
        setTimeout(() => {
          cleanup(config, state, server);
          process.exit(0);
        }, 100);
        return;
      }

      // 404 for everything else
      sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Internal server error';
      sendJson(res, 500, { error: message });
    }
  };
}

// We store a reference so the shutdown handler can use it
let server: https.Server | http.Server;

/**
 * Create and start the vault server.
 *
 * By default uses HTTPS with auto-generated self-signed certificates.
 * Pass `insecure: true` in config for plain HTTP (testing only).
 */
export function createVaultServer(config: ServerConfig): Promise<https.Server | http.Server> {
  const isNetwork = config.network === true;

  // ── Network mode validations (before allocating resources) ─────────
  if (isNetwork) {
    // Network mode REQUIRES TLS — refuse --insecure
    if (config.insecure) {
      throw new Error('Network mode requires TLS. Cannot use --insecure with --network.');
    }

    // Network mode REQUIRES at least one identity to exist.
    // We do a lightweight pre-check here before opening all the long-lived resources.
    let preCheckIdentityDb: IdentityDatabase | null = null;
    try {
      const idDbPath = config.identityDbPath || getDefaultIdentityDbPath();
      if (!fs.existsSync(idDbPath)) {
        throw new Error(
          'Network mode requires an identity database. Create at least one identity first with: hq-vault identity create',
        );
      }
      preCheckIdentityDb = new IdentityDatabase(idDbPath);
      const identities = preCheckIdentityDb.listIdentities();
      if (identities.length === 0) {
        throw new Error(
          'Network mode requires at least one identity. Create one first with: hq-vault identity create',
        );
      }
    } finally {
      try { if (preCheckIdentityDb) preCheckIdentityDb.close(); } catch { /* ok */ }
    }
  }

  // Generate or retrieve the bearer token
  const tokenFile = config.tokenFile || path.join(path.dirname(config.pidFile), 'token');
  const token = config.token || generateToken();

  // Write the token file (even in network mode, for internal management)
  writeTokenFile(tokenFile, token);

  // Open a database connection for the token manager (separate from VaultEngine's)
  const tokenDb = new VaultDatabase(config.vaultPath);
  const tokenManager = new TokenManager(tokenDb);

  // Initialize the audit logger
  const auditLogger = new AuditLogger(config.auditLogPath);

  // Initialize the identity database for scope-based access control (optional).
  // Only load if the identity DB file already exists or an explicit path was given.
  // This ensures backward compat: servers without identity setup skip scoping entirely.
  let identityDb: IdentityDatabase | null = null;
  if (config.identityDbPath) {
    try {
      identityDb = new IdentityDatabase(config.identityDbPath);
    } catch {
      // Identity DB could not be opened — scoping will be disabled
    }
  } else {
    const defaultIdDbPath = getDefaultIdentityDbPath();
    if (fs.existsSync(defaultIdDbPath)) {
      try {
        identityDb = new IdentityDatabase(defaultIdDbPath);
      } catch {
        // Identity DB could not be opened — scoping will be disabled
      }
    }
  }

  // Initialize network authenticator if identity DB is available (US-003).
  let networkAuth: NetworkAuthenticator | null = null;
  if (identityDb) {
    networkAuth = new NetworkAuthenticator(
      identityDb,
      config.challengeTtlMs,
      config.sessionTtlMs,
    );
  }

  // Initialize access request manager if identity DB is available (US-004).
  let accessRequestManager: AccessRequestManager | null = null;
  if (identityDb) {
    accessRequestManager = new AccessRequestManager(identityDb);
  }

  const state: ServerState = {
    vault: new VaultEngine(config.vaultPath),
    idleTimer: null,
    idleTimeoutMs: config.idleTimeoutMs,
    lastActivity: Date.now(),
    boundPort: config.port,
    token,
    rateLimiter: new RateLimiter(config.rateLimitConfig),
    tokenManager,
    tokenDb,
    auditLogger,
    identityDb,
    networkAuth,
    accessRequestManager,
    networkMode: isNetwork,
  };

  const handler = createRequestHandler(config, state);

  if (config.insecure) {
    // Plain HTTP for testing (never allowed in network mode — validated above)
    server = http.createServer(handler);
  } else {
    // HTTPS — use custom cert paths or auto-generated self-signed certs
    let certData: TlsCertData;
    if (config.tlsCertFile && config.tlsKeyFile) {
      // Custom CA-signed or user-provided certs
      certData = {
        cert: fs.readFileSync(config.tlsCertFile, 'utf-8'),
        key: fs.readFileSync(config.tlsKeyFile, 'utf-8'),
      };
    } else if (config.tlsCertData) {
      certData = config.tlsCertData;
    } else {
      certData = ensureCerts(config.tlsCertPaths);
      // In network mode, print a loud warning about self-signed certs
      if (isNetwork) {
        process.stderr.write('\n');
        process.stderr.write('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n');
        process.stderr.write('!!! WARNING: Using auto-generated self-signed certificate.  !!!\n');
        process.stderr.write('!!! This is NOT suitable for production use.                !!!\n');
        process.stderr.write('!!! Use --tls-cert and --tls-key with CA-signed certs.      !!!\n');
        process.stderr.write('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n');
        process.stderr.write('\n');
      }
    }
    server = https.createServer(
      {
        cert: certData.cert,
        key: certData.key,
      },
      handler,
    );
  }

  // Handle process signals for clean shutdown
  const onSignal = () => {
    cleanup(config, state, server);
    process.exit(0);
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  // Determine bind address
  const bindAddress = config.bindAddress || (isNetwork ? '0.0.0.0' : '127.0.0.1');

  return new Promise((resolve, reject) => {
    server.listen(config.port, bindAddress, () => {
      // Capture actual bound port (important when config.port is 0)
      const addr = server.address();
      if (typeof addr === 'object' && addr) {
        state.boundPort = addr.port;
      }

      // Write PID file
      const dir = path.dirname(config.pidFile);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(config.pidFile, process.pid.toString(), 'utf-8');

      // Write port file (use actual bound port)
      fs.writeFileSync(config.portFile, state.boundPort.toString(), 'utf-8');

      resolve(server);
    });

    server.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Clean up PID file, port file, idle timer, and lock the vault.
 */
function cleanup(config: ServerConfig, state: ServerState, srv: https.Server | http.Server): void {
  if (state.idleTimer) {
    clearTimeout(state.idleTimer);
    state.idleTimer = null;
  }
  try { state.vault.close(); } catch { /* ok */ }
  try { state.tokenDb.close(); } catch { /* ok */ }
  try { state.auditLogger.close(); } catch { /* ok */ }
  try { if (state.identityDb) state.identityDb.close(); } catch { /* ok */ }
  try { if (state.networkAuth) state.networkAuth.close(); } catch { /* ok */ }
  try { if (fs.existsSync(config.pidFile)) fs.unlinkSync(config.pidFile); } catch { /* ok */ }
  try { if (fs.existsSync(config.portFile)) fs.unlinkSync(config.portFile); } catch { /* ok */ }
  try { srv.close(); } catch { /* ok */ }
}

/**
 * Check if a vault server is already running by reading the PID file.
 */
export function isServerRunning(pidFile: string): { running: boolean; pid?: number } {
  if (!fs.existsSync(pidFile)) {
    return { running: false };
  }

  const pidStr = fs.readFileSync(pidFile, 'utf-8').trim();
  const pid = parseInt(pidStr, 10);
  if (isNaN(pid)) {
    return { running: false };
  }

  try {
    // Sending signal 0 checks if process exists without killing it
    process.kill(pid, 0);
    return { running: true, pid };
  } catch {
    // Process doesn't exist — stale PID file
    try { fs.unlinkSync(pidFile); } catch { /* ok */ }
    return { running: false };
  }
}

/**
 * Read the port from the port file.
 */
export function readServerPort(portFile: string): number | null {
  if (!fs.existsSync(portFile)) {
    return null;
  }

  const portStr = fs.readFileSync(portFile, 'utf-8').trim();
  const port = parseInt(portStr, 10);
  return isNaN(port) ? null : port;
}
