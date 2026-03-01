/**
 * Worker SDK — simple, high-level API for agents and workers to access vault secrets.
 *
 * Designed to be the primary interface for programmatic vault access.
 * Auto-discovers vault URL and token from environment variables.
 *
 * Usage:
 *   import { getSecret, storeSecret, listSecrets } from 'hq-vault/sdk';
 *
 *   const apiKey = await getSecret('aws/access-key');
 *   await storeSecret('slack/token', 'xoxb-...', { type: 'oauth-token' });
 *   const entries = await listSecrets('aws/');
 *
 * Environment variables:
 *   HQ_VAULT_URL   — Vault server URL (default: https://localhost:13100)
 *   HQ_VAULT_TOKEN — Bearer token for authentication (required)
 */

import { request, type ClientConfig } from './client.js';

/** Default vault server URL when HQ_VAULT_URL is not set. */
const DEFAULT_VAULT_URL = 'https://localhost:13100';

/** Metadata that can be attached to a secret. */
export interface SecretMetadata {
  type?: string;
  description?: string;
  [key: string]: unknown;
}

/** An entry returned by listSecrets. */
export interface SecretEntry {
  path: string;
  metadata: SecretMetadata;
  createdAt: string;
  updatedAt: string;
}

/**
 * SDK configuration options (overrides environment variables).
 */
export interface VaultSdkConfig {
  /** Vault server URL (overrides HQ_VAULT_URL). */
  url?: string;
  /** Bearer token for authentication (overrides HQ_VAULT_TOKEN). */
  token?: string;
}

/**
 * Custom error class for vault SDK errors.
 */
export class VaultSdkError extends Error {
  /** HTTP status code from the vault server, if available. */
  public readonly statusCode?: number;
  /** Error code for programmatic handling. */
  public readonly code: string;

  constructor(message: string, code: string, statusCode?: number) {
    super(message);
    this.name = 'VaultSdkError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Parse the vault URL into a ClientConfig.
 * Supports both http and https URLs.
 */
function resolveConfig(overrides?: VaultSdkConfig): ClientConfig {
  const urlStr = overrides?.url || process.env.HQ_VAULT_URL || DEFAULT_VAULT_URL;
  const token = overrides?.token || process.env.HQ_VAULT_TOKEN;

  if (!token) {
    throw new VaultSdkError(
      'No vault token provided. Set HQ_VAULT_TOKEN environment variable or pass token in config.',
      'NO_TOKEN',
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    throw new VaultSdkError(
      `Invalid vault URL: ${urlStr}. Expected format: https://localhost:13100`,
      'INVALID_URL',
    );
  }

  const isHttp = parsed.protocol === 'http:';
  const defaultPort = isHttp ? 80 : 443;
  const port = parsed.port ? parseInt(parsed.port, 10) : defaultPort;

  return {
    host: parsed.hostname,
    port,
    token,
    insecure: isHttp,
    rejectUnauthorized: false, // Self-signed certs
  };
}

/**
 * Get a decrypted secret value from the vault.
 *
 * @param path - The secret path (e.g. 'aws/access-key', 'slack/indigo/token')
 * @param config - Optional SDK configuration overrides
 * @returns The decrypted secret value as a string
 * @throws VaultSdkError if the secret is not found, vault is locked, or connection fails
 *
 * @example
 * ```ts
 * const apiKey = await getSecret('aws/access-key');
 * ```
 */
export async function getSecret(path: string, config?: VaultSdkConfig): Promise<string> {
  const clientConfig = resolveConfig(config);

  let res;
  try {
    res = await request(
      clientConfig,
      'GET',
      `/v1/secrets/${encodeURIComponent(path)}`,
    );
  } catch (err) {
    throw wrapConnectionError(err);
  }

  if (res.statusCode === 200) {
    return res.body.value as string;
  }

  if (res.statusCode === 404) {
    throw new VaultSdkError(
      `Secret not found: ${path}`,
      'NOT_FOUND',
      404,
    );
  }

  if (res.statusCode === 403) {
    throw new VaultSdkError(
      'Vault is locked. Unlock it before accessing secrets.',
      'VAULT_LOCKED',
      403,
    );
  }

  if (res.statusCode === 401) {
    throw new VaultSdkError(
      'Authentication failed. Check your HQ_VAULT_TOKEN.',
      'UNAUTHORIZED',
      401,
    );
  }

  throw new VaultSdkError(
    `Vault server error: ${res.body.error || 'Unknown error'}`,
    'SERVER_ERROR',
    res.statusCode,
  );
}

/**
 * Store a secret in the vault.
 *
 * @param path - The secret path (e.g. 'aws/access-key', 'slack/indigo/token')
 * @param value - The secret value to store
 * @param metadata - Optional metadata (type, description)
 * @param config - Optional SDK configuration overrides
 *
 * @example
 * ```ts
 * await storeSecret('slack/token', 'xoxb-1234', { type: 'oauth-token' });
 * ```
 */
export async function storeSecret(
  path: string,
  value: string,
  metadata?: SecretMetadata,
  config?: VaultSdkConfig,
): Promise<void> {
  const clientConfig = resolveConfig(config);

  const body: Record<string, unknown> = { value };
  if (metadata?.type) body.type = metadata.type;
  if (metadata?.description) body.description = metadata.description;

  let res;
  try {
    res = await request(
      clientConfig,
      'PUT',
      `/v1/secrets/${encodeURIComponent(path)}`,
      body,
    );
  } catch (err) {
    throw wrapConnectionError(err);
  }

  if (res.statusCode === 200) {
    return;
  }

  if (res.statusCode === 403) {
    throw new VaultSdkError(
      'Vault is locked. Unlock it before storing secrets.',
      'VAULT_LOCKED',
      403,
    );
  }

  if (res.statusCode === 401) {
    throw new VaultSdkError(
      'Authentication failed. Check your HQ_VAULT_TOKEN.',
      'UNAUTHORIZED',
      401,
    );
  }

  throw new VaultSdkError(
    `Vault server error: ${res.body.error || 'Unknown error'}`,
    'SERVER_ERROR',
    res.statusCode,
  );
}

/**
 * List secrets in the vault, optionally filtered by a path prefix.
 *
 * @param prefix - Optional path prefix to filter by (e.g. 'aws/' returns all aws/* secrets)
 * @param config - Optional SDK configuration overrides
 * @returns Array of secret entries (paths and metadata, NOT values)
 *
 * @example
 * ```ts
 * const awsSecrets = await listSecrets('aws/');
 * for (const entry of awsSecrets) {
 *   console.log(entry.path, entry.metadata.type);
 * }
 * ```
 */
export async function listSecrets(
  prefix?: string,
  config?: VaultSdkConfig,
): Promise<SecretEntry[]> {
  const clientConfig = resolveConfig(config);

  const queryStr = prefix ? `?prefix=${encodeURIComponent(prefix)}` : '';

  let res;
  try {
    res = await request(
      clientConfig,
      'GET',
      `/v1/secrets${queryStr}`,
    );
  } catch (err) {
    throw wrapConnectionError(err);
  }

  if (res.statusCode === 200) {
    const entries = res.body.entries as Array<{
      path: string;
      metadata: SecretMetadata;
      createdAt: string;
      updatedAt: string;
    }>;
    return entries.map((e) => ({
      path: e.path,
      metadata: e.metadata || {},
      createdAt: e.createdAt,
      updatedAt: e.updatedAt,
    }));
  }

  if (res.statusCode === 403) {
    throw new VaultSdkError(
      'Vault is locked. Unlock it before listing secrets.',
      'VAULT_LOCKED',
      403,
    );
  }

  if (res.statusCode === 401) {
    throw new VaultSdkError(
      'Authentication failed. Check your HQ_VAULT_TOKEN.',
      'UNAUTHORIZED',
      401,
    );
  }

  throw new VaultSdkError(
    `Vault server error: ${res.body.error || 'Unknown error'}`,
    'SERVER_ERROR',
    res.statusCode,
  );
}

/**
 * Wrap connection-level errors (ECONNREFUSED, timeout) in VaultSdkError
 * with clear, actionable messages.
 */
function wrapConnectionError(err: unknown): VaultSdkError {
  if (err instanceof VaultSdkError) {
    return err;
  }
  const message = err instanceof Error ? err.message : String(err);

  if (message.includes('not running')) {
    return new VaultSdkError(
      'Vault server is not running. Start it with: hq-vault serve',
      'CONNECTION_REFUSED',
    );
  }
  if (message.includes('timed out')) {
    return new VaultSdkError(
      'Connection to vault server timed out. Is the server running?',
      'TIMEOUT',
    );
  }
  return new VaultSdkError(
    `Failed to connect to vault server: ${message}`,
    'CONNECTION_ERROR',
  );
}
