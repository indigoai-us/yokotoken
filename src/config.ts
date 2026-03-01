/**
 * Vault configuration persistence module — US-006.
 *
 * Provides persistent configuration for remote vault connections stored at
 * ~/.hq-vault/config.json. Supports get/set/show operations for fields:
 * - remote_url: Remote vault server URL
 * - identity: Identity name for challenge-response auth
 * - key_file: Path to Ed25519 private key file
 * - ca_cert: Path to custom CA certificate for self-signed server certs
 */

import fs from 'node:fs';
import path from 'node:path';

// ─── Types ──────────────────────────────────────────────────────────

export interface VaultConfig {
  /** Remote vault server URL. */
  remote_url?: string;
  /** Identity name for challenge-response auth. */
  identity?: string;
  /** Path to Ed25519 private key file (base64-encoded). */
  key_file?: string;
  /** Path to custom CA certificate for self-signed server certs. */
  ca_cert?: string;
}

/** Valid config field names. */
export type VaultConfigField = keyof VaultConfig;

/** CLI-friendly field name mapping (kebab-case -> snake_case). */
const FIELD_ALIASES: Record<string, VaultConfigField> = {
  'remote-url': 'remote_url',
  'remote_url': 'remote_url',
  'identity': 'identity',
  'key-file': 'key_file',
  'key_file': 'key_file',
  'ca-cert': 'ca_cert',
  'ca_cert': 'ca_cert',
};

const VALID_FIELDS: VaultConfigField[] = ['remote_url', 'identity', 'key_file', 'ca_cert'];

// ─── Config Manager ─────────────────────────────────────────────────

/**
 * Get the default config file path: ~/.hq-vault/config.json
 */
export function getDefaultConfigPath(): string {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  return path.join(home, '.hq-vault', 'config.json');
}

/**
 * Resolve a CLI field name (kebab-case or snake_case) to a VaultConfigField.
 * Returns null if the field name is invalid.
 */
export function resolveFieldName(name: string): VaultConfigField | null {
  return FIELD_ALIASES[name] ?? null;
}

/**
 * Read the vault config file. Returns empty config if file doesn't exist.
 */
export function readConfig(configPath?: string): VaultConfig {
  const filePath = configPath ?? getDefaultConfigPath();
  if (!fs.existsSync(filePath)) {
    return {};
  }
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    // Only return known fields
    const config: VaultConfig = {};
    for (const field of VALID_FIELDS) {
      if (typeof parsed[field] === 'string' && parsed[field].length > 0) {
        config[field] = parsed[field];
      }
    }
    return config;
  } catch {
    return {};
  }
}

/**
 * Write the vault config file. Creates the directory if it doesn't exist.
 */
export function writeConfig(config: VaultConfig, configPath?: string): void {
  const filePath = configPath ?? getDefaultConfigPath();
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  // Only persist known fields with values
  const toWrite: VaultConfig = {};
  for (const field of VALID_FIELDS) {
    if (config[field] !== undefined && config[field] !== null && config[field] !== '') {
      toWrite[field] = config[field];
    }
  }
  fs.writeFileSync(filePath, JSON.stringify(toWrite, null, 2) + '\n', {
    encoding: 'utf-8',
    mode: 0o600,
  });
}

/**
 * Set a single config field value.
 */
export function setConfigField(
  field: VaultConfigField,
  value: string,
  configPath?: string,
): void {
  if (!VALID_FIELDS.includes(field)) {
    throw new Error(`Invalid config field: '${field}'. Valid fields: ${VALID_FIELDS.join(', ')}`);
  }
  const config = readConfig(configPath);
  config[field] = value;
  writeConfig(config, configPath);
}

/**
 * Get a single config field value.
 */
export function getConfigField(
  field: VaultConfigField,
  configPath?: string,
): string | undefined {
  if (!VALID_FIELDS.includes(field)) {
    throw new Error(`Invalid config field: '${field}'. Valid fields: ${VALID_FIELDS.join(', ')}`);
  }
  const config = readConfig(configPath);
  return config[field];
}

/**
 * Delete a single config field.
 */
export function deleteConfigField(
  field: VaultConfigField,
  configPath?: string,
): void {
  if (!VALID_FIELDS.includes(field)) {
    throw new Error(`Invalid config field: '${field}'. Valid fields: ${VALID_FIELDS.join(', ')}`);
  }
  const config = readConfig(configPath);
  delete config[field];
  writeConfig(config, configPath);
}

/**
 * Format config for display. Redacts key_file to just the filename.
 */
export function formatConfigForDisplay(config: VaultConfig): Record<string, string> {
  const display: Record<string, string> = {};

  if (config.remote_url) {
    display['remote-url'] = config.remote_url;
  }
  if (config.identity) {
    display['identity'] = config.identity;
  }
  if (config.key_file) {
    // Redact to just filename for security
    display['key-file'] = path.basename(config.key_file);
  }
  if (config.ca_cert) {
    display['ca-cert'] = config.ca_cert;
  }

  return display;
}

/**
 * Get the list of valid field names (for CLI help).
 */
export function getValidFields(): string[] {
  return [...VALID_FIELDS];
}
