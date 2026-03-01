/**
 * Audit logging module for hq-vault — US-010.
 *
 * Provides:
 * - Append-only audit log at ~/.hq-vault/audit.log
 * - Logs every secret access (get, store, delete, list) with:
 *   timestamp, token name, operation, secret path, IP
 * - Logs failed auth attempts with: timestamp, IP, reason
 * - Secret values are NEVER logged — only paths and metadata
 * - Log cannot be modified through the API (file-system only)
 * - Supports reading/filtering/tailing the audit log
 */

import fs from 'node:fs';
import path from 'node:path';
import { getVaultDir } from './server.js';

// ─── Types ──────────────────────────────────────────────────────────

export type AuditOperation =
  | 'secret.get'
  | 'secret.store'
  | 'secret.delete'
  | 'secret.list'
  | 'network-auth.verify'
  | 'auth.failure';

export interface AuditEntry {
  /** ISO 8601 timestamp. */
  timestamp: string;
  /** Operation performed. */
  operation: AuditOperation;
  /** Name of the token used (or 'bootstrap' for admin token, null for auth failures). */
  tokenName: string | null;
  /** Secret path involved (null for list/auth operations). */
  secretPath: string | null;
  /** Client IP address. */
  ip: string;
  /** Additional context (e.g., failure reason, list prefix). */
  detail: string | null;
}

export interface AuditFilterOptions {
  /** Filter by secret path (substring match). */
  path?: string;
  /** Filter by token name (exact match). */
  token?: string;
  /** Filter entries since this ISO 8601 date/time. */
  since?: string;
  /** Maximum number of entries to return. */
  limit?: number;
}

// ─── AuditLogger ────────────────────────────────────────────────────

/**
 * Append-only audit logger that writes JSON lines to a file.
 *
 * Each line is a self-contained JSON object (JSONL format) for easy
 * parsing, streaming, and tailing.
 *
 * The log file is opened in append mode ('a') — existing content is
 * never modified or truncated.
 */
export class AuditLogger {
  private logPath: string;
  private fd: number | null = null;

  constructor(logPath?: string) {
    this.logPath = logPath || getDefaultAuditLogPath();
  }

  /**
   * Get the path to the audit log file.
   */
  getLogPath(): string {
    return this.logPath;
  }

  /**
   * Ensure the log directory exists and open the file descriptor.
   */
  private ensureOpen(): void {
    if (this.fd !== null) return;

    const dir = path.dirname(this.logPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.fd = fs.openSync(this.logPath, 'a');
  }

  /**
   * Log a secret access operation.
   *
   * IMPORTANT: Never pass secret values to this method.
   * Only paths and metadata are logged.
   */
  logAccess(
    operation: Exclude<AuditOperation, 'auth.failure'>,
    opts: {
      tokenName: string;
      secretPath?: string | null;
      ip: string;
      detail?: string | null;
    },
  ): void {
    this.writeEntry({
      timestamp: new Date().toISOString(),
      operation,
      tokenName: opts.tokenName,
      secretPath: opts.secretPath ?? null,
      ip: opts.ip,
      detail: opts.detail ?? null,
    });
  }

  /**
   * Log a failed authentication attempt.
   */
  logAuthFailure(ip: string, reason: string): void {
    this.writeEntry({
      timestamp: new Date().toISOString(),
      operation: 'auth.failure',
      tokenName: null,
      secretPath: null,
      ip,
      detail: reason,
    });
  }

  /**
   * Write a single audit entry as a JSON line.
   */
  private writeEntry(entry: AuditEntry): void {
    this.ensureOpen();
    const line = JSON.stringify(entry) + '\n';
    fs.writeSync(this.fd!, line);
  }

  /**
   * Close the file descriptor.
   */
  close(): void {
    if (this.fd !== null) {
      try { fs.closeSync(this.fd); } catch { /* ok */ }
      this.fd = null;
    }
  }
}

// ─── Audit log reading ──────────────────────────────────────────────

/**
 * Get the default audit log path.
 * Respects HQ_VAULT_DIR environment variable.
 */
export function getDefaultAuditLogPath(): string {
  return path.join(getVaultDir(), 'audit.log');
}

/**
 * Read and parse audit log entries from the log file.
 *
 * Supports filtering by path, token, and time range.
 * Returns entries in chronological order (oldest first).
 */
export function readAuditLog(
  logPath?: string,
  filters?: AuditFilterOptions,
): AuditEntry[] {
  const filePath = logPath || getDefaultAuditLogPath();

  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').filter((line) => line.trim().length > 0);

  let entries: AuditEntry[] = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line) as AuditEntry);
    } catch {
      // Skip malformed lines (should not happen, but be defensive)
    }
  }

  // Apply filters
  if (filters?.path) {
    const pathFilter = filters.path;
    entries = entries.filter(
      (e) => e.secretPath !== null && e.secretPath.includes(pathFilter),
    );
  }

  if (filters?.token) {
    const tokenFilter = filters.token;
    entries = entries.filter(
      (e) => e.tokenName !== null && e.tokenName === tokenFilter,
    );
  }

  if (filters?.since) {
    const sinceDate = new Date(filters.since);
    if (!isNaN(sinceDate.getTime())) {
      entries = entries.filter(
        (e) => new Date(e.timestamp).getTime() >= sinceDate.getTime(),
      );
    }
  }

  if (filters?.limit && filters.limit > 0) {
    // Return the most recent N entries
    entries = entries.slice(-filters.limit);
  }

  return entries;
}

/**
 * Tail the audit log file, calling the callback for each new line.
 *
 * Returns a function to stop tailing.
 */
export function tailAuditLog(
  logPath: string | undefined,
  onEntry: (entry: AuditEntry) => void,
): () => void {
  const filePath = logPath || getDefaultAuditLogPath();

  // If the file doesn't exist yet, create it so we can watch it
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, '', 'utf-8');
  }

  let position = fs.statSync(filePath).size;
  let buffer = '';
  let stopped = false;

  // Poll-based approach (more reliable than fs.watch across platforms)
  const interval = setInterval(() => {
    if (stopped) return;

    try {
      const stat = fs.statSync(filePath);
      if (stat.size <= position) return;

      const fd = fs.openSync(filePath, 'r');
      const chunk = Buffer.alloc(stat.size - position);
      fs.readSync(fd, chunk, 0, chunk.length, position);
      fs.closeSync(fd);

      position = stat.size;
      buffer += chunk.toString('utf-8');

      // Process complete lines
      const lines = buffer.split('\n');
      // Keep the last element (might be incomplete)
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.trim().length === 0) continue;
        try {
          const entry = JSON.parse(line) as AuditEntry;
          onEntry(entry);
        } catch {
          // Skip malformed lines
        }
      }
    } catch {
      // File may have been deleted or rotated — just continue
    }
  }, 200);

  return () => {
    stopped = true;
    clearInterval(interval);
  };
}
