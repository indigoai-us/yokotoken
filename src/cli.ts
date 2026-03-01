#!/usr/bin/env node

/**
 * hq-vault CLI — command-line interface for the vault.
 *
 * Commands:
 * - init     Create a new vault (prompts for passphrase via stdin)
 * - unlock   Unlock the vault (prompts for passphrase via stdin)
 * - lock     Wipe the decryption key from memory
 * - status   Show vault status
 * - serve    Start the vault server (holds key in memory)
 */

import { Command } from 'commander';
import { readPassphrase, readAndConfirmPassphrase } from './passphrase.js';
import {
  createVaultServer,
  getDefaultVaultPath,
  getDefaultPidFile,
  getDefaultPortFile,
  isServerRunning,
  readServerPort,
  DEFAULT_PORT,
} from './server.js';
import { request } from './client.js';
import { getDefaultTokenFile, readTokenFile } from './auth.js';
import { startWebEntry } from './web-entry.js';
import { startDaemon, stopDaemon, restartDaemon, getDefaultLogFile } from './daemon.js';
import {
  readAuditLog,
  tailAuditLog,
  getDefaultAuditLogPath,
  type AuditEntry,
} from './audit.js';
import {
  createBackup,
  restoreBackup,
  exportEnv,
  importEnv,
  parseEnvFile,
  envNameToPath,
  detectImportDuplicates,
} from './backup.js';
import fs from 'node:fs';

const program = new Command();

program
  .name('hq-vault')
  .description('Agent-native encrypted credential vault')
  .version('0.1.0');

/**
 * Helper: get the server port, either from the port file or default.
 */
function getServerPort(): number {
  const portFile = getDefaultPortFile();
  const port = readServerPort(portFile);
  return port ?? DEFAULT_PORT;
}

/**
 * Helper: get the bearer token from the token file.
 */
function getServerToken(): string | undefined {
  const tokenFile = getDefaultTokenFile();
  return readTokenFile(tokenFile) || undefined;
}

/**
 * Helper: ensure the vault server is running. Returns the port.
 */
function ensureServerRunning(): number {
  const pidFile = getDefaultPidFile();
  const { running } = isServerRunning(pidFile);
  if (!running) {
    process.stderr.write('Error: Vault server is not running. Start it with: hq-vault serve\n');
    process.exit(1);
  }
  return getServerPort();
}

// ─── init ───────────────────────────────────────────────────────────
program
  .command('init')
  .description('Create a new vault')
  .option('--force', 'Overwrite existing vault')
  .option('--vault-path <path>', 'Path to vault database', getDefaultVaultPath())
  .action(async (opts) => {
    try {
      const vaultPath = opts.vaultPath;

      // Check if vault already exists (before starting server)
      if (fs.existsSync(vaultPath) && !opts.force) {
        process.stderr.write(
          `Error: Vault already exists at ${vaultPath}\n` +
          'Use --force to reinitialize (this will destroy all stored secrets).\n'
        );
        process.exit(1);
      }

      // Prompt for passphrase with confirmation
      const passphrase = await readAndConfirmPassphrase();

      // Check if server is running; if so, use it. Otherwise, do inline init.
      const pidFile = getDefaultPidFile();
      const { running } = isServerRunning(pidFile);

      if (running) {
        const serverPort = getServerPort();
        const token = getServerToken();
        const res = await request(
          { port: serverPort, host: '127.0.0.1', token },
          'POST',
          '/v1/init',
          { passphrase, force: opts.force || false },
        );

        if (res.statusCode === 200) {
          process.stderr.write(`Vault initialized at ${vaultPath}\n`);
          process.stderr.write('Vault is now unlocked.\n');
        } else {
          process.stderr.write(`Error: ${res.body.error}\n`);
          process.exit(1);
        }
      } else {
        // No server running — start a temporary one for init, then stop
        // Actually, for init we can just create the vault directly
        // without needing the server, since no key needs to persist
        const { VaultEngine } = await import('./vault.js');

        if (opts.force && fs.existsSync(vaultPath)) {
          fs.unlinkSync(vaultPath);
          const walPath = vaultPath + '-wal';
          const shmPath = vaultPath + '-shm';
          if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
          if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
        }

        const vault = new VaultEngine(vaultPath);
        vault.init(passphrase);
        vault.close();

        process.stderr.write(`Vault initialized at ${vaultPath}\n`);
        process.stderr.write('Start the vault server with: hq-vault serve\n');
        process.stderr.write('Then unlock with: hq-vault unlock\n');
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── serve ──────────────────────────────────────────────────────────
program
  .command('serve')
  .description('Start the vault server (holds key in memory)')
  .option('--port <number>', 'Server port', String(DEFAULT_PORT))
  .option('--vault-path <path>', 'Path to vault database', getDefaultVaultPath())
  .option('--idle-timeout <minutes>', 'Auto-lock after N minutes of inactivity (0 to disable)', '30')
  .option('--insecure', 'Use plain HTTP instead of HTTPS (NOT recommended)')
  .option('--network', 'Enable network mode: bind to 0.0.0.0, require TLS and identity auth')
  .option('--bind <address>', 'Custom bind address (default: 127.0.0.1 for local, 0.0.0.0 for network)')
  .option('--tls-cert <path>', 'Path to TLS certificate file (PEM)')
  .option('--tls-key <path>', 'Path to TLS private key file (PEM)')
  .option('--daemon', 'Run the server as a background daemon process')
  .option('--stop', 'Stop a running daemon')
  .option('--restart', 'Restart the daemon')
  .action(async (opts) => {
    try {
      // ── Stop daemon ────────────────────────────────────────────
      if (opts.stop) {
        const result = await stopDaemon();
        if (result.success) {
          process.stderr.write(`Vault daemon stopped (was PID ${result.pid})\n`);
        } else {
          process.stderr.write(`Error: ${result.error}\n`);
          process.exit(1);
        }
        return;
      }

      // ── Restart daemon ─────────────────────────────────────────
      if (opts.restart) {
        process.stderr.write('Restarting vault daemon...\n');
        const result = await restartDaemon({
          port: opts.port !== String(DEFAULT_PORT) ? parseInt(opts.port, 10) : undefined,
          vaultPath: opts.vaultPath !== getDefaultVaultPath() ? opts.vaultPath : undefined,
          idleTimeout: opts.idleTimeout !== '30' ? opts.idleTimeout : undefined,
          insecure: opts.insecure || false,
        });

        if (result.success) {
          process.stderr.write(`Vault daemon restarted (PID ${result.pid})\n`);
          if (result.port) {
            const protocol = opts.insecure ? 'http' : 'https';
            process.stderr.write(`Listening on ${protocol}://127.0.0.1:${result.port}\n`);
          }
          process.stderr.write(`Logs: ${result.logFile || getDefaultLogFile()}\n`);
        } else {
          process.stderr.write(`Error: ${result.error}\n`);
          process.exit(1);
        }
        return;
      }

      // ── Daemon mode ────────────────────────────────────────────
      if (opts.daemon) {
        const result = await startDaemon({
          port: opts.port !== String(DEFAULT_PORT) ? parseInt(opts.port, 10) : undefined,
          vaultPath: opts.vaultPath !== getDefaultVaultPath() ? opts.vaultPath : undefined,
          idleTimeout: opts.idleTimeout !== '30' ? opts.idleTimeout : undefined,
          insecure: opts.insecure || false,
        });

        if (result.success) {
          const protocol = opts.insecure ? 'http' : 'https';
          process.stderr.write(`Vault daemon started (PID ${result.pid})\n`);
          if (result.port) {
            process.stderr.write(`Listening on ${protocol}://127.0.0.1:${result.port}\n`);
          }
          process.stderr.write(`Logs: ${result.logFile || getDefaultLogFile()}\n`);
          process.stderr.write('Vault is locked. Unlock with: hq-vault unlock\n');
        } else {
          process.stderr.write(`Error: ${result.error}\n`);
          process.exit(1);
        }
        return;
      }

      // ── Foreground mode (default) ──────────────────────────────
      const port = parseInt(opts.port, 10);
      const vaultPath = opts.vaultPath;
      const idleTimeoutMinutes = parseInt(opts.idleTimeout, 10);
      const idleTimeoutMs = idleTimeoutMinutes * 60 * 1000;
      const pidFile = getDefaultPidFile();
      const portFile = getDefaultPortFile();
      const isNetwork = opts.network || false;

      // ── Network mode CLI validations ─────────────────────────
      if (isNetwork && opts.insecure) {
        process.stderr.write('Error: Cannot use --insecure with --network. Network mode requires TLS.\n');
        process.exit(1);
      }

      // Validate --tls-cert and --tls-key are provided together
      if ((opts.tlsCert && !opts.tlsKey) || (!opts.tlsCert && opts.tlsKey)) {
        process.stderr.write('Error: --tls-cert and --tls-key must be provided together.\n');
        process.exit(1);
      }

      // Validate cert/key files exist
      if (opts.tlsCert && !fs.existsSync(opts.tlsCert)) {
        process.stderr.write(`Error: TLS certificate file not found: ${opts.tlsCert}\n`);
        process.exit(1);
      }
      if (opts.tlsKey && !fs.existsSync(opts.tlsKey)) {
        process.stderr.write(`Error: TLS key file not found: ${opts.tlsKey}\n`);
        process.exit(1);
      }

      // Check if server is already running
      const { running, pid } = isServerRunning(pidFile);
      if (running) {
        process.stderr.write(`Error: Vault server is already running (PID ${pid})\n`);
        process.exit(1);
      }

      // Check vault exists
      if (!fs.existsSync(vaultPath)) {
        process.stderr.write(
          `Error: No vault found at ${vaultPath}\n` +
          'Initialize one with: hq-vault init\n'
        );
        process.exit(1);
      }

      const server = await createVaultServer({
        vaultPath,
        port,
        idleTimeoutMs,
        pidFile,
        portFile,
        insecure: opts.insecure || false,
        network: isNetwork,
        bindAddress: opts.bind || undefined,
        tlsCertFile: opts.tlsCert || undefined,
        tlsKeyFile: opts.tlsKey || undefined,
      });

      const addr = server.address();
      const boundPort = typeof addr === 'object' && addr ? addr.port : port;
      const protocol = opts.insecure ? 'http' : 'https';
      const bindAddr = opts.bind || (isNetwork ? '0.0.0.0' : '127.0.0.1');

      process.stderr.write(`hq-vault server listening on ${protocol}://${bindAddr}:${boundPort}\n`);
      if (isNetwork) {
        process.stderr.write('Mode: NETWORK (identity-based auth only, bootstrap token disabled)\n');
      }
      process.stderr.write(`Vault path: ${vaultPath}\n`);
      if (idleTimeoutMinutes > 0) {
        process.stderr.write(`Auto-lock: ${idleTimeoutMinutes} minutes\n`);
      } else {
        process.stderr.write('Auto-lock: disabled\n');
      }
      process.stderr.write('Vault is locked. Unlock with: hq-vault unlock\n');
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── unlock ─────────────────────────────────────────────────────────
program
  .command('unlock')
  .description('Unlock the vault')
  .action(async () => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();
      const passphrase = await readPassphrase('Enter master passphrase: ');

      if (!passphrase || passphrase.length === 0) {
        process.stderr.write('Error: Passphrase cannot be empty\n');
        process.exit(1);
      }

      const res = await request(
        { port, host: '127.0.0.1', token },
        'POST',
        '/v1/unlock',
        { passphrase },
      );

      if (res.statusCode === 200) {
        process.stderr.write('Vault unlocked.\n');
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── lock ───────────────────────────────────────────────────────────
program
  .command('lock')
  .description('Lock the vault (wipe decryption key from memory)')
  .action(async () => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();

      const res = await request(
        { port, host: '127.0.0.1', token },
        'POST',
        '/v1/lock',
      );

      if (res.statusCode === 200) {
        process.stderr.write('Vault locked.\n');
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── status ─────────────────────────────────────────────────────────
program
  .command('status')
  .description('Show vault status')
  .option('--vault-path <path>', 'Path to vault database', getDefaultVaultPath())
  .action(async (opts) => {
    try {
      const pidFile = getDefaultPidFile();
      const { running } = isServerRunning(pidFile);

      if (running) {
        // Get status from the running server
        const port = getServerPort();
        const token = getServerToken();
        const res = await request(
          { port, host: '127.0.0.1', token },
          'GET',
          '/v1/status',
        );

        if (res.statusCode === 200) {
          const s = res.body;
          process.stdout.write(`Vault path:    ${s.vaultPath}\n`);
          process.stdout.write(`Status:        ${s.locked ? 'LOCKED' : 'UNLOCKED'}\n`);
          process.stdout.write(`Secrets:       ${s.secretCount}\n`);
          process.stdout.write(`Server:        running (port ${s.port})\n`);
          process.stdout.write(`Auto-lock:     ${(s.idleTimeoutMs as number) > 0 ? `${(s.idleTimeoutMs as number) / 60000} minutes` : 'disabled'}\n`);
        } else {
          process.stderr.write(`Error: ${res.body.error}\n`);
          process.exit(1);
        }
      } else {
        // Server not running — show offline status from the vault file
        const vaultPath = opts.vaultPath;
        if (fs.existsSync(vaultPath)) {
          process.stdout.write(`Vault path:    ${vaultPath}\n`);
          process.stdout.write(`Status:        LOCKED\n`);
          process.stdout.write(`Server:        stopped\n`);
          process.stdout.write('Start the server with: hq-vault serve\n');
        } else {
          process.stdout.write(`Vault path:    ${vaultPath}\n`);
          process.stdout.write(`Status:        not initialized\n`);
          process.stdout.write(`Server:        stopped\n`);
          process.stdout.write('Initialize a vault with: hq-vault init\n');
        }
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── store ─────────────────────────────────────────────────────────
program
  .command('store <path>')
  .description('Store a secret at the given path (use --org/--project for scoped secrets)')
  .option('--file <filepath>', 'Read secret value from a file instead of stdin')
  .option('--type <type>', 'Secret type (oauth-token, api-key, password, certificate, other)')
  .option('--description <desc>', 'Human-readable description of the secret')
  .option('--org <org>', 'Organization scope for the secret')
  .option('--project <project>', 'Project scope for the secret (requires --org)')
  .action(async (secretPath: string, opts) => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();
      let value: string;

      // Validate --project requires --org
      if (opts.project && !opts.org) {
        process.stderr.write('Error: --project requires --org to be specified\n');
        process.exit(1);
      }

      // Build the scoped path if --org is provided
      let finalPath = secretPath;
      if (opts.org) {
        if (opts.project) {
          finalPath = `org/${opts.org}/project/${opts.project}/${secretPath}`;
        } else {
          finalPath = `org/${opts.org}/${secretPath}`;
        }
      }

      if (opts.file) {
        // Read secret value from file
        if (!fs.existsSync(opts.file)) {
          process.stderr.write(`Error: File not found: ${opts.file}\n`);
          process.exit(1);
        }
        value = fs.readFileSync(opts.file, 'utf-8');
      } else {
        // Prompt for secret value via stdin (echo disabled)
        value = await readPassphrase('Enter secret value: ');
      }

      const body: Record<string, unknown> = { value };
      if (opts.type) body.type = opts.type;
      if (opts.description) body.description = opts.description;

      const res = await request(
        { port, host: '127.0.0.1', token },
        'PUT',
        `/v1/secrets/${encodeURIComponent(finalPath)}`,
        body,
      );

      if (res.statusCode === 200) {
        const typeStr = opts.type ? ` (${opts.type})` : '';
        process.stderr.write(`Stored: ${finalPath}${typeStr}, ${res.body.bytes} bytes\n`);
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── get ───────────────────────────────────────────────────────────
program
  .command('get <path>')
  .description('Get a decrypted secret (output to stdout)')
  .option('--env <varName>', 'Output as export VAR_NAME=value for shell eval')
  .action(async (secretPath: string, opts) => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();

      const res = await request(
        { port, host: '127.0.0.1', token },
        'GET',
        `/v1/secrets/${encodeURIComponent(secretPath)}`,
      );

      if (res.statusCode === 200) {
        const value = res.body.value as string;
        if (opts.env) {
          // Output as export statement for shell eval
          // Escape single quotes in value for safe shell interpolation
          const escaped = value.replace(/'/g, "'\\''");
          process.stdout.write(`export ${opts.env}='${escaped}'\n`);
        } else {
          // Raw output for piping
          process.stdout.write(value);
        }
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── list ──────────────────────────────────────────────────────────
program
  .command('list [prefix]')
  .description('List secret paths with metadata')
  .action(async (prefix: string | undefined) => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();

      const queryStr = prefix ? `?prefix=${encodeURIComponent(prefix)}` : '';
      const res = await request(
        { port, host: '127.0.0.1', token },
        'GET',
        `/v1/secrets${queryStr}`,
      );

      if (res.statusCode === 200) {
        const entries = res.body.entries as Array<{
          path: string;
          metadata: { type?: string; description?: string };
          createdAt: string;
          updatedAt: string;
        }>;

        if (entries.length === 0) {
          if (prefix) {
            process.stderr.write(`No secrets found matching prefix: ${prefix}\n`);
          } else {
            process.stderr.write('No secrets stored in the vault.\n');
          }
          return;
        }

        // Table output
        process.stdout.write(`${'PATH'.padEnd(40)} ${'TYPE'.padEnd(15)} ${'UPDATED'.padEnd(20)} DESCRIPTION\n`);
        process.stdout.write(`${'─'.repeat(40)} ${'─'.repeat(15)} ${'─'.repeat(20)} ${'─'.repeat(30)}\n`);

        for (const entry of entries) {
          const pathCol = entry.path.padEnd(40);
          const typeCol = (entry.metadata?.type || '-').padEnd(15);
          const updatedCol = entry.updatedAt.padEnd(20);
          const descCol = entry.metadata?.description || '';
          process.stdout.write(`${pathCol} ${typeCol} ${updatedCol} ${descCol}\n`);
        }

        process.stderr.write(`\n${entries.length} secret(s) found.\n`);
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── delete ────────────────────────────────────────────────────────
program
  .command('delete <path>')
  .description('Delete a secret')
  .option('--force', 'Skip confirmation prompt')
  .action(async (secretPath: string, opts) => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();

      if (!opts.force) {
        // Confirmation prompt
        const answer = await readPassphrase(`Delete secret '${secretPath}'? Type 'yes' to confirm: `);
        if (answer.toLowerCase() !== 'yes') {
          process.stderr.write('Aborted.\n');
          return;
        }
      }

      const res = await request(
        { port, host: '127.0.0.1', token },
        'DELETE',
        `/v1/secrets/${encodeURIComponent(secretPath)}`,
      );

      if (res.statusCode === 200) {
        process.stderr.write(`Deleted: ${secretPath}\n`);
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── token ──────────────────────────────────────────────────────────
const tokenCmd = program
  .command('token')
  .description('Manage access tokens');

// ─── token create ───────────────────────────────────────────────────
tokenCmd
  .command('create')
  .description('Create a new access token')
  .requiredOption('--name <name>', 'Human-readable name for the token')
  .option('--ttl <duration>', 'Time-to-live (e.g. 1h, 30m, 7d). Default: no expiry')
  .option('--max-uses <count>', 'Maximum number of uses. Default: unlimited')
  .action(async (opts) => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();

      const body: Record<string, unknown> = { name: opts.name };
      if (opts.ttl) body.ttl = opts.ttl;
      if (opts.maxUses) body.max_uses = parseInt(opts.maxUses, 10);

      const res = await request(
        { port, host: '127.0.0.1', token },
        'POST',
        '/v1/tokens',
        body,
      );

      if (res.statusCode === 201) {
        const meta = res.body.metadata as Record<string, unknown>;
        process.stderr.write(`Token created: ${opts.name}\n`);
        process.stderr.write('\n');
        // Display the token ONCE — it cannot be retrieved again
        process.stdout.write(`${res.body.token}\n`);
        process.stderr.write('\n');
        process.stderr.write('IMPORTANT: Save this token now. It cannot be retrieved again.\n');
        if (meta.expiresAt) {
          process.stderr.write(`Expires: ${meta.expiresAt}\n`);
        }
        if (meta.maxUses) {
          process.stderr.write(`Max uses: ${meta.maxUses}\n`);
        }
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── token list ─────────────────────────────────────────────────────
tokenCmd
  .command('list')
  .description('List all access tokens (metadata only, not token values)')
  .action(async () => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();

      const res = await request(
        { port, host: '127.0.0.1', token },
        'GET',
        '/v1/tokens',
      );

      if (res.statusCode === 200) {
        const tokens = res.body.tokens as Array<{
          name: string;
          createdAt: string;
          expiresAt: string | null;
          lastUsedAt: string | null;
          useCount: number;
          maxUses: number | null;
        }>;

        if (tokens.length === 0) {
          process.stderr.write('No access tokens found.\n');
          return;
        }

        // Table output
        process.stdout.write(
          `${'NAME'.padEnd(25)} ${'CREATED'.padEnd(20)} ${'EXPIRES'.padEnd(20)} ${'USES'.padEnd(10)} ${'LAST USED'.padEnd(20)}\n`
        );
        process.stdout.write(
          `${'─'.repeat(25)} ${'─'.repeat(20)} ${'─'.repeat(20)} ${'─'.repeat(10)} ${'─'.repeat(20)}\n`
        );

        for (const t of tokens) {
          const nameCol = t.name.padEnd(25);
          const createdCol = (t.createdAt || '-').substring(0, 19).padEnd(20);
          const expiresCol = (t.expiresAt ? t.expiresAt.substring(0, 19) : 'never').padEnd(20);
          const usesCol = (t.maxUses !== null ? `${t.useCount}/${t.maxUses}` : `${t.useCount}`).padEnd(10);
          const lastUsedCol = (t.lastUsedAt ? t.lastUsedAt.substring(0, 19) : 'never').padEnd(20);
          process.stdout.write(`${nameCol} ${createdCol} ${expiresCol} ${usesCol} ${lastUsedCol}\n`);
        }

        process.stderr.write(`\n${tokens.length} token(s) found.\n`);
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── token revoke ───────────────────────────────────────────────────
tokenCmd
  .command('revoke <name>')
  .description('Revoke (delete) an access token')
  .action(async (tokenName: string) => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();

      const res = await request(
        { port, host: '127.0.0.1', token },
        'DELETE',
        `/v1/tokens/${encodeURIComponent(tokenName)}`,
      );

      if (res.statusCode === 200) {
        process.stderr.write(`Token revoked: ${tokenName}\n`);
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── ingest ─────────────────────────────────────────────────────────
program
  .command('ingest <path>')
  .description('Securely ingest a secret — designed for AI agent workflows (output never contains the secret value)')
  .option('--type <type>', 'Secret type (oauth-token, api-key, password, certificate, other)')
  .option('--description <desc>', 'Human-readable description of the secret')
  .option('--overwrite', 'Allow overwriting an existing secret')
  .option('--web', 'Open a one-time web page for secret entry instead of stdin')
  .action(async (secretPath: string, opts) => {
    try {
      const pidFile = getDefaultPidFile();
      const { running } = isServerRunning(pidFile);
      if (!running) {
        process.stderr.write('Error: Vault server is not running. Start it with: hq-vault serve\n');
        process.exit(1);
      }
      const port = getServerPort();
      const token = getServerToken();

      // Check vault status — if locked, prompt for passphrase first
      const statusRes = await request(
        { port, host: '127.0.0.1', token },
        'GET',
        '/v1/status',
      );

      if (statusRes.statusCode !== 200) {
        process.stderr.write(`Error: ${statusRes.body.error}\n`);
        process.exit(1);
      }

      if (statusRes.body.locked) {
        const passphrase = await readPassphrase('Enter master passphrase: ');
        if (!passphrase || passphrase.length === 0) {
          process.stderr.write('Error: Passphrase cannot be empty\n');
          process.exit(1);
        }

        const unlockRes = await request(
          { port, host: '127.0.0.1', token },
          'POST',
          '/v1/unlock',
          { passphrase },
        );

        if (unlockRes.statusCode !== 200) {
          process.stderr.write(`Error: ${unlockRes.body.error}\n`);
          process.exit(1);
        }
        process.stderr.write('Vault unlocked.\n');
      }

      // Check if secret already exists (refuse overwrite without --overwrite)
      if (!opts.overwrite) {
        const existsRes = await request(
          { port, host: '127.0.0.1', token },
          'GET',
          `/v1/secrets/${encodeURIComponent(secretPath)}`,
        );

        if (existsRes.statusCode === 200) {
          process.stderr.write(`Error: secret already exists at ${secretPath}\n`);
          process.stderr.write('Use --overwrite to replace the existing secret.\n');
          process.exit(1);
        }
        // 404 means it doesn't exist — proceed
        // Any other error is unexpected
        if (existsRes.statusCode !== 404) {
          process.stderr.write(`Error: ${existsRes.body.error}\n`);
          process.exit(1);
        }
      }

      // ── Web entry mode (--web) ────────────────────────────────────
      if (opts.web) {
        const result = await startWebEntry({
          secretPath,
          type: opts.type,
          description: opts.description,
          vaultClient: { port, host: '127.0.0.1', token },
        });

        if (result.success) {
          const typeStr = opts.type ? `, ${opts.type}` : '';
          process.stdout.write(`Stored: ${secretPath} (via web entry, ${result.bytes} bytes${typeStr})\n`);
        } else {
          process.stderr.write(`Error: ${result.error}\n`);
          process.exit(1);
        }
        return;
      }

      // ── Stdin entry mode (default) ────────────────────────────────
      // Prompt for secret value via stdin (echo disabled)
      const value = await readPassphrase('Enter secret value: ');
      if (!value || value.length === 0) {
        process.stderr.write('Error: Secret value cannot be empty\n');
        process.exit(1);
      }

      // Store via the server API
      const body: Record<string, unknown> = { value };
      if (opts.type) body.type = opts.type;
      if (opts.description) body.description = opts.description;

      const storeRes = await request(
        { port, host: '127.0.0.1', token },
        'PUT',
        `/v1/secrets/${encodeURIComponent(secretPath)}`,
        body,
      );

      if (storeRes.statusCode === 200) {
        // Agent-safe output: NEVER include the secret value
        const typeStr = opts.type ? `, ${opts.type}` : '';
        const bytes = storeRes.body.bytes as number;
        process.stdout.write(`Stored: ${secretPath} (${bytes} bytes${typeStr})\n`);
      } else {
        process.stderr.write(`Error: ${storeRes.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── env ───────────────────────────────────────────────────────────
program
  .command('env <path> <varName>')
  .description('Output a secret as an export statement for shell eval (e.g. eval $(hq-vault env aws/key AWS_KEY))')
  .action(async (secretPath: string, varName: string) => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();

      const res = await request(
        { port, host: '127.0.0.1', token },
        'GET',
        `/v1/secrets/${encodeURIComponent(secretPath)}`,
      );

      if (res.statusCode === 200) {
        const value = res.body.value as string;
        // Escape single quotes in value for safe shell interpolation
        const escaped = value.replace(/'/g, "'\\''");
        process.stdout.write(`export ${varName}='${escaped}'\n`);
      } else {
        process.stderr.write(`Error: ${res.body.error}\n`);
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── env-file ──────────────────────────────────────────────────────
program
  .command('env-file <prefix>')
  .description('Output all secrets under a prefix as dotenv-format export statements')
  .option('--format <format>', 'Output format: dotenv (default) or export', 'dotenv')
  .action(async (prefix: string, opts) => {
    try {
      const port = ensureServerRunning();
      const token = getServerToken();

      const queryStr = `?prefix=${encodeURIComponent(prefix)}`;
      const listRes = await request(
        { port, host: '127.0.0.1', token },
        'GET',
        `/v1/secrets${queryStr}`,
      );

      if (listRes.statusCode !== 200) {
        process.stderr.write(`Error: ${listRes.body.error}\n`);
        process.exit(1);
      }

      const entries = listRes.body.entries as Array<{
        path: string;
        metadata: { type?: string; description?: string };
      }>;

      if (entries.length === 0) {
        process.stderr.write(`No secrets found matching prefix: ${prefix}\n`);
        return;
      }

      // Fetch each secret value
      for (const entry of entries) {
        const getRes = await request(
          { port, host: '127.0.0.1', token },
          'GET',
          `/v1/secrets/${encodeURIComponent(entry.path)}`,
        );

        if (getRes.statusCode !== 200) {
          process.stderr.write(`Warning: Could not read ${entry.path}: ${getRes.body.error}\n`);
          continue;
        }

        const value = getRes.body.value as string;

        // Derive the env var name from the path:
        // Remove the prefix, replace remaining slashes and dashes with underscores, uppercase
        let relativePath = entry.path;
        if (relativePath.startsWith(prefix)) {
          relativePath = relativePath.slice(prefix.length);
        }
        // Remove leading slash if any
        if (relativePath.startsWith('/')) {
          relativePath = relativePath.slice(1);
        }
        const varName = relativePath
          .replace(/[/\-\.]/g, '_')
          .toUpperCase();

        if (!varName) {
          process.stderr.write(`Warning: Could not derive env var name for ${entry.path}\n`);
          continue;
        }

        if (opts.format === 'export') {
          // Shell export format
          const escaped = value.replace(/'/g, "'\\''");
          process.stdout.write(`export ${varName}='${escaped}'\n`);
        } else {
          // dotenv format (default)
          // Escape double quotes and newlines for .env format
          const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
          process.stdout.write(`${varName}="${escaped}"\n`);
        }
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── audit ─────────────────────────────────────────────────────────
program
  .command('audit')
  .description('Show recent audit log entries')
  .option('--path <path>', 'Filter by secret path (substring match)')
  .option('--token <name>', 'Filter by token name')
  .option('--since <datetime>', 'Show entries since this date/time (ISO 8601)')
  .option('--limit <count>', 'Maximum number of entries to show', '50')
  .option('--tail', 'Follow the audit log in real-time')
  .option('--json', 'Output as JSON lines instead of formatted table')
  .action(async (opts) => {
    try {
      const logPath = getDefaultAuditLogPath();

      if (opts.tail) {
        // ── Tail mode ──────────────────────────────────────────
        process.stderr.write(`Tailing audit log: ${logPath}\n`);
        process.stderr.write('Press Ctrl+C to stop.\n\n');

        const stop = tailAuditLog(logPath, (entry: AuditEntry) => {
          if (opts.json) {
            process.stdout.write(JSON.stringify(entry) + '\n');
          } else {
            process.stdout.write(formatAuditEntry(entry) + '\n');
          }
        });

        // Keep the process alive until Ctrl+C
        process.on('SIGINT', () => {
          stop();
          process.exit(0);
        });
        process.on('SIGTERM', () => {
          stop();
          process.exit(0);
        });

        // Prevent the process from exiting
        await new Promise(() => {
          // Never resolves — waits for signal
        });
      }

      // ── Read mode (default) ───────────────────────────────────
      const entries = readAuditLog(logPath, {
        path: opts.path,
        token: opts.token,
        since: opts.since,
        limit: parseInt(opts.limit, 10),
      });

      if (entries.length === 0) {
        process.stderr.write('No audit log entries found.\n');
        if (!fs.existsSync(logPath)) {
          process.stderr.write(`Audit log does not exist yet: ${logPath}\n`);
        }
        return;
      }

      if (opts.json) {
        for (const entry of entries) {
          process.stdout.write(JSON.stringify(entry) + '\n');
        }
      } else {
        // Formatted table output
        process.stdout.write(
          `${'TIMESTAMP'.padEnd(24)} ${'OPERATION'.padEnd(16)} ${'TOKEN'.padEnd(20)} ${'PATH'.padEnd(30)} ${'IP'.padEnd(16)} DETAIL\n`,
        );
        process.stdout.write(
          `${'─'.repeat(24)} ${'─'.repeat(16)} ${'─'.repeat(20)} ${'─'.repeat(30)} ${'─'.repeat(16)} ${'─'.repeat(20)}\n`,
        );
        for (const entry of entries) {
          process.stdout.write(formatAuditEntry(entry) + '\n');
        }
      }

      process.stderr.write(`\n${entries.length} audit entries shown.\n`);
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

/**
 * Format a single audit entry as a table row.
 */
function formatAuditEntry(entry: AuditEntry): string {
  const ts = entry.timestamp.substring(0, 23).padEnd(24);
  const op = entry.operation.padEnd(16);
  const token = (entry.tokenName || '-').padEnd(20);
  const secretPath = (entry.secretPath || '-').padEnd(30);
  const ip = entry.ip.padEnd(16);
  const detail = entry.detail || '';
  return `${ts} ${op} ${token} ${secretPath} ${ip} ${detail}`;
}

// ─── backup ─────────────────────────────────────────────────────────
program
  .command('backup <filepath>')
  .description('Create an encrypted backup of the vault database')
  .option('--vault-path <path>', 'Path to vault database', getDefaultVaultPath())
  .action(async (filepath: string, opts) => {
    try {
      const vaultPath = opts.vaultPath;

      if (!fs.existsSync(vaultPath)) {
        process.stderr.write(`Error: No vault found at ${vaultPath}\n`);
        process.stderr.write('Initialize one with: hq-vault init\n');
        process.exit(1);
      }

      // Prompt for passphrase (needed to encrypt the backup)
      const passphrase = await readPassphrase('Enter master passphrase: ');
      if (!passphrase || passphrase.length === 0) {
        process.stderr.write('Error: Passphrase cannot be empty\n');
        process.exit(1);
      }

      // Verify the passphrase against the vault before creating the backup
      const { VaultEngine } = await import('./vault.js');
      const vault = new VaultEngine(vaultPath);
      try {
        vault.unlock(passphrase);
      } catch {
        vault.close();
        process.stderr.write('Error: Invalid passphrase\n');
        process.exit(1);
      }
      vault.close();

      const result = createBackup(vaultPath, filepath, passphrase);
      process.stderr.write(`Backup created: ${result.filepath}\n`);
      process.stderr.write(`Size: ${result.sizeBytes} bytes\n`);
      process.stderr.write('The backup is fully encrypted and safe to store in cloud storage or git.\n');
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── restore ────────────────────────────────────────────────────────
program
  .command('restore <filepath>')
  .description('Restore the vault from an encrypted backup')
  .option('--vault-path <path>', 'Path to restore the vault database', getDefaultVaultPath())
  .option('--force', 'Overwrite existing vault without confirmation')
  .action(async (filepath: string, opts) => {
    try {
      const restorePath = opts.vaultPath;

      if (!fs.existsSync(filepath)) {
        process.stderr.write(`Error: Backup file not found: ${filepath}\n`);
        process.exit(1);
      }

      // Check if a vault already exists at the restore path
      if (fs.existsSync(restorePath) && !opts.force) {
        const answer = await readPassphrase(
          `A vault already exists at ${restorePath}. Overwrite? Type 'yes' to confirm: `
        );
        if (answer.toLowerCase() !== 'yes') {
          process.stderr.write('Aborted.\n');
          return;
        }
      }

      // Prompt for passphrase (needed to decrypt the backup)
      const passphrase = await readPassphrase('Enter master passphrase: ');
      if (!passphrase || passphrase.length === 0) {
        process.stderr.write('Error: Passphrase cannot be empty\n');
        process.exit(1);
      }

      const result = restoreBackup(filepath, restorePath, passphrase);
      process.stderr.write(`Vault restored to: ${result.restoredPath}\n`);
      process.stderr.write(`Secrets: ${result.secretCount}\n`);
      process.stderr.write('Start the vault server with: hq-vault serve\n');
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── export ─────────────────────────────────────────────────────────
program
  .command('export')
  .description('Export secrets as .env format (requires unlock)')
  .option('--format <format>', 'Output format: env (default)', 'env')
  .option('--prefix <prefix>', 'Only export secrets matching this prefix')
  .option('--vault-path <path>', 'Path to vault database', getDefaultVaultPath())
  .option('--output <filepath>', 'Write output to a file instead of stdout')
  .action(async (opts) => {
    try {
      // Check if server is running — prefer using server
      const pidFile = getDefaultPidFile();
      const { running } = isServerRunning(pidFile);

      if (running) {
        // Use the running server
        const port = getServerPort();
        const token = getServerToken();

        // Check vault is unlocked
        const statusRes = await request(
          { port, host: '127.0.0.1', token },
          'GET',
          '/v1/status',
        );
        if (statusRes.statusCode !== 200 || statusRes.body.locked) {
          process.stderr.write('Error: Vault is locked. Unlock it first with: hq-vault unlock\n');
          process.exit(1);
        }

        // List secrets
        const queryStr = opts.prefix ? `?prefix=${encodeURIComponent(opts.prefix)}` : '';
        const listRes = await request(
          { port, host: '127.0.0.1', token },
          'GET',
          `/v1/secrets${queryStr}`,
        );

        if (listRes.statusCode !== 200) {
          process.stderr.write(`Error: ${listRes.body.error}\n`);
          process.exit(1);
        }

        const entries = listRes.body.entries as Array<{
          path: string;
          metadata: { type?: string; description?: string };
        }>;

        if (entries.length === 0) {
          process.stderr.write('No secrets to export.\n');
          return;
        }

        // Fetch each secret and build .env output
        const lines: string[] = [];
        for (const entry of entries) {
          const getRes = await request(
            { port, host: '127.0.0.1', token },
            'GET',
            `/v1/secrets/${encodeURIComponent(entry.path)}`,
          );

          if (getRes.statusCode !== 200) {
            process.stderr.write(`Warning: Could not read ${entry.path}: ${getRes.body.error}\n`);
            continue;
          }

          const value = getRes.body.value as string;
          let relativePath = entry.path;
          if (opts.prefix && relativePath.startsWith(opts.prefix)) {
            relativePath = relativePath.slice(opts.prefix.length);
          }
          if (relativePath.startsWith('/')) {
            relativePath = relativePath.slice(1);
          }
          const varName = relativePath.replace(/[/\-\.]/g, '_').toUpperCase();
          if (!varName) continue;

          const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
          if (entry.metadata?.description) {
            lines.push(`# ${entry.metadata.description}`);
          }
          lines.push(`${varName}="${escaped}"`);
        }

        const output = lines.join('\n') + (lines.length > 0 ? '\n' : '');

        if (opts.output) {
          fs.writeFileSync(opts.output, output, 'utf-8');
          process.stderr.write(`Exported ${entries.length} secret(s) to ${opts.output}\n`);
        } else {
          process.stdout.write(output);
          process.stderr.write(`\nExported ${entries.length} secret(s).\n`);
        }
      } else {
        // No server running — open the vault directly
        const vaultPath = opts.vaultPath;
        if (!fs.existsSync(vaultPath)) {
          process.stderr.write(`Error: No vault found at ${vaultPath}\n`);
          process.exit(1);
        }

        const passphrase = await readPassphrase('Enter master passphrase: ');
        if (!passphrase || passphrase.length === 0) {
          process.stderr.write('Error: Passphrase cannot be empty\n');
          process.exit(1);
        }

        const { VaultEngine } = await import('./vault.js');
        const vault = new VaultEngine(vaultPath);
        try {
          vault.unlock(passphrase);
          const result = exportEnv(vault, opts.prefix);

          if (result.entryCount === 0) {
            process.stderr.write('No secrets to export.\n');
            return;
          }

          if (opts.output) {
            fs.writeFileSync(opts.output, result.output, 'utf-8');
            process.stderr.write(`Exported ${result.entryCount} secret(s) to ${opts.output}\n`);
          } else {
            process.stdout.write(result.output);
            process.stderr.write(`\nExported ${result.entryCount} secret(s).\n`);
          }
        } finally {
          vault.close();
        }
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── import ─────────────────────────────────────────────────────────
program
  .command('import <filepath>')
  .description('Import secrets from a .env file')
  .option('--format <format>', 'Input format: env (default)', 'env')
  .option('--prefix <prefix>', 'Prefix to prepend to imported secret paths')
  .option('--vault-path <path>', 'Path to vault database', getDefaultVaultPath())
  .option('--on-conflict <strategy>', 'Conflict strategy: skip, overwrite, or rename', 'skip')
  .action(async (filepath: string, opts) => {
    try {
      if (!fs.existsSync(filepath)) {
        process.stderr.write(`Error: File not found: ${filepath}\n`);
        process.exit(1);
      }

      const envContent = fs.readFileSync(filepath, 'utf-8');
      const parsedEntries = parseEnvFile(envContent);

      if (parsedEntries.length === 0) {
        process.stderr.write('No entries found in the .env file.\n');
        return;
      }

      process.stderr.write(`Found ${parsedEntries.length} entries in ${filepath}\n`);

      const strategy = opts.onConflict as 'skip' | 'overwrite' | 'rename';
      if (!['skip', 'overwrite', 'rename'].includes(strategy)) {
        process.stderr.write(`Error: Invalid conflict strategy: ${strategy}. Use skip, overwrite, or rename.\n`);
        process.exit(1);
      }

      // Check if server is running
      const pidFile = getDefaultPidFile();
      const { running } = isServerRunning(pidFile);

      if (running) {
        // Use the running server
        const port = getServerPort();
        const token = getServerToken();

        // Check vault is unlocked
        const statusRes = await request(
          { port, host: '127.0.0.1', token },
          'GET',
          '/v1/status',
        );
        if (statusRes.statusCode !== 200 || statusRes.body.locked) {
          process.stderr.write('Error: Vault is locked. Unlock it first with: hq-vault unlock\n');
          process.exit(1);
        }

        // Import each entry via the API
        let imported = 0;
        let skipped = 0;
        let overwritten = 0;
        let renamed = 0;
        const errors: string[] = [];

        for (const entry of parsedEntries) {
          const secretPath = envNameToPath(entry.key, opts.prefix);

          // Check if path already exists
          const existsRes = await request(
            { port, host: '127.0.0.1', token },
            'GET',
            `/v1/secrets/${encodeURIComponent(secretPath)}`,
          );

          const exists = existsRes.statusCode === 200;

          if (exists) {
            if (strategy === 'skip') {
              process.stderr.write(`  Skip: ${secretPath} (already exists)\n`);
              skipped++;
              continue;
            } else if (strategy === 'rename') {
              let counter = 1;
              let renamedPath = `${secretPath}-imported-${counter}`;
              // Check if renamed path exists too
              let renameExists = true;
              while (renameExists) {
                const checkRes = await request(
                  { port, host: '127.0.0.1', token },
                  'GET',
                  `/v1/secrets/${encodeURIComponent(renamedPath)}`,
                );
                renameExists = checkRes.statusCode === 200;
                if (renameExists) {
                  counter++;
                  renamedPath = `${secretPath}-imported-${counter}`;
                }
              }
              const storeRes = await request(
                { port, host: '127.0.0.1', token },
                'PUT',
                `/v1/secrets/${encodeURIComponent(renamedPath)}`,
                { value: entry.value, type: 'api-key', description: `Imported from .env (renamed from ${secretPath})` },
              );
              if (storeRes.statusCode === 200) {
                process.stderr.write(`  Rename: ${secretPath} -> ${renamedPath}\n`);
                renamed++;
              } else {
                errors.push(`${entry.key}: ${storeRes.body.error}`);
              }
              continue;
            }
            // strategy === 'overwrite' — fall through to store
          }

          const storeRes = await request(
            { port, host: '127.0.0.1', token },
            'PUT',
            `/v1/secrets/${encodeURIComponent(secretPath)}`,
            { value: entry.value, type: 'api-key', description: 'Imported from .env' },
          );

          if (storeRes.statusCode === 200) {
            if (exists) {
              process.stderr.write(`  Overwrite: ${secretPath}\n`);
              overwritten++;
            } else {
              process.stderr.write(`  Import: ${secretPath}\n`);
              imported++;
            }
          } else {
            errors.push(`${entry.key}: ${storeRes.body.error}`);
          }
        }

        process.stderr.write(`\nImport complete: ${imported} imported, ${skipped} skipped, ${overwritten} overwritten, ${renamed} renamed\n`);
        if (errors.length > 0) {
          process.stderr.write(`Errors:\n`);
          for (const e of errors) {
            process.stderr.write(`  ${e}\n`);
          }
          process.exit(1);
        }
      } else {
        // No server running — open the vault directly
        const vaultPath = opts.vaultPath;
        if (!fs.existsSync(vaultPath)) {
          process.stderr.write(`Error: No vault found at ${vaultPath}\n`);
          process.exit(1);
        }

        const passphrase = await readPassphrase('Enter master passphrase: ');
        if (!passphrase || passphrase.length === 0) {
          process.stderr.write('Error: Passphrase cannot be empty\n');
          process.exit(1);
        }

        const { VaultEngine } = await import('./vault.js');
        const vault = new VaultEngine(vaultPath);
        try {
          vault.unlock(passphrase);

          // Detect duplicates and warn
          const duplicates = detectImportDuplicates(vault, envContent, opts.prefix);
          if (duplicates.length > 0) {
            process.stderr.write(`\nWarning: ${duplicates.length} duplicate path(s) detected:\n`);
            for (const d of duplicates) {
              process.stderr.write(`  ${d}\n`);
            }
            process.stderr.write(`Conflict strategy: ${strategy}\n\n`);
          }

          const result = importEnv(vault, envContent, strategy, opts.prefix);

          process.stderr.write(`Import complete: ${result.imported} imported, ${result.skipped} skipped, ${result.overwritten} overwritten, ${result.renamed} renamed\n`);
          if (result.errors.length > 0) {
            process.stderr.write(`Errors:\n`);
            for (const e of result.errors) {
              process.stderr.write(`  ${e}\n`);
            }
            process.exit(1);
          }
        } finally {
          vault.close();
        }
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── identity ───────────────────────────────────────────────────────
const identityCmd = program
  .command('identity')
  .description('Manage vault identities');

identityCmd
  .command('create')
  .description('Create a new identity with an Ed25519 keypair')
  .requiredOption('--name <name>', 'Identity name')
  .requiredOption('--type <type>', 'Identity type: human or agent')
  .option('--identity-db <path>', 'Path to identity database')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const result = idb.createIdentity(opts.name, opts.type);

        process.stdout.write(`Identity created:\n`);
        process.stdout.write(`  ID:   ${result.identity.id}\n`);
        process.stdout.write(`  Name: ${result.identity.name}\n`);
        process.stdout.write(`  Type: ${result.identity.type}\n`);
        process.stdout.write(`\n`);
        process.stdout.write(`Private key (save this — it will NOT be shown again):\n`);
        process.stdout.write(`  ${result.privateKey}\n`);
        process.stdout.write(`\n`);
        process.stdout.write(`Public key:\n`);
        process.stdout.write(`  ${result.publicKey}\n`);
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

identityCmd
  .command('list')
  .description('List all identities')
  .option('--identity-db <path>', 'Path to identity database')
  .option('--json', 'Output as JSON')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const identities = idb.listIdentities();

        if (identities.length === 0) {
          process.stderr.write('No identities found.\n');
          return;
        }

        if (opts.json) {
          process.stdout.write(JSON.stringify(identities, null, 2) + '\n');
        } else {
          process.stdout.write(
            `${'ID'.padEnd(34)} ${'NAME'.padEnd(20)} ${'TYPE'.padEnd(8)} CREATED\n`,
          );
          process.stdout.write(
            `${'─'.repeat(34)} ${'─'.repeat(20)} ${'─'.repeat(8)} ${'─'.repeat(20)}\n`,
          );
          for (const id of identities) {
            process.stdout.write(
              `${id.id.padEnd(34)} ${id.name.padEnd(20)} ${id.type.padEnd(8)} ${id.created_at}\n`,
            );
          }
          process.stderr.write(`\n${identities.length} identity(ies).\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

identityCmd
  .command('verify')
  .description('Verify an identity using its private key')
  .requiredOption('--key <privateKey>', 'Base64-encoded Ed25519 private key')
  .option('--identity-db <path>', 'Path to identity database')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const identity = idb.verifyIdentity(opts.key);
        if (identity) {
          process.stdout.write(`Identity verified:\n`);
          process.stdout.write(`  ID:   ${identity.id}\n`);
          process.stdout.write(`  Name: ${identity.name}\n`);
          process.stdout.write(`  Type: ${identity.type}\n`);
        } else {
          process.stderr.write('Error: Private key does not match any known identity.\n');
          process.exit(1);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── org ─────────────────────────────────────────────────────────────
const orgCmd = program
  .command('org')
  .description('Manage organizations');

orgCmd
  .command('create')
  .description('Create a new organization')
  .requiredOption('--name <name>', 'Organization name')
  .option('--identity <id>', 'Founding identity ID (assigned as admin)')
  .option('--identity-db <path>', 'Path to identity database')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const org = idb.createOrg(opts.name, opts.identity);

        process.stdout.write(`Organization created:\n`);
        process.stdout.write(`  ID:   ${org.id}\n`);
        process.stdout.write(`  Name: ${org.name}\n`);
        if (opts.identity) {
          process.stdout.write(`  Founder: ${opts.identity} (admin)\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

orgCmd
  .command('list')
  .description('List all organizations')
  .option('--identity-db <path>', 'Path to identity database')
  .option('--json', 'Output as JSON')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const orgs = idb.listOrgs();

        if (orgs.length === 0) {
          process.stderr.write('No organizations found.\n');
          return;
        }

        if (opts.json) {
          process.stdout.write(JSON.stringify(orgs, null, 2) + '\n');
        } else {
          process.stdout.write(
            `${'ID'.padEnd(34)} ${'NAME'.padEnd(24)} CREATED\n`,
          );
          process.stdout.write(
            `${'─'.repeat(34)} ${'─'.repeat(24)} ${'─'.repeat(20)}\n`,
          );
          for (const org of orgs) {
            process.stdout.write(
              `${org.id.padEnd(34)} ${org.name.padEnd(24)} ${org.created_at}\n`,
            );
          }
          process.stderr.write(`\n${orgs.length} organization(s).\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

orgCmd
  .command('add-member')
  .description('Add a member to an organization')
  .requiredOption('--org <orgId>', 'Organization ID')
  .requiredOption('--identity <identityId>', 'Identity ID to add')
  .requiredOption('--role <role>', 'Role: admin, member, or readonly')
  .option('--identity-db <path>', 'Path to identity database')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        idb.addOrgMember(opts.org, opts.identity, opts.role);
        process.stdout.write(`Added identity ${opts.identity} to org ${opts.org} as ${opts.role}.\n`);
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

orgCmd
  .command('members')
  .description('List members of an organization')
  .requiredOption('--org <orgId>', 'Organization ID')
  .option('--identity-db <path>', 'Path to identity database')
  .option('--json', 'Output as JSON')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const members = idb.listOrgMembers(opts.org);

        if (members.length === 0) {
          process.stderr.write('No members found.\n');
          return;
        }

        if (opts.json) {
          process.stdout.write(JSON.stringify(members, null, 2) + '\n');
        } else {
          process.stdout.write(
            `${'IDENTITY ID'.padEnd(34)} ${'NAME'.padEnd(20)} ${'TYPE'.padEnd(8)} ROLE\n`,
          );
          process.stdout.write(
            `${'─'.repeat(34)} ${'─'.repeat(20)} ${'─'.repeat(8)} ${'─'.repeat(10)}\n`,
          );
          for (const m of members) {
            process.stdout.write(
              `${m.identity_id.padEnd(34)} ${m.name.padEnd(20)} ${m.type.padEnd(8)} ${m.role}\n`,
            );
          }
          process.stderr.write(`\n${members.length} member(s).\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── project ─────────────────────────────────────────────────────────
const projectCmd = program
  .command('project')
  .description('Manage projects within organizations');

projectCmd
  .command('create')
  .description('Create a new project within an organization')
  .requiredOption('--org <orgId>', 'Organization ID')
  .requiredOption('--name <name>', 'Project name')
  .option('--identity <id>', 'Founding identity ID (assigned as admin)')
  .option('--identity-db <path>', 'Path to identity database')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const project = idb.createProject(opts.org, opts.name, opts.identity);

        process.stdout.write(`Project created:\n`);
        process.stdout.write(`  ID:   ${project.id}\n`);
        process.stdout.write(`  Name: ${project.name}\n`);
        process.stdout.write(`  Org:  ${project.org_id}\n`);
        if (opts.identity) {
          process.stdout.write(`  Founder: ${opts.identity} (admin)\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

projectCmd
  .command('list')
  .description('List projects in an organization')
  .requiredOption('--org <orgId>', 'Organization ID')
  .option('--identity-db <path>', 'Path to identity database')
  .option('--json', 'Output as JSON')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const projects = idb.listProjects(opts.org);

        if (projects.length === 0) {
          process.stderr.write('No projects found.\n');
          return;
        }

        if (opts.json) {
          process.stdout.write(JSON.stringify(projects, null, 2) + '\n');
        } else {
          process.stdout.write(
            `${'ID'.padEnd(34)} ${'NAME'.padEnd(24)} CREATED\n`,
          );
          process.stdout.write(
            `${'─'.repeat(34)} ${'─'.repeat(24)} ${'─'.repeat(20)}\n`,
          );
          for (const p of projects) {
            process.stdout.write(
              `${p.id.padEnd(34)} ${p.name.padEnd(24)} ${p.created_at}\n`,
            );
          }
          process.stderr.write(`\n${projects.length} project(s).\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

projectCmd
  .command('add-member')
  .description('Add a member to a project')
  .requiredOption('--project <projectId>', 'Project ID')
  .requiredOption('--identity <identityId>', 'Identity ID to add')
  .requiredOption('--role <role>', 'Role: admin, member, or readonly')
  .option('--identity-db <path>', 'Path to identity database')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        idb.addProjectMember(opts.project, opts.identity, opts.role);
        process.stdout.write(`Added identity ${opts.identity} to project ${opts.project} as ${opts.role}.\n`);
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

projectCmd
  .command('members')
  .description('List members of a project')
  .requiredOption('--project <projectId>', 'Project ID')
  .option('--identity-db <path>', 'Path to identity database')
  .option('--json', 'Output as JSON')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const members = idb.listProjectMembers(opts.project);

        if (members.length === 0) {
          process.stderr.write('No members found.\n');
          return;
        }

        if (opts.json) {
          process.stdout.write(JSON.stringify(members, null, 2) + '\n');
        } else {
          process.stdout.write(
            `${'IDENTITY ID'.padEnd(34)} ${'NAME'.padEnd(20)} ${'TYPE'.padEnd(8)} ROLE\n`,
          );
          process.stdout.write(
            `${'─'.repeat(34)} ${'─'.repeat(20)} ${'─'.repeat(8)} ${'─'.repeat(10)}\n`,
          );
          for (const m of members) {
            process.stdout.write(
              `${m.identity_id.padEnd(34)} ${m.name.padEnd(20)} ${m.type.padEnd(8)} ${m.role}\n`,
            );
          }
          process.stderr.write(`\n${members.length} member(s).\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── auth ───────────────────────────────────────────────────────────
const authCmd = program
  .command('auth')
  .description('Network authentication (challenge-response)');

authCmd
  .command('login')
  .description('Authenticate using Ed25519 keypair (challenge-response flow)')
  .requiredOption('--identity <name>', 'Identity name')
  .requiredOption('--key <path>', 'Path to Ed25519 private key file (base64)')
  .option('--identity-db <path>', 'Path to identity database')
  .option('--json', 'Output as JSON')
  .action(async (opts) => {
    try {
      const port = ensureServerRunning();

      // Read the private key from file
      if (!fs.existsSync(opts.key)) {
        process.stderr.write(`Error: Key file not found: ${opts.key}\n`);
        process.exit(1);
      }
      const privateKeyBase64 = fs.readFileSync(opts.key, 'utf-8').trim();

      // We need to extract the public key from the private key and the identity ID
      // Look up the identity by name in the identity database
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      let identityId: string;
      let publicKeyBase64: string;
      try {
        const identity = idb.getIdentityByName(opts.identity);
        if (!identity) {
          process.stderr.write(`Error: Identity '${opts.identity}' not found\n`);
          process.exit(1);
        }
        identityId = identity.id;

        // Extract public key from private key using sodium
        const sodium = (await import('sodium-native')).default;
        const secretKey = Buffer.from(privateKeyBase64, 'base64');
        if (secretKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
          process.stderr.write(`Error: Invalid private key length\n`);
          process.exit(1);
        }
        const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
        sodium.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);
        publicKeyBase64 = publicKey.toString('base64');

        // Step 1: Request a challenge
        const challengeRes = await request(
          { port, host: '127.0.0.1', token: undefined, insecure: true },
          'POST',
          '/v1/auth/challenge',
          { identity_id: identityId },
        );

        if (challengeRes.statusCode !== 200) {
          process.stderr.write(`Error: Failed to get challenge: ${(challengeRes.body as Record<string, unknown>).error || 'unknown error'}\n`);
          process.exit(1);
        }

        const challengeNonce = Buffer.from(challengeRes.body.challenge as string, 'base64url');
        const challengeId = challengeRes.body.challenge_id as string;

        // Step 2: Sign the challenge nonce
        const { ed25519Sign } = await import('./network-auth.js');
        const signature = ed25519Sign(challengeNonce, secretKey);
        const signatureBase64url = signature.toString('base64url');

        // Zero out the secret key
        sodium.sodium_memzero(secretKey);

        // Step 3: Verify the signature and get a session token
        const verifyRes = await request(
          { port, host: '127.0.0.1', token: undefined, insecure: true },
          'POST',
          '/v1/auth/verify',
          {
            challenge_id: challengeId,
            identity_id: identityId,
            signature: signatureBase64url,
            public_key: publicKeyBase64,
          },
        );

        if (verifyRes.statusCode !== 200) {
          process.stderr.write(`Error: Authentication failed: ${(verifyRes.body as Record<string, unknown>).error || 'unknown error'}\n`);
          process.exit(1);
        }

        const sessionToken = verifyRes.body.session_token as string;
        const expiresIn = verifyRes.body.expires_in as number;

        // Cache the session token to the token file location
        const { getVaultDir } = await import('./server.js');
        const path = await import('node:path');
        const sessionTokenFile = path.join(getVaultDir(), 'session-token');
        fs.writeFileSync(sessionTokenFile, sessionToken, { encoding: 'utf-8', mode: 0o600 });

        if (opts.json) {
          process.stdout.write(JSON.stringify({
            ok: true,
            identity_id: identityId,
            identity_name: opts.identity,
            session_token_file: sessionTokenFile,
            expires_in: expiresIn,
          }, null, 2) + '\n');
        } else {
          process.stdout.write(`Authenticated as '${opts.identity}' (${identityId})\n`);
          process.stdout.write(`Session token cached at: ${sessionTokenFile}\n`);
          process.stdout.write(`Expires in: ${expiresIn} seconds\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

// ─── access-requests ────────────────────────────────────────────────
const accessRequestsCmd = program
  .command('access-requests')
  .description('Manage access requests (agent access request + human approval flow)');

accessRequestsCmd
  .command('list')
  .description('List access requests')
  .option('--org <org>', 'Filter by organization name')
  .option('--status <status>', 'Filter by status: pending, approved, denied')
  .option('--identity-db <path>', 'Path to identity database')
  .option('--json', 'Output as JSON')
  .action(async (opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const { AccessRequestManager } = await import('./access-requests.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const arm = new AccessRequestManager(idb);

        // Clean expired requests first
        arm.cleanExpired();

        const filters: Record<string, string> = {};
        if (opts.org) filters.org = opts.org;
        if (opts.status) filters.status = opts.status;

        const requests = arm.listRequests(filters);

        if (requests.length === 0) {
          process.stderr.write('No access requests found.\n');
          return;
        }

        if (opts.json) {
          process.stdout.write(JSON.stringify(requests, null, 2) + '\n');
        } else {
          process.stdout.write(
            `${'REQUEST ID'.padEnd(34)} ${'ORG'.padEnd(16)} ${'PROJECT'.padEnd(16)} ${'ROLE'.padEnd(10)} ${'STATUS'.padEnd(10)} JUSTIFICATION\n`,
          );
          process.stdout.write(
            `${'─'.repeat(34)} ${'─'.repeat(16)} ${'─'.repeat(16)} ${'─'.repeat(10)} ${'─'.repeat(10)} ${'─'.repeat(30)}\n`,
          );
          for (const r of requests) {
            const proj = r.project || '-';
            const justTrunc = r.justification.length > 30 ? r.justification.slice(0, 27) + '...' : r.justification;
            process.stdout.write(
              `${r.request_id.padEnd(34)} ${r.org.padEnd(16)} ${proj.padEnd(16)} ${r.role_requested.padEnd(10)} ${r.status.padEnd(10)} ${justTrunc}\n`,
            );
          }
          process.stderr.write(`\n${requests.length} access request(s).\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

accessRequestsCmd
  .command('approve <requestId>')
  .description('Approve an access request (creates membership automatically)')
  .option('--identity-db <path>', 'Path to identity database')
  .action(async (requestId: string, opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const { AccessRequestManager } = await import('./access-requests.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const arm = new AccessRequestManager(idb);
        const result = arm.approveRequest(requestId, 'cli-admin');

        process.stdout.write(`Access request approved:\n`);
        process.stdout.write(`  Request ID: ${result.request_id}\n`);
        process.stdout.write(`  Identity:   ${result.identity_id}\n`);
        process.stdout.write(`  Org:        ${result.org}\n`);
        if (result.project) {
          process.stdout.write(`  Project:    ${result.project}\n`);
        }
        process.stdout.write(`  Role:       ${result.role_requested}\n`);
        process.stdout.write(`  Status:     ${result.status}\n`);
        process.stdout.write(`Membership created successfully.\n`);
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

accessRequestsCmd
  .command('deny <requestId>')
  .description('Deny an access request')
  .option('--reason <reason>', 'Denial reason (visible to the requesting agent)')
  .option('--identity-db <path>', 'Path to identity database')
  .action(async (requestId: string, opts) => {
    try {
      const { IdentityDatabase, getDefaultIdentityDbPath } = await import('./identity.js');
      const { AccessRequestManager } = await import('./access-requests.js');
      const dbPath = opts.identityDb || getDefaultIdentityDbPath();
      const idb = new IdentityDatabase(dbPath);

      try {
        const arm = new AccessRequestManager(idb);
        const result = arm.denyRequest(requestId, 'cli-admin', opts.reason);

        process.stdout.write(`Access request denied:\n`);
        process.stdout.write(`  Request ID: ${result.request_id}\n`);
        process.stdout.write(`  Identity:   ${result.identity_id}\n`);
        process.stdout.write(`  Org:        ${result.org}\n`);
        if (result.project) {
          process.stdout.write(`  Project:    ${result.project}\n`);
        }
        process.stdout.write(`  Status:     ${result.status}\n`);
        if (result.denial_reason) {
          process.stdout.write(`  Reason:     ${result.denial_reason}\n`);
        }
      } finally {
        idb.close();
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exit(1);
    }
  });

program.parse();
