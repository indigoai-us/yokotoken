/**
 * Vault client — sends requests to the vault server.
 *
 * Used by CLI commands to communicate with the running vault server
 * process that holds the master key in memory.
 *
 * Supports HTTPS with self-signed certificates and Bearer token auth.
 */

import https from 'node:https';
import http from 'node:http';

export interface ClientConfig {
  port: number;
  host: string;
  /** Bearer token for authentication. */
  token?: string;
  /** If true, use plain HTTP instead of HTTPS. */
  insecure?: boolean;
  /** If true, skip TLS certificate validation (for self-signed certs). */
  rejectUnauthorized?: boolean;
}

export interface ClientResponse {
  statusCode: number;
  body: Record<string, unknown>;
}

/**
 * Send a request to the vault server.
 */
export function request(
  config: ClientConfig,
  method: string,
  path: string,
  body?: Record<string, unknown>,
): Promise<ClientResponse> {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : undefined;
    const useHttps = !config.insecure;

    const headers: Record<string, string> = {};
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = String(Buffer.byteLength(payload));
    }
    if (config.token) {
      headers['Authorization'] = `Bearer ${config.token}`;
    }

    const options: https.RequestOptions = {
      hostname: config.host,
      port: config.port,
      path,
      method,
      headers,
      timeout: 5000,
      ...(useHttps ? { rejectUnauthorized: config.rejectUnauthorized ?? false } : {}),
    };

    const transport = useHttps ? https : http;

    const req = transport.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        try {
          const responseBody = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
          resolve({
            statusCode: res.statusCode || 500,
            body: responseBody,
          });
        } catch {
          resolve({
            statusCode: res.statusCode || 500,
            body: { error: 'Invalid response from server' },
          });
        }
      });
    });

    req.on('error', (err) => {
      if ((err as NodeJS.ErrnoException).code === 'ECONNREFUSED') {
        reject(new Error('Vault server is not running. Start it with: hq-vault serve'));
      } else {
        reject(err);
      }
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request to vault server timed out'));
    });

    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}
