/**
 * Web entry module for hq-vault — US-007.
 *
 * Provides a one-time local HTTPS web page for secure secret entry.
 * When `hq-vault ingest <path> --web` is invoked:
 *
 * 1. A one-time token is generated
 * 2. An HTTPS server starts on a random port using the vault's self-signed cert
 * 3. The URL https://localhost:PORT/enter/ONETIME_TOKEN is printed to stderr
 * 4. The page shows: secret path, textarea, submit button (minimal HTML, no JS frameworks)
 * 5. On submit: secret is stored via the vault API, page shows success, endpoint shuts down
 * 6. The one-time token expires after 60 seconds if not used
 * 7. The page cannot be reloaded or resubmitted after use
 *
 * Security properties:
 * - One-time token prevents replay
 * - 60-second expiry prevents stale pages
 * - HTTPS with self-signed cert (same as vault server)
 * - Server shuts down after successful submission
 * - Secret value never appears in terminal output (agent-safe)
 */

import https from 'node:https';
import http from 'node:http';
import crypto from 'node:crypto';
import { request, type ClientConfig } from './client.js';
import { ensureCerts, type TlsCertPaths, type TlsCertData } from './tls.js';

export interface WebEntryOptions {
  /** The secret path in the vault (e.g., "slack/user-token"). */
  secretPath: string;
  /** Secret type (optional). */
  type?: string;
  /** Secret description (optional). */
  description?: string;
  /** Client config for the vault server (to store the secret). */
  vaultClient: ClientConfig;
  /** TLS certificate data (for the web entry server). If not provided, uses vault's certs. */
  tlsCertData?: TlsCertData;
  /** TLS certificate paths (for the web entry server). Ignored if tlsCertData is provided. */
  tlsCertPaths?: TlsCertPaths;
  /** Token expiry in milliseconds. Default: 60000 (60 seconds). */
  tokenExpiryMs?: number;
  /** If true, use plain HTTP instead of HTTPS (for testing only). */
  insecure?: boolean;
}

export interface WebEntryResult {
  /** Whether the secret was successfully stored. */
  success: boolean;
  /** The number of bytes stored (if successful). */
  bytes?: number;
  /** Error message (if failed). */
  error?: string;
}

/**
 * Generate a cryptographically random one-time token (32 bytes, hex).
 */
export function generateOneTimeToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Build the minimal HTML page for secret entry.
 * No JS frameworks, no external resources. Pure inline HTML/CSS/JS.
 */
export function buildEntryPage(secretPath: string, submitUrl: string): string {
  // Escape HTML entities in the secret path to prevent XSS
  const escapedPath = secretPath
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>hq-vault: Enter Secret</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 600px;
      margin: 60px auto;
      padding: 0 20px;
      background: #0d1117;
      color: #c9d1d9;
    }
    h1 {
      font-size: 1.4em;
      color: #58a6ff;
      margin-bottom: 4px;
    }
    .path {
      font-family: 'SFMono-Regular', Consolas, monospace;
      background: #161b22;
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid #30363d;
      margin-bottom: 20px;
      font-size: 0.95em;
      color: #f0f6fc;
    }
    label {
      display: block;
      margin-bottom: 8px;
      font-weight: 600;
    }
    textarea {
      width: 100%;
      min-height: 120px;
      padding: 10px;
      font-family: 'SFMono-Regular', Consolas, monospace;
      font-size: 0.9em;
      background: #0d1117;
      color: #c9d1d9;
      border: 1px solid #30363d;
      border-radius: 6px;
      resize: vertical;
      box-sizing: border-box;
    }
    textarea:focus {
      outline: none;
      border-color: #58a6ff;
    }
    button {
      margin-top: 16px;
      padding: 10px 24px;
      background: #238636;
      color: #fff;
      border: none;
      border-radius: 6px;
      font-size: 1em;
      cursor: pointer;
      font-weight: 600;
    }
    button:hover {
      background: #2ea043;
    }
    button:disabled {
      background: #21262d;
      color: #484f58;
      cursor: not-allowed;
    }
    .msg {
      margin-top: 16px;
      padding: 12px;
      border-radius: 6px;
      display: none;
    }
    .msg.success {
      display: block;
      background: #0d2818;
      border: 1px solid #238636;
      color: #3fb950;
    }
    .msg.error {
      display: block;
      background: #2d1117;
      border: 1px solid #f85149;
      color: #f85149;
    }
  </style>
</head>
<body>
  <h1>hq-vault</h1>
  <p>Enter the secret value for:</p>
  <div class="path">${escapedPath}</div>
  <form id="form" method="POST" action="${submitUrl}">
    <label for="secret">Secret value</label>
    <textarea id="secret" name="value" required autofocus placeholder="Paste or type the secret value here..."></textarea>
    <button type="submit" id="btn">Store Secret</button>
  </form>
  <div id="msg" class="msg"></div>
  <script>
    var form = document.getElementById('form');
    var btn = document.getElementById('btn');
    var msg = document.getElementById('msg');
    var submitted = false;
    form.addEventListener('submit', function(e) {
      e.preventDefault();
      if (submitted) return;
      submitted = true;
      btn.disabled = true;
      btn.textContent = 'Storing...';
      var value = document.getElementById('secret').value;
      var xhr = new XMLHttpRequest();
      xhr.open('POST', form.action, true);
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
        if (xhr.status === 200) {
          form.style.display = 'none';
          msg.className = 'msg success';
          msg.textContent = 'Stored successfully.';
        } else {
          try {
            var resp = JSON.parse(xhr.responseText);
            msg.className = 'msg error';
            msg.textContent = 'Error: ' + (resp.error || 'Unknown error');
          } catch(ex) {
            msg.className = 'msg error';
            msg.textContent = 'Error: ' + xhr.statusText;
          }
          submitted = false;
          btn.disabled = false;
          btn.textContent = 'Store Secret';
        }
      };
      xhr.onerror = function() {
        msg.className = 'msg error';
        msg.textContent = 'Network error. The server may have shut down.';
        submitted = false;
        btn.disabled = false;
        btn.textContent = 'Store Secret';
      };
      xhr.send('value=' + encodeURIComponent(value));
    });
  </script>
</body>
</html>`;
}

/**
 * Build the "already used" page shown when the token has been consumed.
 */
function buildUsedPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>hq-vault: Entry Complete</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 600px;
      margin: 60px auto;
      padding: 0 20px;
      background: #0d1117;
      color: #c9d1d9;
    }
    .msg {
      padding: 12px;
      border-radius: 6px;
      background: #0d2818;
      border: 1px solid #238636;
      color: #3fb950;
    }
  </style>
</head>
<body>
  <h1 style="color:#58a6ff;font-size:1.4em;">hq-vault</h1>
  <div class="msg">This entry page has already been used. You can close this tab.</div>
</body>
</html>`;
}

/**
 * Build the "expired" page shown when the token has timed out.
 */
function buildExpiredPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>hq-vault: Entry Expired</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 600px;
      margin: 60px auto;
      padding: 0 20px;
      background: #0d1117;
      color: #c9d1d9;
    }
    .msg {
      padding: 12px;
      border-radius: 6px;
      background: #2d1117;
      border: 1px solid #f85149;
      color: #f85149;
    }
  </style>
</head>
<body>
  <h1 style="color:#58a6ff;font-size:1.4em;">hq-vault</h1>
  <div class="msg">This entry page has expired. Please run the ingest command again.</div>
</body>
</html>`;
}

/**
 * Parse URL-encoded form body from a POST request.
 */
function parseFormBody(req: http.IncomingMessage): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    const MAX_BODY = 1024 * 1024; // 1MB max

    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf-8');
      const params: Record<string, string> = {};
      for (const pair of raw.split('&')) {
        const [key, ...rest] = pair.split('=');
        if (key) {
          params[decodeURIComponent(key)] = decodeURIComponent(rest.join('='));
        }
      }
      resolve(params);
    });
    req.on('error', reject);
  });
}

/**
 * Send an HTML response.
 */
function sendHtml(res: http.ServerResponse, statusCode: number, html: string): void {
  const body = Buffer.from(html, 'utf-8');
  res.writeHead(statusCode, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache',
  });
  res.end(body);
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
 * Start the one-time web entry server.
 *
 * Returns a promise that resolves when the secret has been submitted
 * (or the token expires).
 *
 * The caller should await this — it blocks until the entry is complete
 * or times out.
 */
export function startWebEntry(options: WebEntryOptions): Promise<WebEntryResult> {
  const tokenExpiryMs = options.tokenExpiryMs ?? 60_000;
  const oneTimeToken = generateOneTimeToken();

  return new Promise((resolve) => {
    let tokenUsed = false;
    let tokenExpired = false;
    let serverInstance: https.Server | http.Server;

    // Set up the expiry timer
    const expiryTimer = setTimeout(() => {
      tokenExpired = true;
      // Shut down the server after expiry + a small grace period
      setTimeout(() => {
        try { serverInstance.close(); } catch { /* ok */ }
      }, 1000);
      resolve({
        success: false,
        error: 'One-time token expired (not used within timeout)',
      });
    }, tokenExpiryMs);
    expiryTimer.unref();

    const handler = async (req: http.IncomingMessage, res: http.ServerResponse) => {
      const urlObj = new URL(req.url || '/', `https://localhost`);
      const pathname = urlObj.pathname;
      const expectedEntryPath = `/enter/${oneTimeToken}`;
      const expectedSubmitPath = `/submit/${oneTimeToken}`;

      // GET /enter/<token> — Show the entry form
      if (req.method === 'GET' && pathname === expectedEntryPath) {
        if (tokenExpired) {
          sendHtml(res, 410, buildExpiredPage());
          return;
        }
        if (tokenUsed) {
          sendHtml(res, 410, buildUsedPage());
          return;
        }
        const submitUrl = expectedSubmitPath;
        sendHtml(res, 200, buildEntryPage(options.secretPath, submitUrl));
        return;
      }

      // POST /submit/<token> — Store the secret
      if (req.method === 'POST' && pathname === expectedSubmitPath) {
        if (tokenExpired) {
          sendJson(res, 410, { error: 'Token expired' });
          return;
        }
        if (tokenUsed) {
          sendJson(res, 410, { error: 'Token already used' });
          return;
        }

        // Mark as used immediately to prevent race conditions
        tokenUsed = true;
        clearTimeout(expiryTimer);

        try {
          const formData = await parseFormBody(req);
          const value = formData['value'];

          if (!value || value.length === 0) {
            tokenUsed = false; // Allow retry on empty value
            sendJson(res, 400, { error: 'Secret value cannot be empty' });
            return;
          }

          // Store via vault API
          const body: Record<string, unknown> = { value };
          if (options.type) body.type = options.type;
          if (options.description) body.description = options.description;

          const storeRes = await request(
            options.vaultClient,
            'PUT',
            `/v1/secrets/${encodeURIComponent(options.secretPath)}`,
            body,
          );

          if (storeRes.statusCode === 200) {
            const bytes = storeRes.body.bytes as number;
            sendJson(res, 200, { ok: true });

            // Shut down the server after a brief delay to allow response flush
            setTimeout(() => {
              try { serverInstance.close(); } catch { /* ok */ }
            }, 500);

            resolve({
              success: true,
              bytes,
            });
          } else {
            tokenUsed = false; // Allow retry on server error
            sendJson(res, 502, { error: storeRes.body.error || 'Failed to store secret' });
          }
        } catch (err) {
          tokenUsed = false; // Allow retry on error
          const message = err instanceof Error ? err.message : 'Internal error';
          sendJson(res, 500, { error: message });
        }
        return;
      }

      // Everything else: 404
      sendHtml(res, 404, '<html><body><h1>Not Found</h1></body></html>');
    };

    if (options.insecure) {
      serverInstance = http.createServer(handler);
    } else {
      const certData = options.tlsCertData || ensureCerts(options.tlsCertPaths);
      serverInstance = https.createServer(
        { cert: certData.cert, key: certData.key },
        handler,
      );
    }

    serverInstance.listen(0, '127.0.0.1', () => {
      const addr = serverInstance.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      const protocol = options.insecure ? 'http' : 'https';
      const url = `${protocol}://localhost:${port}/enter/${oneTimeToken}`;

      process.stderr.write(`\nOpen this URL to enter the secret:\n\n  ${url}\n\n`);
      process.stderr.write(`This link expires in ${Math.round(tokenExpiryMs / 1000)} seconds.\n`);
      process.stderr.write('Waiting for submission...\n');
    });

    // Store the server/token for external access (used by getServerInfo for testing)
    (handler as any).__server = serverInstance;
    (handler as any).__token = oneTimeToken;
  });
}

/**
 * A lower-level API for tests that need access to the server and token.
 *
 * Returns the server instance, one-time token, and a result promise.
 */
export function createWebEntryServer(options: WebEntryOptions): {
  resultPromise: Promise<WebEntryResult>;
  getPort: () => number;
  getToken: () => string;
  getServer: () => https.Server | http.Server;
} {
  const tokenExpiryMs = options.tokenExpiryMs ?? 60_000;
  const oneTimeToken = generateOneTimeToken();

  let tokenUsed = false;
  let tokenExpired = false;
  let serverInstance: https.Server | http.Server;
  let resolveResult: (result: WebEntryResult) => void;

  const resultPromise = new Promise<WebEntryResult>((resolve) => {
    resolveResult = resolve;
  });

  // Set up the expiry timer
  const expiryTimer = setTimeout(() => {
    tokenExpired = true;
    setTimeout(() => {
      try { serverInstance.close(); } catch { /* ok */ }
    }, 1000);
    resolveResult({
      success: false,
      error: 'One-time token expired (not used within timeout)',
    });
  }, tokenExpiryMs);
  expiryTimer.unref();

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse) => {
    const urlObj = new URL(req.url || '/', `https://localhost`);
    const pathname = urlObj.pathname;
    const expectedEntryPath = `/enter/${oneTimeToken}`;
    const expectedSubmitPath = `/submit/${oneTimeToken}`;

    // GET /enter/<token> -- Show the entry form
    if (req.method === 'GET' && pathname === expectedEntryPath) {
      if (tokenExpired) {
        sendHtml(res, 410, buildExpiredPage());
        return;
      }
      if (tokenUsed) {
        sendHtml(res, 410, buildUsedPage());
        return;
      }
      const submitUrl = expectedSubmitPath;
      sendHtml(res, 200, buildEntryPage(options.secretPath, submitUrl));
      return;
    }

    // POST /submit/<token> -- Store the secret
    if (req.method === 'POST' && pathname === expectedSubmitPath) {
      if (tokenExpired) {
        sendJson(res, 410, { error: 'Token expired' });
        return;
      }
      if (tokenUsed) {
        sendJson(res, 410, { error: 'Token already used' });
        return;
      }

      tokenUsed = true;
      clearTimeout(expiryTimer);

      try {
        const formData = await parseFormBody(req);
        const value = formData['value'];

        if (!value || value.length === 0) {
          tokenUsed = false;
          sendJson(res, 400, { error: 'Secret value cannot be empty' });
          return;
        }

        // Store via vault API
        const body: Record<string, unknown> = { value };
        if (options.type) body.type = options.type;
        if (options.description) body.description = options.description;

        const storeRes = await request(
          options.vaultClient,
          'PUT',
          `/v1/secrets/${encodeURIComponent(options.secretPath)}`,
          body,
        );

        if (storeRes.statusCode === 200) {
          const bytes = storeRes.body.bytes as number;
          sendJson(res, 200, { ok: true });

          setTimeout(() => {
            try { serverInstance.close(); } catch { /* ok */ }
          }, 500);

          resolveResult({ success: true, bytes });
        } else {
          tokenUsed = false;
          sendJson(res, 502, { error: storeRes.body.error || 'Failed to store secret' });
        }
      } catch (err) {
        tokenUsed = false;
        const message = err instanceof Error ? err.message : 'Internal error';
        sendJson(res, 500, { error: message });
      }
      return;
    }

    // 404 for everything else
    sendHtml(res, 404, '<html><body><h1>Not Found</h1></body></html>');
  };

  if (options.insecure) {
    serverInstance = http.createServer(handler);
  } else {
    const certData = options.tlsCertData || ensureCerts(options.tlsCertPaths);
    serverInstance = https.createServer(
      { cert: certData.cert, key: certData.key },
      handler,
    );
  }

  serverInstance.listen(0, '127.0.0.1');

  return {
    resultPromise,
    getPort: () => {
      const addr = serverInstance.address();
      return typeof addr === 'object' && addr ? addr.port : 0;
    },
    getToken: () => oneTimeToken,
    getServer: () => serverInstance,
  };
}
