# hq-vault

Agent-native encrypted credential vault with libsodium encryption.

[![npm version](https://img.shields.io/npm/v/hq-vault)](https://www.npmjs.com/package/hq-vault)
[![license](https://img.shields.io/npm/l/hq-vault)](./LICENSE)
[![tests](https://img.shields.io/github/actions/workflow/status/indigoai-us/hq-vault/ci.yml?label=tests)](https://github.com/indigoai-us/hq-vault/actions)

hq-vault is a local-first secrets manager built for AI agents and developer workflows. It uses XSalsa20-Poly1305 encryption (via libsodium) with Argon2id key derivation to protect credentials at rest, and exposes them over a localhost HTTPS API with token or identity-based authentication.

## Install

```bash
npm install -g hq-vault
```

Requires Node.js 20 or later.

## Quick Start

```bash
# Create a new vault (you'll be prompted for a passphrase)
hq-vault init

# Start the vault server
hq-vault serve

# Store a secret
hq-vault store aws/access-key AKIAIOSFODNN7EXAMPLE

# Retrieve it
hq-vault get aws/access-key
```

## SDK Usage

```typescript
import { getSecret, storeSecret, listSecrets } from 'hq-vault/sdk';

const apiKey = await getSecret('aws/access-key');
await storeSecret('slack/token', 'xoxb-...', { type: 'oauth-token' });
const entries = await listSecrets('aws/');
```

The SDK auto-discovers the vault URL and auth token from environment variables (`HQ_VAULT_URL`, `HQ_VAULT_TOKEN`). For identity-based auth, set `HQ_VAULT_IDENTITY` and `HQ_VAULT_KEY_FILE`.

## Network Client

For multi-vault topologies, use the network client:

```typescript
import { NetworkVaultClient } from 'hq-vault/client';

const client = new NetworkVaultClient({
  url: 'https://vault.internal:13100',
  identity: 'worker-01',
  privateKeyPath: './keys/worker-01.key',
});

const secret = await client.get('shared/api-key');
```

## Docker

```bash
docker build -t hq-vault .
docker run -v vault-data:/data -p 13100:13100 hq-vault serve
```

## Documentation

Full documentation is available at [hq-vault-docs.vercel.app](https://hq-vault-docs.vercel.app).

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Run tests (`npm test`)
4. Submit a pull request

See [SECURITY.md](./SECURITY.md) for reporting vulnerabilities.

## License

[MIT](./LICENSE) -- Copyright (c) 2026 Indigo AI, Inc.
