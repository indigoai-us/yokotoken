# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in hq-vault, please report it responsibly.

**Email:** [security@getindigo.ai](mailto:security@getindigo.ai)

Please include:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes (optional)

**Do not** open a public GitHub issue for security vulnerabilities.

## Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Acknowledgement | Within 72 hours |
| Initial assessment | Within 1 week |
| Fix development | Within 90 days |
| Public disclosure | After fix is released |

We will coordinate disclosure with you and credit you in the release notes (unless you prefer to remain anonymous).

## Scope

The following areas are in scope for security reports:

- **Encryption** -- XSalsa20-Poly1305 secret encryption, key derivation (Argon2id), at-rest vault security
- **Authentication** -- Token-based auth, identity-based challenge-response auth, session tokens
- **TLS** -- Self-signed CA generation, certificate validation, network transport security
- **Access control** -- Scoped tokens, identity permissions, access request approval flow
- **Key management** -- Master key handling, identity key rotation, key material in memory

## Out of Scope

The following are generally out of scope:

- Denial of service attacks against the local vault server
- Issues requiring physical access to the machine running the vault
- Social engineering attacks
- Vulnerabilities in dependencies (report those to the upstream project, but let us know so we can update)
- Issues in the documentation site

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

We recommend always running the latest version.
