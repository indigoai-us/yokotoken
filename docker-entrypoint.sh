#!/bin/sh
set -e

# ─── hq-vault Docker entrypoint ─────────────────────────────────────
#
# Handles:
# - Data directory setup
# - Vault existence detection (first-run guidance)
# - TLS cert injection from environment
# - Signal forwarding for graceful shutdown
# - Starting the vault in network mode
#

DATA_DIR="${HQ_VAULT_DATA_DIR:-/data}"
PORT="${HQ_VAULT_PORT:-13100}"
VAULT_DB="${DATA_DIR}/vault.db"
IDENTITY_DB="${DATA_DIR}/identity.db"
CERTS_DIR="${DATA_DIR}/certs"

# ─── Handle "init" command ───────────────────────────────────────────
# Usage: docker compose run vault init [--force]
if [ "$1" = "init" ]; then
  shift
  exec node dist/cli.js init --vault-path "${VAULT_DB}" "$@"
fi

# ─── Handle "identity" command ───────────────────────────────────────
# Usage: docker compose run vault identity create --name admin --type human
if [ "$1" = "identity" ]; then
  shift
  exec node dist/cli.js identity "$@" --identity-db "${IDENTITY_DB}"
fi

# ─── Handle arbitrary CLI commands ──────────────────────────────────
# Usage: docker compose run vault <any-cli-command> [args...]
if [ "$1" != "serve" ] && [ "$1" != "" ]; then
  exec node dist/cli.js "$@"
fi

# ─── Serve mode ─────────────────────────────────────────────────────

# Check for vault.db — first run guidance
if [ ! -f "${VAULT_DB}" ]; then
  echo "=================================================="
  echo "  No vault found at ${VAULT_DB}"
  echo ""
  echo "  Initialize a new vault:"
  echo "    docker compose run vault init"
  echo ""
  echo "  Then create an admin identity:"
  echo "    docker compose run vault identity create \\"
  echo "      --name admin --type human"
  echo ""
  echo "  Then start the service:"
  echo "    docker compose up -d"
  echo "=================================================="
  exit 1
fi

# ─── Write TLS certs from environment if provided ────────────────────
# Allows injecting certs via env vars instead of volume-mounting files.
if [ -n "${HQ_VAULT_TLS_CERT}" ] && [ -n "${HQ_VAULT_TLS_KEY}" ]; then
  echo "[entrypoint] Writing TLS cert and key from environment variables..."
  echo "${HQ_VAULT_TLS_CERT}" > "${CERTS_DIR}/cert.pem"
  echo "${HQ_VAULT_TLS_KEY}" > "${CERTS_DIR}/key.pem"
  chmod 600 "${CERTS_DIR}/key.pem"
  TLS_ARGS="--tls-cert ${CERTS_DIR}/cert.pem --tls-key ${CERTS_DIR}/key.pem"
elif [ -f "${CERTS_DIR}/cert.pem" ] && [ -f "${CERTS_DIR}/key.pem" ]; then
  echo "[entrypoint] Using TLS certs from ${CERTS_DIR}/"
  TLS_ARGS="--tls-cert ${CERTS_DIR}/cert.pem --tls-key ${CERTS_DIR}/key.pem"
else
  echo "[entrypoint] No TLS certs provided — using auto-generated self-signed certificate"
  TLS_ARGS=""
fi

# ─── Build the serve command ─────────────────────────────────────────
SERVE_CMD="node dist/cli.js serve \
  --network \
  --vault-path ${VAULT_DB} \
  --port ${PORT}"

if [ -n "${TLS_ARGS}" ]; then
  SERVE_CMD="${SERVE_CMD} ${TLS_ARGS}"
fi

if [ -n "${HQ_VAULT_IDLE_TIMEOUT}" ]; then
  SERVE_CMD="${SERVE_CMD} --idle-timeout ${HQ_VAULT_IDLE_TIMEOUT}"
fi

echo "[entrypoint] Starting hq-vault in network mode on port ${PORT}"
echo "[entrypoint] Vault DB: ${VAULT_DB}"
echo "[entrypoint] Data dir: ${DATA_DIR}"

# ─── Signal forwarding ──────────────────────────────────────────────
# exec replaces shell with node process, so signals (SIGTERM, SIGINT)
# go directly to the vault server for graceful shutdown.
exec ${SERVE_CMD}
