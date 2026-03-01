# ─── Stage 1: Build ──────────────────────────────────────────────────
# Install build tools for native modules (sodium-native, better-sqlite3)
FROM node:20-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      python3 \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy package files first for layer caching
COPY package.json package-lock.json ./

# Install all dependencies (including devDependencies for TypeScript build)
RUN npm ci

# Copy source and config
COPY tsconfig.json ./
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Prune devDependencies — keep only production deps with native modules
RUN npm prune --omit=dev


# ─── Stage 2: Runtime ───────────────────────────────────────────────
FROM node:20-slim AS runtime

# Install minimal runtime dependencies for native modules and healthcheck
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      wget && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --system vault && \
    useradd --system --gid vault --home-dir /home/vault --create-home vault

WORKDIR /app

# Copy built application from builder
COPY --from=builder /build/dist/ ./dist/
COPY --from=builder /build/node_modules/ ./node_modules/
COPY --from=builder /build/package.json ./

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create data directory structure
RUN mkdir -p /data/certs && \
    chown -R vault:vault /data

# Environment defaults
ENV NODE_ENV=production
ENV HQ_VAULT_PORT=13100
ENV HQ_VAULT_DATA_DIR=/data
ENV HQ_VAULT_NETWORK=true
ENV HQ_VAULT_DIR=/data

# Expose vault port
EXPOSE 13100

# Persistent data volume
VOLUME /data

# Switch to non-root user
USER vault

# Healthcheck: poll /v1/health every 30s (TLS with self-signed cert)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-check-certificate --spider -q https://localhost:${HQ_VAULT_PORT}/v1/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["serve"]
