#!/usr/bin/env node
/**
 * Workaround for libsodium-wrappers-sumo ESM resolution bug.
 *
 * The ESM entry point (libsodium-wrappers.mjs) imports "./libsodium-sumo.mjs"
 * as a bare relative import, but that file lives in the *separate* package
 * `libsodium-sumo` — not in `libsodium-wrappers-sumo`.
 *
 * This script copies the missing file into the correct location so that
 * Node.js ESM resolution works at runtime (not just in vitest, which has
 * a resolve alias).
 *
 * Run automatically via the `postinstall` npm script.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

const src = path.join(
  root,
  'node_modules',
  'libsodium-sumo',
  'dist',
  'modules-sumo-esm',
  'libsodium-sumo.mjs',
);

const dest = path.join(
  root,
  'node_modules',
  'libsodium-wrappers-sumo',
  'dist',
  'modules-sumo-esm',
  'libsodium-sumo.mjs',
);

if (!fs.existsSync(src)) {
  console.warn('[fix-libsodium-esm] Source file not found, skipping:', src);
  process.exit(0);
}

if (fs.existsSync(dest)) {
  // Already patched (or upstream fixed) — nothing to do
  process.exit(0);
}

try {
  fs.copyFileSync(src, dest);
  console.log('[fix-libsodium-esm] Copied libsodium-sumo.mjs into libsodium-wrappers-sumo ESM dir');
} catch (err) {
  console.warn('[fix-libsodium-esm] Failed to copy:', err.message);
  process.exit(0); // Non-fatal — don't break npm install
}
