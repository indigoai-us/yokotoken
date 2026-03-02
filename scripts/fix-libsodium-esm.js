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
 *
 * Uses createRequire + require.resolve for portable path resolution.
 * Works when:
 *   (a) developing locally (npm install in repo)
 *   (b) installed as a dependency (npm install hq-vault)
 *   (c) installed globally (npm install -g hq-vault)
 */

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

// createRequire anchored to this script's location — resolves packages
// from the same node_modules tree that installed hq-vault, regardless of
// hoisting, nesting, or global install layout.
const require = createRequire(import.meta.url);

/**
 * Find the root directory of an npm package by resolving its main entry
 * point and walking up the directory tree until we find a package.json
 * with the matching name.
 *
 * This avoids require.resolve('<pkg>/package.json') which fails when the
 * package uses an "exports" map that doesn't expose package.json.
 */
function findPackageRoot(packageName) {
  const entry = require.resolve(packageName);
  let dir = path.dirname(entry);
  const root = path.parse(dir).root;

  while (dir !== root) {
    const pkgPath = path.join(dir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        if (pkg.name === packageName) {
          return dir;
        }
      } catch {
        // Malformed package.json — keep walking up
      }
    }
    dir = path.dirname(dir);
  }

  return null;
}

let src, dest;

try {
  const sodiumSumoRoot = findPackageRoot('libsodium-sumo');
  if (!sodiumSumoRoot) {
    console.warn('[fix-libsodium-esm] Could not locate libsodium-sumo package root, skipping');
    process.exit(0);
  }
  src = path.join(sodiumSumoRoot, 'dist', 'modules-sumo-esm', 'libsodium-sumo.mjs');
} catch {
  console.warn('[fix-libsodium-esm] Could not resolve libsodium-sumo package, skipping');
  process.exit(0);
}

try {
  const wrappersRoot = findPackageRoot('libsodium-wrappers-sumo');
  if (!wrappersRoot) {
    console.warn('[fix-libsodium-esm] Could not locate libsodium-wrappers-sumo package root, skipping');
    process.exit(0);
  }
  dest = path.join(wrappersRoot, 'dist', 'modules-sumo-esm', 'libsodium-sumo.mjs');
} catch {
  console.warn('[fix-libsodium-esm] Could not resolve libsodium-wrappers-sumo package, skipping');
  process.exit(0);
}

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
