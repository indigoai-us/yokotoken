import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      // libsodium-wrappers-sumo ESM entry references ./libsodium-sumo.mjs
      // which doesn't exist in its own package — it lives in the libsodium-sumo dep.
      // Force vitest to use the CJS entry instead.
      'libsodium-wrappers-sumo': path.resolve(
        __dirname,
        'node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js',
      ),
    },
  },
  test: {
    globals: true,
    testTimeout: 30000,
    hookTimeout: 30000,
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
    teardownTimeout: 10000,
  },
});
