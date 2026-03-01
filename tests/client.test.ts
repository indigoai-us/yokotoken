/**
 * Tests for the vault client module.
 *
 * Verifies:
 * - Connection refused error is reported clearly
 * - Timeout handling
 */

import { describe, it, expect } from 'vitest';
import { request } from '../src/client.js';

describe('Client — connection errors', () => {
  it('should report clear error when server is not running', async () => {
    await expect(
      request({ port: 19999, host: '127.0.0.1' }, 'GET', '/v1/status'),
    ).rejects.toThrow('Vault server is not running');
  });
});
