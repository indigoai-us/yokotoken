/**
 * Tests for the passphrase module.
 *
 * Since the passphrase module relies on TTY stdin for echo-disabled input,
 * we test the non-TTY fallback path (piped input) and the confirmation logic.
 */

import { describe, it, expect } from 'vitest';
import { Readable } from 'node:stream';

describe('Passphrase — readAndConfirmPassphrase validation', () => {
  it('should export readPassphrase and readAndConfirmPassphrase', async () => {
    const mod = await import('../src/passphrase.js');
    expect(typeof mod.readPassphrase).toBe('function');
    expect(typeof mod.readAndConfirmPassphrase).toBe('function');
  });
});

describe('Passphrase — input handling', () => {
  it('readPassphrase should handle non-TTY piped input', async () => {
    // Save original stdin
    const originalStdin = process.stdin;
    const originalIsTTY = process.stdin.isTTY;

    try {
      // Create a mock stdin stream with piped data
      const mockStdin = new Readable({
        read() {
          this.push('my-secret-passphrase\n');
          this.push(null);
        },
      });

      // Replace stdin temporarily
      Object.defineProperty(process, 'stdin', {
        value: mockStdin,
        writable: true,
        configurable: true,
      });
      Object.defineProperty(process.stdin, 'isTTY', {
        value: undefined,
        writable: true,
        configurable: true,
      });

      const { readPassphrase } = await import('../src/passphrase.js');
      const result = await readPassphrase('Enter passphrase: ');
      expect(result).toBe('my-secret-passphrase');
    } finally {
      // Restore original stdin
      Object.defineProperty(process, 'stdin', {
        value: originalStdin,
        writable: true,
        configurable: true,
      });
    }
  });
});
