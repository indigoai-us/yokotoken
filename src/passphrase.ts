/**
 * Secure passphrase input via stdin with echo disabled.
 *
 * The passphrase is read from stdin character by character with
 * terminal echo turned off, so it never appears on screen or in
 * shell history.
 */

import readline from 'node:readline';

/**
 * Read a passphrase from stdin with echo disabled.
 * Falls back to normal readline if stdin is not a TTY (piped input).
 */
export async function readPassphrase(prompt: string): Promise<string> {
  // If stdin is not a TTY (piped input), just read a line
  if (!process.stdin.isTTY) {
    return readLine(prompt);
  }

  return new Promise<string>((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr, // Write prompt to stderr so it doesn't mix with stdout
      terminal: true,
    });

    // Disable echo by using a custom _writeToOutput that suppresses the input
    const origWrite = (rl as any)._writeToOutput;
    (rl as any)._writeToOutput = function (str: string) {
      // Only write the prompt, not the user's input
      if (str === prompt) {
        origWrite.call(rl, str);
      }
    };

    rl.question(prompt, (answer) => {
      // Restore original write
      (rl as any)._writeToOutput = origWrite;
      rl.close();
      // Print a newline since echo was suppressed
      process.stderr.write('\n');
      resolve(answer);
    });
  });
}

/**
 * Simple line reader (no echo suppression) for non-TTY input.
 */
function readLine(prompt: string): Promise<string> {
  return new Promise<string>((resolve) => {
    process.stderr.write(prompt);
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: false,
    });
    rl.once('line', (line) => {
      rl.close();
      resolve(line);
    });
  });
}

/**
 * Read and confirm a passphrase (asks twice, verifies they match).
 * Returns the confirmed passphrase or throws if they don't match.
 */
export async function readAndConfirmPassphrase(): Promise<string> {
  const pass1 = await readPassphrase('Enter master passphrase: ');
  if (!pass1 || pass1.length === 0) {
    throw new Error('Passphrase cannot be empty');
  }

  const pass2 = await readPassphrase('Confirm master passphrase: ');
  if (pass1 !== pass2) {
    throw new Error('Passphrases do not match');
  }

  return pass1;
}
