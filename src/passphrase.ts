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
 * Read all lines from piped stdin at once.
 * Needed because readline eagerly consumes the entire pipe buffer,
 * so creating sequential readline interfaces loses data.
 */
function readAllLines(): Promise<string[]> {
  return new Promise<string[]>((resolve) => {
    const lines: string[] = [];
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: false,
    });
    rl.on('line', (line) => {
      lines.push(line);
    });
    rl.on('close', () => {
      resolve(lines);
    });
  });
}

/**
 * Read and confirm a passphrase (asks twice, verifies they match).
 * Returns the confirmed passphrase or throws if they don't match.
 *
 * When stdin is piped (non-TTY), all lines are read at once to avoid
 * the readline buffer-drain race condition.
 */
export async function readAndConfirmPassphrase(): Promise<string> {
  // For piped input, read all lines up front to avoid race conditions
  // where readline eagerly consumes the entire buffer on the first read.
  if (!process.stdin.isTTY) {
    process.stderr.write('Enter master passphrase: ');
    const lines = await readAllLines();
    process.stderr.write('Confirm master passphrase: ');

    const pass1 = lines[0] || '';
    const pass2 = lines[1] || '';

    if (!pass1 || pass1.length === 0) {
      throw new Error('Passphrase cannot be empty');
    }
    if (pass1 !== pass2) {
      throw new Error('Passphrases do not match');
    }
    return pass1;
  }

  // TTY mode — interactive, read one at a time
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
