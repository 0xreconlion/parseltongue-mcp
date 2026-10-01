'use strict';

/**
 * Passphrase entry.
 *
 * This is why the CLI exists. A passphrase passed as an MCP tool argument would travel through
 * the model's context and land in the session transcript; a passphrase typed here goes to a TTY
 * and nowhere else. Same reasoning applies to decrypted plaintext, which is why `open` prints to
 * the terminal and never returns through an agent.
 *
 * Implemented with raw-mode character reading rather than readline. The first version created a
 * readline interface per prompt and suppressed echo by monkey-patching the output stream; it
 * worked for a single prompt and then hung on the second, because the closed interface had
 * already swallowed buffered input. Reading characters directly handles sequential prompts and
 * makes the echo suppression unconditional rather than dependent on matching the prompt string.
 *
 * If stdin is not a TTY the prompt refuses rather than silently reading from a pipe, because a
 * piped passphrase is usually one that just got written into shell history or a CI log.
 */

const CTRL_C = 0x03;
const CTRL_D = 0x04;
const BACKSPACE = 0x7f;
const BACKSPACE_ALT = 0x08;
const ENTER = 0x0d;
const NEWLINE = 0x0a;

class PromptError extends Error {}

/**
 * Bytes received but not yet consumed by a prompt.
 *
 * A TTY delivers whatever is available in one chunk, so a single 'data' event can contain more
 * than one line - from a paste, from fast typing, or from a pty fed by a file. The first version
 * returned as soon as it saw a newline and dropped the remainder of the chunk, which silently ate
 * the second line of a two-prompt sequence. Anything past the terminating newline is carried over
 * for the next prompt instead.
 */
let carry = [];

function assertInteractive() {
  if (!process.stdin.isTTY) {
    throw new PromptError(
      'passphrase entry requires an interactive terminal. Refusing to read it from a pipe or ' +
        'redirect - that is how passphrases end up in shell history, CI logs and transcripts.\n' +
        'If you are automating, the honest answer is that this tool does not support unattended ' +
        'sealing; the passphrase is the thing protecting every message you have ever received.'
    );
  }
}

/**
 * Read a line from the TTY without echoing it. Shows one asterisk per character so the user can
 * see that keystrokes are registering - silence reads as a hung program.
 */
function readHidden(question) {
  assertInteractive();

  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    let buffer = '';
    let settled = false;

    process.stderr.write(question);

    const restore = () => {
      stdin.removeListener('data', onData);
      if (stdin.setRawMode) stdin.setRawMode(Boolean(wasRaw));
      stdin.pause();
    };

    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      restore();
      process.stderr.write('\n');
      fn(value);
    };

    function consume(bytes) {
      for (let i = 0; i < bytes.length; i += 1) {
        const byte = bytes[i];

        if (byte === ENTER || byte === NEWLINE) {
          // Carry anything after the line terminator over to the next prompt. A CR immediately
          // followed by LF is one terminator, not two.
          let rest = i + 1;
          if (byte === ENTER && bytes[rest] === NEWLINE) rest += 1;
          carry = Array.from(bytes).slice(rest);
          finish(resolve, buffer);
          return true;
        }
        if (byte === CTRL_C) {
          carry = [];
          finish(reject, new PromptError('cancelled'));
          return true;
        }
        if (byte === CTRL_D) {
          if (buffer.length === 0) {
            carry = [];
            finish(reject, new PromptError('cancelled'));
            return true;
          }
          continue;
        }
        if (byte === BACKSPACE || byte === BACKSPACE_ALT) {
          if (buffer.length > 0) {
            buffer = buffer.slice(0, -1);
            process.stderr.write('\b \b');
          }
          continue;
        }
        // Ignore other control characters rather than embedding them in a passphrase.
        if (byte < 0x20) continue;

        buffer += String.fromCharCode(byte);
        process.stderr.write('*');
      }
      return false;
    }

    function onData(chunk) {
      consume(chunk);
    }

    // Drain anything left over from a previous prompt before reading more.
    if (carry.length > 0) {
      const pending = carry;
      carry = [];
      if (consume(pending)) return;
    }

    if (stdin.setRawMode) stdin.setRawMode(true);
    stdin.resume();
    stdin.on('data', onData);
  });
}

async function passphrase(label = 'Passphrase') {
  const value = await readHidden(`${label}: `);
  if (!value) throw new PromptError('no passphrase entered');
  return value;
}

/** Ask twice and compare — for anything being set rather than verified. */
async function newPassphrase(label = 'New passphrase', minLength = 10) {
  const first = await readHidden(`${label} (min ${minLength} chars): `);
  if (first.length < minLength) {
    throw new PromptError(`passphrase must be at least ${minLength} characters`);
  }
  const second = await readHidden('Confirm: ');
  if (first !== second) throw new PromptError('passphrases do not match');
  return first;
}

/** Visible yes/no question. Uses the same raw reader so it composes with hidden prompts. */
async function confirm(question) {
  assertInteractive();
  const stdin = process.stdin;
  const wasRaw = stdin.isRaw;

  process.stderr.write(`${question} [y/N] `);

  return new Promise((resolve) => {
    const onData = (chunk) => {
      const char = String.fromCharCode(chunk[0]);
      stdin.removeListener('data', onData);
      if (stdin.setRawMode) stdin.setRawMode(Boolean(wasRaw));
      stdin.pause();
      process.stderr.write(`${char}\n`);
      resolve(/^y$/i.test(char));
    };
    if (stdin.setRawMode) stdin.setRawMode(true);
    stdin.resume();
    stdin.on('data', onData);
  });
}

module.exports = { PromptError, assertInteractive, confirm, newPassphrase, passphrase, readHidden };
