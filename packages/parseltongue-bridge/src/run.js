'use strict';

/**
 * Running transforms, and upstream's universal auto-decoder.
 */

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const { getRegistry, defaultOptions } = require('./registry');
const { loadTransforms, resolveParseltongueRoot, withProtectedStdout } = require('./loader');

class TransformError extends Error {}

/**
 * Run one transform. `action` is 'encode' | 'decode' | 'preview'.
 *
 * Returns the output plus the fidelity metadata that applies to it, so a caller can never see a
 * decode result without also seeing how much to trust it.
 */
function runTransform(key, { action = 'encode', text = '', options = {} } = {}) {
  const { entries } = getRegistry();
  const entry = entries.get(key);
  if (!entry) {
    throw new TransformError(`Unknown transform: ${key}`);
  }

  const transform = entry._impl;
  const resolvedOptions = { ...defaultOptions(transform), ...options };

  let output;
  if (action === 'encode') {
    output = transform.func(text, resolvedOptions);
  } else if (action === 'decode') {
    if (typeof transform.reverse !== 'function') {
      throw new TransformError(`${entry.name} has no decode; it is encode-only.`);
    }
    output = transform.reverse(text, resolvedOptions);
  } else if (action === 'preview') {
    if (typeof transform.preview !== 'function') {
      // Upstream's cli_bridge calls preview() unguarded and crashes when it is absent.
      throw new TransformError(`${entry.name} has no preview.`);
    }
    output = transform.preview(text, resolvedOptions);
  } else {
    throw new TransformError(`Unsupported action: ${action}. Use encode, decode or preview.`);
  }

  const result = {
    transform: key,
    name: entry.name,
    category: entry.category,
    action,
    options: resolvedOptions,
    output,
    fidelity: entry.fidelity,
    fidelityNote: entry.fidelityNote,
    ...(entry.safeFor ? { safeFor: entry.safeFor } : {}),
  };

  // An empty result from non-empty input is a real upstream failure mode (`morse`), and it is
  // easy to mistake for "the text had nothing in it".
  if (output === '' && text !== '') {
    result.warning =
      `${entry.name} returned an empty string for non-empty input. This is a known upstream ` +
      'defect in some transforms, not an encoding of your text.';
  }

  return result;
}

let decoderCache = null;

/**
 * Load upstream's universal decoder out of js/core/decoder.js.
 *
 * Ported from cli_bridge.js loadUniversalDecoder, including its mock steganography object —
 * which is why autoDecode cannot detect emoji or invisible-character steganography. That is a
 * real capability gap and reported as one rather than left implicit.
 */
function loadDecoder() {
  if (decoderCache) return decoderCache;

  const root = resolveParseltongueRoot();
  const read = (...parts) => fs.readFileSync(path.join(root, ...parts), 'utf8');

  const transforms = loadTransforms(root);
  const sandbox = {
    window: {
      transforms,
      // Upstream's bridge stubs these out; steganographic carriers are therefore invisible to
      // the decoder. Mirrored exactly so behavior matches upstream's own CLI.
      steganography: {
        hasEmojiInText: () => false,
        decodeEmoji: () => null,
        decodeInvisible: () => null,
      },
      emojiLibrary: {},
      emojiKeywords: {},
      emojiData: {},
    },
    console,
    TextEncoder,
    TextDecoder,
    Intl,
    btoa: (str) => Buffer.from(str, 'binary').toString('base64'),
    atob: (str) => Buffer.from(str, 'base64').toString('binary'),
  };

  withProtectedStdout(() => {
    vm.createContext(sandbox);
    vm.runInContext(read('js', 'utils', 'emoji.js'), sandbox);
    vm.runInContext(read('src', 'emojiWordMap.js'), sandbox);
    vm.runInContext(read('js', 'core', 'transformOptions.js'), sandbox);
    vm.runInContext(read('js', 'core', 'decoder.js'), sandbox);
  });

  if (typeof sandbox.universalDecode !== 'function') {
    throw new TransformError(
      'upstream decoder.js did not define universalDecode; the checkout may be incomplete'
    );
  }

  decoderCache = sandbox.universalDecode;
  return decoderCache;
}

/** Upstream's detector-based auto-decode. */
function autoDecode(text) {
  const decode = loadDecoder();
  const result = decode(text || '', {});
  return {
    result,
    limitations: [
      'Steganographic carriers are not detected: upstream\'s Node decode path stubs out emoji ' +
        'and invisible-character steganography. Use inspect_text to look for hidden characters.',
      'Detection is heuristic. A result is a best guess at the encoding, not proof of it.',
    ],
  };
}

module.exports = { TransformError, autoDecode, runTransform };
