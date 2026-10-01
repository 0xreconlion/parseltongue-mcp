# @reconlion/parseltongue-bridge

**AGPL-3.0-only.** Node access to the [P4RS3LT0NGV3](https://github.com/elder-plinius/P4RS3LT0NGV3)
transform catalog. The only package in this repo that touches upstream source, and therefore the
only reason the repo as a whole is AGPL. See [`../../docs/LICENSING.md`](../../docs/LICENSING.md).

Transforms are **representation, not confidentiality**. Everything here is reversible by anyone
with no key.

## Upstream checkout

Not vendored. Point at a local clone:

```bash
export PARSELTONGUE_ROOT=/path/to/P4RS3LT0NGV3
```

Without it, known local checkouts are tried in order. The checkout must have had `npm install`
run at least once.

## Why this is not a thin re-export

### Fidelity is measured, not assumed

Upstream's `canDecode` means only "a `reverse()` function exists". Measured against commit
`a6cb7c9`, across 222 transforms:

| Tier | Count | Meaning |
|---|---|---|
| `exact` | 92 | round-trips byte for byte |
| `lossy` | 58 | recovers the text but drops case, spacing, digits (normal for classical ciphers) |
| `constrained` | 24 | round-trips *some* input shapes and corrupts others — `safeFor` names which |
| `encode_only` | 37 | no `reverse()` at all |
| `unreliable` | 11 | decode never recovers the input |

So of the 185 transforms advertising `canDecode`, only 92 actually return your text unchanged. An
agent told only `canDecode: true` will hand back corrupted text with full confidence, which is why
every result carries its tier.

Regenerate after any upstream pull — the data records the commit it was measured against, and
`catalogSummary().fidelityStale` goes true if the loaded checkout has moved since:

```bash
node scripts/probe-fidelity.js            # write the data file
node scripts/probe-fidelity.js --report   # print a summary only
```

### Known upstream defects, surfaced rather than hidden

- `morse` returns an **empty string** for most input. Encode is broken, not just decode. A
  result of `''` from non-empty input gets an explicit warning rather than looking like "your
  text was empty".
- `randomizer` throws under Node — it depends on a browser global the Node loader does not set up.
- `js/emojiData.js` is build-generated and absent from a fresh checkout; emoji-adjacent
  transforms run degraded. Upstream warns to **stderr** about this.

### stdout is protected

Upstream's loader calls `console.warn` during load. That goes to stderr today and is harmless —
but this package is loaded by an MCP server speaking JSON-RPC over stdout, where one stray byte
corrupts the stream and surfaces as an unrelated protocol error. Any stdout write during load is
diverted to stderr rather than trusting upstream never to switch a `warn` to a `log`.

### The load path is not caller-controlled

Upstream's loader evaluates all ~222 transform files through `node:vm` with `export` keywords
stripped. **`node:vm` is not a security boundary.** The set of evaluated files must therefore
never depend on tool input: the root is chosen once from the environment, and no API here accepts
a path or filename.

## API

```js
const bridge = require('@reconlion/parseltongue-bridge');

bridge.catalogSummary();                    // counts, categories, fidelity spread, provenance
bridge.listTransforms({ category, canDecode, fidelity });
bridge.findTransforms('base 64');           // fuzzy, ranked
bridge.runTransform('base64', { action: 'encode', text: 'hi', options: {} });
bridge.autoDecode('QXR0YWNr');              // upstream's detector-based decode
bridge.inspectText(text);                   // hidden characters, homoglyphs, mixed scripts
```

`findTransforms` ports the matching logic from upstream's `agent.py` (exact key, exact name,
token membership, edit distance, token overlap). The natural-language prompt parsing around it is
deliberately **not** ported — MCP callers pass structured arguments, so an English parser would
be dead weight and one more place to guess wrong.

`autoDecode` mirrors upstream's Node decode path, which **stubs out steganography detection**. It
cannot see emoji or invisible-character carriers; `inspectText` covers that gap and every
`autoDecode` result says so in its `limitations`.

`inspectText` is original code, not a port. It reports structure — hidden codepoints, confusables,
mixed scripts, unexpected controls — and never decodes, sanitises, or returns a hidden payload's
contents.
