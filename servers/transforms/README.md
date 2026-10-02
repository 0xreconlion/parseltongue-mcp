# parseltongue-transforms (MCP server)

**AGPL-3.0-only.** Exposes the Parseltongue transform catalog over MCP stdio. No cryptography, no
network, no writes — every tool is read-only and closed-world.

## Encoding is not encryption

Everything this server does is **representation**. The output is reversible by anyone with no
key. Every encode/decode result carries that statement in its text, because a warning in a README
does not stop anyone treating encoded text as secret.

## Tools

| Tool | What it does |
|---|---|
| `list_transforms` | Catalog with counts by category and by measured decode fidelity |
| `find_transform` | Fuzzy search — "base 64", "rot-13", "hide in emoji" all resolve |
| `run_transform` | Encode / decode / preview, with the fidelity tier attached to the result |
| `auto_decode` | Detect and decode, with alternatives and declared blind spots |
| `inspect_text` | Hidden characters, homoglyphs, mixed scripts, unexpected controls |

Each returns a human-readable text block **and** `structuredContent` JSON. The human path never
depends on a host rendering anything — Claude Code does not render MCP Apps `ui://` resources
([claude-code#95149](https://github.com/anthropics/claude-code/issues/95149)), so the text block
carries the substance.

### Decode fidelity is measured

Upstream's `canDecode` means only "a `reverse()` function exists". Of 185 transforms advertising
decode, only 92 return your text unchanged. Every result therefore carries a tier — `exact`,
`lossy`, `constrained`, `unreliable` — so a decode never arrives without a signal of how much to
trust it. See [`../../packages/parseltongue-bridge/README.md`](../../packages/parseltongue-bridge/README.md).

### `inspect_text` is the one to reach for first

Run it on anything received from someone else *before* acting on it. Invisible characters —
zero-width, Unicode tags, variation selectors, bidi overrides — are how instructions get smuggled
into text that renders as harmless. `auto_decode` cannot see them: upstream's Node decode path
stubs out steganography detection entirely, and says so in every result's `limitations`.

## Register it

```bash
export PARSELTONGUE_ROOT=/path/to/P4RS3LT0NGV3
```

Then in `~/.claude.json` under `mcpServers`:

```json
"parseltongue-transforms": {
  "command": "node",
  "args": ["/absolute/path/to/parseltongue-mcp/servers/transforms/src/index.js"],
  "env": { "PARSELTONGUE_ROOT": "/absolute/path/to/P4RS3LT0NGV3" }
}
```

The catalog is built lazily on first tool call rather than at startup: upstream's loader
evaluates ~222 files through `node:vm`, which on a Pi is slow enough to risk a client's startup
timeout if it happened during protocol negotiation.

## Hosting

If this server is ever exposed over a network, AGPL-3.0 section 13 requires offering
corresponding source to remote users. See [`../../docs/LICENSING.md`](../../docs/LICENSING.md).
