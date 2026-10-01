# parseltongue-mcp

Two MCP servers, one repo.

1. **`parseltongue-transforms`** — the [P4RS3LT0NGV3](https://github.com/elder-plinius/P4RS3LT0NGV3)
   transform catalog, made agent-callable. Encode, decode, auto-detect, and inspect text.
   No cryptography in it.
2. **`parseltongue-capsules`** — local secure message capsules: create an identity, exchange
   public contact cards, seal a message to a recipient, send it through any channel you already
   use, open and verify it locally. *(Phase B — not implemented, not registered.)*

Everything is local. There is no relay, no account system, no hosted decrypt, and no outbound
network capability in either server.

## Encoding is not encryption

This is the one thing the tool is built to make unmissable.

The 200-plus Parseltongue transforms — base64, ciphers, Unicode styling, zero-width
concealment, steganography — are **representation**. They change how text looks. They provide
**zero confidentiality**: anything encoded can be decoded by anyone, with no key.

Confidentiality comes only from the capsule layer: X25519 key agreement, XChaCha20-Poly1305
authenticated encryption, Ed25519 signatures. Separate package, separate server, separate
license.

Running a sealed capsule through a concealment transform does not make it *more* secret, and
this tool says so out loud rather than leaving it in a README: `inspect_capsule` reports a
concealment wrapper explicitly and states that it adds no confidentiality.

## Status

| Component | State |
|---|---|
| `packages/parseltongue-bridge` | Phase A — in progress |
| `servers/transforms` | Phase A — in progress |
| `packages/capsule-core` | Phase B — surface declared, not implemented |
| `servers/capsules` | Phase B — not implemented, do not register |
| `cli/`, `wizard/` | Phase B — not implemented |

The capsule server does not get registered until a security review has run and the key-leak test
passes. The transform server has no crypto in it and carries no such gate.

## Licensing

- `packages/capsule-core` — **Apache-2.0**, standalone, zero Parseltongue imports
- everything else, and the repo as a whole — **AGPL-3.0-only**

Upstream P4RS3LT0NGV3 declares AGPL-3.0 in its `LICENSE` and MIT in its `package.json`. This repo
assumes the restrictive reading and ships AGPL-3.0, which is valid under either. The seam is
enforced by `npm run check:seam` and `npm run check:licenses`, not by convention.

Full reasoning, and what AGPL section 13 would require if this is ever hosted:
[`docs/LICENSING.md`](docs/LICENSING.md).

## Requirements

Node >= 20 (developed on v24). No Python — upstream's Python CLI requires >= 3.12 and shells out
to Node anyway; the bridge calls the Node transform loader directly.

## Setup

The upstream Parseltongue checkout is **not** vendored here. Point the bridge at a local clone:

```bash
export PARSELTONGUE_ROOT=/path/to/P4RS3LT0NGV3
npm install
npm test
```

## Tests

```bash
npm test              # seam guard + license consistency + unit tests
npm run check:seam    # Apache-2.0 boundary of capsule-core
```

Both guards fail loudly if they inspect zero files. A check that covered nothing is not a pass.
