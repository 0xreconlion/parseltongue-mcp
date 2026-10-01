# parseltongue-mcp

Hide an encrypted message inside one that looks completely ordinary.

```
you send:   "Hey! Running late, see you at the thing 🙂"      ← what they see
you also:   gray-dock-perch-8937-garlic-poem-cobra           ← the code, sent a DIFFERENT way
they get:   east gate, 0400                                   ← the message underneath
```

Two MCP servers, one repo.

1. **`parseltongue-transforms`** — the [P4RS3LT0NGV3](https://github.com/elder-plinius/P4RS3LT0NGV3)
   transform catalog, made agent-callable. Encode, decode, auto-detect, and inspect text.
   No cryptography in it.
2. **`parseltongue-capsules`** — local secure message capsules: create an identity, exchange
   public contact cards, seal a message to a recipient, send it through any channel you already
   use, open and verify it locally.

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
| `packages/parseltongue-bridge` | live — 222 transforms, fidelity measured |
| `servers/transforms` | live — 5 tools |
| `packages/capsule-core` | live — X25519 / Ed25519 / XChaCha20-Poly1305 / Argon2id |
| `servers/capsules` | live — 7 tools, none of which can hold a secret |
| `cli/parseltongue-capsule` | live — all passphrase and plaintext handling |
| `wizard/index.html` | live — explainer + offline checker, zero dependencies |
| sealed notes (shared code) | live — `conceal_message` / `reveal_message`, no identity needed |

104 tests. Security review notes, including what was found and fixed, are in
[`docs/SECURITY.md`](docs/SECURITY.md). It is a self-review, not an external audit.

## The CLI is a security boundary

There is no `seal_capsule` or `open_capsule` MCP tool, deliberately. A passphrase passed as a tool
argument travels through the model's context and into the session transcript — and so does a
decrypted message returned from one. For a confidentiality tool that is self-defeating.

So the MCP server inspects, verifies, explains, and manages public contacts. Everything touching a
passphrase or plaintext is `parseltongue-capsule` at a terminal, which reads passphrases from a
TTY and prints messages nowhere else.

## Two modes

| | Shared code (sealed notes) | Identity (capsules) |
|---|---|---|
| Setup | **none** | create identity, exchange cards, verify fingerprints |
| Proves who sent it | no | **yes**, Ed25519 signature |
| Hides that it exists | **yes**, invisible carrier | no, obviously a capsule |
| Use when | two people can agree a code | authorship matters |

## Hidden messages — the short path

```bash
parseltongue-capsule styles                    # carrier options
parseltongue-capsule conceal --in secret.txt \
    --cover "running late, see you there" --out message.txt
parseltongue-capsule reveal --in message.txt   # asks for the code
```

Or as MCP tools: `conceal_options` → `conceal_message` → `reveal_message`.

**Send the code by a different route than the message.** If both travel the same way, anyone
reading that channel reads the message and the encryption bought you nothing. That is the whole
security of the scheme and the realistic way it fails.

Carrier styles, measured:

| Style | Cover text | They see | Size |
|---|---|---|---|
| `invisible` (default) | yes | only your cover message | 1× |
| `zerowidth` | yes | only your cover message | 4× |
| `emoji` | **no** | a string of emoji | 1× |

`emoji` cannot take cover text — its decoder consumes every emoji it is given, including any in
your cover, which corrupts the payload.

## Quick start

```bash
parseltongue-capsule init --label "Your Name"
parseltongue-capsule backup --out identity-backup.txt     # there is no recovery
parseltongue-capsule verify-backup --in identity-backup.txt
parseltongue-capsule card --out my-card.txt               # share this

parseltongue-capsule add-contact alice alice-card.txt     # confirm fingerprints by voice
parseltongue-capsule seal --to alice --message "..." --out capsule.txt
parseltongue-capsule open --in capsule.txt --from alice
parseltongue-capsule wizard                               # offline inspector in a browser
```

## Licensing

- `packages/capsule-core` — **Apache-2.0**, standalone, zero Parseltongue imports
- everything else, and the repo as a whole — **AGPL-3.0-only**

Upstream P4RS3LT0NGV3 declares AGPL-3.0 in its `LICENSE` and MIT in its `package.json`. This repo
assumes the restrictive reading and ships AGPL-3.0, which is valid under either. The seam is
enforced by `npm run check:seam` and `npm run check:licenses`, not by convention.

Full reasoning, and what AGPL section 13 would require if this is ever hosted:
[`docs/LICENSING.md`](docs/LICENSING.md).

## Hosting

**Do not host the MCP server.** Hosting it means the operator's machine derives the key and holds
every user's plaintext — which makes every local-first claim in this README false. The crypto
would port to a Worker; the transform catalog would not (`node:vm`). Neither fact changes the
answer.

Host `wizard/index.html` instead: one self-contained file, all work in the visitor's browser,
nothing reaching a server. Reasoning and the deployment path in
[`docs/HOSTING.md`](docs/HOSTING.md).

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
npm test               # all guards + 104 tests
npm run check:all      # seam + license consistency + artifact guard
npm run check:secrets  # no vault/backup/capsule anywhere in the tree
```

Both guards fail loudly if they inspect zero files. A check that covered nothing is not a pass.
