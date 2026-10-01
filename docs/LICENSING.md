# Licensing

**This is an engineering risk read, not legal advice.** It records the assumptions this repo is
built on so a future reader does not have to re-derive them. A licensing conclusion that carries
real consequence should be signed by a human, and if this is ever deployed publicly or handed to
a client, reviewed by a lawyer.

## Inbound: upstream P4RS3LT0NGV3 is ambiguous

Checked directly against pinned commit `a6cb7c9` of
`https://github.com/elder-plinius/P4RS3LT0NGV3.git`:

| Source | Declaration |
|---|---|
| `LICENSE` | AGPL-3.0 (stock text, `sha256 8486a10c…2f07ef`) |
| `package.json` | `"license": "MIT"` |
| `README.md` | "This project is open source. See LICENSE file for details" |

These are not compatible claims. The README pointing at the LICENSE file weakly favors AGPL as
the author's intent.

**Assumption this repo is built on: treat upstream as AGPL-3.0.** When inbound terms conflict,
the restrictive reading is the safe one. Do not rely on the MIT line because MIT is more
convenient.

## Outbound: AGPL-3.0, which is safe under *either* reading

The upstream ambiguity does **not** have to block anything downstream, because AGPL-3.0 outbound
is valid whichever reading turns out to be correct:

- If upstream is really MIT — MIT *permits* relicensing a derivative under AGPL-3.0.
- If upstream is really AGPL-3.0 — AGPL-3.0 *requires* it.

So AGPL-3.0 outbound is the safe superset, and the conflict becomes harmless rather than
blocking. There is no need to wait on upstream to resolve it.

What is **not** safe: relicensing this work MIT on the strength of upstream's `package.json`, or
folding Parseltongue-derived code into a proprietary surface.

## The seam

| Path | License | Why |
|---|---|---|
| `packages/capsule-core/` | **Apache-2.0** | Standalone. Zero Parseltongue imports. Reusable outside this repo. |
| `packages/parseltongue-bridge/` | AGPL-3.0-only | The only package that touches upstream source. A derivative. |
| `servers/transforms/` | AGPL-3.0-only | Links the bridge. |
| `servers/capsules/` | AGPL-3.0-only | Links the bridge for capsule inspection. |
| `cli/` | AGPL-3.0-only | Links the bridge. |
| repo root | AGPL-3.0-only | The combined work as shipped. |

The split exists so the capsule cryptography stays reusable. It is only worth anything if it
holds, so it is **enforced, not assumed**:

- `npm run check:seam` fails if anything under `packages/capsule-core/` imports the bridge,
  upstream source, or the transform catalog — by import specifier *or* manifest dependency.
- `npm run check:licenses` fails if any package's `LICENSE` file disagrees with its
  `package.json` — upstream's exact bug, not repeated here.
- Both run under `npm test` and `precommit`. Both fail loudly if they inspected zero files,
  because a guard covering nothing must not report a pass.

## If this is ever hosted

AGPL-3.0 **section 13** is the live obligation, and it is deferred rather than avoided. Section 13
requires that if you modify the program and let remote users interact with it over a network, you
must offer *those users* the corresponding source of your modified version.

- Deploying is the trigger. Keeping it local is not.
- In practice the obligation is satisfied by a prominent "Source" link pointing at a public repo
  containing this exact modified version.
- Private and local use triggers nothing: section 13 attaches to network interaction, sections
  5–6 to distribution.

Hosting is therefore a footer link plus a published repo — not a blocker. It does still want a
hosted threat-model review on its own merits, separately from licensing.

## Open item

Ask upstream which license is authoritative. Costs nothing and resolves the ambiguity
permanently if answered. Not a blocker either way, given the outbound choice above.
