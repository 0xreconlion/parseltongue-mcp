# Hosting

Assessed 2026-10-01 against the actual code, not from intent.

## The short version

**Do not host the MCP server. Host the HTML page.**

Those are different artifacts with opposite risk profiles, and the obvious-sounding move — put the
MCP server on a Worker so people can "just use it" — is the one that breaks the product.

---

## Why hosting the MCP server destroys the thing

The sealed-note flow has exactly two secrets: the decrypt code, and the plaintext. Hosting the
server means both cross the network to a machine you operate:

```
hosted:  user → [ your server: derives the key, decrypts, holds the plaintext ] → user
local:   user → [ their own machine ] → user
```

In the hosted shape **the operator can read every message every user sends**. Not through a bug —
by design, because that is where the decryption happens. Everything the tool says about
local-first, no relay, and no server that could read it becomes false the moment it is hosted.

It is also a liability you would be volunteering for. A tool people use for "secure secret
communications" that silently routes their plaintext through your Worker is worse than no tool,
because they would be acting on a guarantee that no longer holds.

MCP servers are normally local anyway: stdio, spawned by the client. Distribution is the
install, not a URL.

## What is technically portable, for the record

Measured by auditing Node API usage per file:

| Package | Node APIs used | Runs on Workers? |
|---|---|---|
| `capsule-core` crypto (`sealed`, `capsule`, `vault`, `backup`) | `node:crypto` only | **yes**, with a `getRandomValues` shim |
| `capsule-core/codec`, `identity`, `wordlist` | none | yes |
| `capsule-core/store` | `fs`, `os`, `path` | no — and it is optional, local persistence only |
| `parseltongue-bridge/loader`, `registry`, `run` | `fs`, `path`, **`node:vm`** | **no** — Workers has no `node:vm` |

So the crypto would port with little effort. The transform catalog would not: it evaluates ~222
upstream files through `node:vm`, which does not exist in a Worker. Hosting the transform half
would need a build step that bundles the catalog — real work, for a capability nobody is asking
to be remote.

**None of that changes the recommendation.** "Could it run there" and "should it run there" are
different questions, and the second one is already answered.

## What to host instead

`wizard/index.html` — a single self-contained file. No `<script src>`, no `<link href>`, no
`fetch`, no fonts, no analytics; a test asserts all of that so it cannot regress. It explains the
flow, shows what is and is not protected, and does real work: paste a message and it finds the
invisible characters, extracts a concealed sealed note, and tells you what you are holding.

All of it runs in the visitor's browser. **Nothing reaches the server, so there is nothing to
hold and nothing to leak.** The page is deliberately unable to decrypt, and deliberately has no
"hide my text" button — concealment without encryption is reversible by anyone, and a button
offering it would be used by people who believed it made them safe.

### Deploying it

It is one static file, so any static host works. On the existing Cloudflare setup the cheapest
path is to drop it into the Astro site's `public/` directory and let the current build publish
it; nothing new to provision, no Worker, no bindings, no secrets.

### AGPL section 13

Serving this page triggers section 13: remote users interacting with a modified AGPL work must be
offered the corresponding source. In practice that is a visible "Source" link to a public
repository containing this exact version. The footer already carries the license line and the
upstream credit — add the source link when the repository goes public.

Note the ordering this implies: **the page should not be hosted before the repository is public**,
or the §13 obligation is live with nothing to point at. That is the one real sequencing constraint.

## If a remote MCP server is ever genuinely wanted

The only version that would not undermine the product is one that handles **no secrets at all** —
the transform catalog, `inspect_text`, the explanation tools. Useful, harmless, and still blocked
on bundling the catalog to escape `node:vm`.

A remote server that seals or opens anything is not a variant of this tool. It is a different
product with a different threat model, and it should be named differently so nobody assumes the
guarantees carry over.

## Distribution, which is the actual question

What people need is not a URL, it is an install:

- `git clone` plus `npm install`, then register the stdio server in their MCP client
- `parseltongue-capsule` on their PATH for the no-transcript path
- the hosted page as the thing you link when explaining it

That keeps every secret on the machine that owns it, which is the entire premise.
