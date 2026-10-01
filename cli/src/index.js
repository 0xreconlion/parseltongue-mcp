#!/usr/bin/env node
'use strict';

/**
 * parseltongue-capsule - the human path.
 *
 * Every operation that touches a passphrase or decrypted plaintext lives here and only here.
 * The MCP server deliberately has no such tool: a passphrase passed as a tool argument would end
 * up in the model's context and the session transcript, and so would any message it decrypted.
 * For a confidentiality tool that is self-defeating, so the split is a security boundary rather
 * than a packaging choice.
 *
 * Works over SSH. Needs no MCP client, which is what makes it the thing you can hand to a
 * recipient.
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const core = require('@reconlion/capsule-core');
const store = require('@reconlion/capsule-core/src/store');
const prompt = require('./prompt');

const PROGRAM = 'parseltongue-capsule';

// `parseltongue-capsule help | head` closes the pipe early, which raises EPIPE on the next write
// and crashes with an unhandled 'error' event. Piping output into head, grep or less is completely
// normal use, so exit quietly instead of dumping a stack trace.
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', (error) => {
    if (error && (error.code === 'EPIPE' || error.code === 'ERR_STREAM_DESTROYED')) process.exit(0);
    throw error;
  });
}

function out(text = '') {
  process.stdout.write(`${text}\n`);
}

function err(text) {
  process.stderr.write(`${text}\n`);
}

function readInput(maybePath) {
  if (maybePath && maybePath !== '-') {
    const resolved = path.resolve(maybePath);
    if (!fs.existsSync(resolved)) throw new Error(`no such file: ${resolved}`);
    return fs.readFileSync(resolved, 'utf8');
  }
  if (process.stdin.isTTY) {
    throw new Error('expected input on stdin or a file path. Use - to read stdin explicitly.');
  }
  return fs.readFileSync(0, 'utf8');
}

function writeOutput(text, destination) {
  if (!destination) {
    out(text);
    return null;
  }
  const resolved = path.resolve(destination);
  fs.writeFileSync(resolved, `${text}\n`, { mode: 0o600 });
  return resolved;
}

function warnPermissions() {
  for (const warning of store.permissionWarnings()) err(`warning: ${warning}`);
}

// ---------------------------------------------------------------- commands

async function cmdInit(args) {
  const label = args.label || '';
  if (store.vaultExists()) {
    throw new Error(
      `an identity already exists at ${store.paths().vault}.\n` +
        'Creating a new one does NOT get you a second identity - it would overwrite the only copy ' +
        'of your private keys and make every capsule ever sealed to you unreadable. Back up first:\n' +
        `  ${PROGRAM} backup --out identity-backup.txt`
    );
  }

  out('Creating a new identity.');
  out('');
  out('This generates two keypairs: Ed25519 for signing (proves you sent something) and X25519');
  out('for encryption (lets others seal messages to you). The private halves are encrypted with');
  out('the passphrase you choose next.');
  out('');
  out('THERE IS NO RECOVERY. Lose this passphrase and every capsule ever sealed to you becomes');
  out('permanently unreadable. No reset, no escrow, by design.');
  out('');

  const passphrase = await prompt.newPassphrase('Vault passphrase', core.MIN_PASSPHRASE_LENGTH);

  const identity = core.createIdentity({ label });
  out('');
  out('Deriving the vault key (Argon2id, deliberately slow)...');
  const record = core.createVault({ identity, passphrase });
  const file = store.saveVault(record);

  out('');
  out(`Identity created: ${file}`);
  out(`  label:                  ${identity.public.label || '(unnamed)'}`);
  out(`  signing fingerprint:    ${identity.public.signFingerprint}`);
  out(`  encryption fingerprint: ${identity.public.encryptFingerprint}`);
  out('');
  out('Next, two things in this order:');
  out(`  1. ${PROGRAM} backup --out identity-backup.txt   <- do this NOW, store it offline`);
  out(`  2. ${PROGRAM} card                               <- share this so people can write to you`);
  warnPermissions();
}

async function cmdCard(args) {
  const publicIdentity = store.publicIdentity();
  if (!publicIdentity) throw new Error(`no identity yet. Run: ${PROGRAM} init`);

  const card = core.exportContactCard(publicIdentity);
  const written = writeOutput(card.card, args.out);
  if (written) out(`contact card written to ${written}`);
  if (!args.quiet) {
    err('');
    err('This is public. Share it anywhere. It cannot decrypt anything.');
    err('Have the recipient confirm these fingerprints with you by voice or in person:');
    err(`  signing:    ${card.fingerprints.sign}`);
    err(`  encryption: ${card.fingerprints.encrypt}`);
  }
}

async function cmdAddContact(args) {
  const name = args._[0];
  if (!name) throw new Error(`usage: ${PROGRAM} add-contact <name> [file]`);

  const text = readInput(args._[1] || args.file);
  const { contact, checksumOk, warnings } = core.importContactCard(text);
  const result = store.putContact(name, contact, { allowReplace: Boolean(args.replace) });

  out(`contact "${result.key}" ${result.status}`);
  out(`  label:                  ${contact.label || '(unnamed)'}`);
  out(`  signing fingerprint:    ${contact.signFingerprint}`);
  out(`  encryption fingerprint: ${contact.encryptFingerprint}`);
  out('');
  if (!checksumOk) for (const warning of warnings) err(`warning: ${warning}`);
  out('Confirm those fingerprints with them over a channel you already trust. A contact card');
  out('proves nothing on its own - anyone can make one claiming any name.');
}

async function cmdContacts() {
  const contacts = store.listContacts();
  if (contacts.length === 0) {
    out(`no contacts yet. Add one: ${PROGRAM} add-contact <name> card.txt`);
    return;
  }
  out(`${contacts.length} contact(s):`);
  for (const contact of contacts) {
    out(`  ${contact.key.padEnd(20)} ${contact.encryptFingerprint}  ${contact.label || ''}`);
  }
}

async function cmdSeal(args) {
  const to = args.to || args._[0];
  if (!to) throw new Error(`usage: ${PROGRAM} seal --to <contact> [--message <text> | --in <file>]`);

  const contact = store.getContact(to);
  const payload = args.message !== undefined ? String(args.message) : readInput(args.in || args._[1]);
  if (!payload.trim()) throw new Error('refusing to seal an empty message');

  const meta = {};
  if (args.subject) meta.subject = String(args.subject);

  const record = store.loadVault();
  const passphrase = await prompt.passphrase('Vault passphrase');
  err('Unlocking (Argon2id)...');
  const unlocked = core.unlockVault(record, passphrase);

  const sealed = core.sealCapsule({
    senderSecret: unlocked.secret,
    senderPublic: unlocked.public,
    recipientContact: contact,
    payload,
    meta,
  });

  const written = writeOutput(sealed.envelope, args.out);
  if (written) out(`capsule written to ${written}`);

  err('');
  err(`Sealed to ${contact.label || to} (${contact.encryptFingerprint}).`);
  err('');
  err('VISIBLE to anyone who intercepts this capsule:');
  err(`  your signing key   ${sealed.visible.senderFingerprint}`);
  err(`  recipient key      ${sealed.visible.recipientFingerprint}`);
  err(`  timestamp          ${sealed.visible.created}`);
  err(`  metadata           ${JSON.stringify(sealed.visible.metadata)}`);
  err(`  approximate length of your message`);
  err('');
  err('ENCRYPTED: the message body, and nothing else.');
  err('');
  err('Send it through any channel. Encoding or obfuscating it further adds no secrecy.');
}

async function cmdOpen(args) {
  const text = readInput(args.in || args._[0]);

  // Pre-flight inspection needs no keys, so show the structure before asking for a passphrase.
  const inspection = core.inspectCapsule(text);
  if (!inspection.wellFormed) {
    throw new Error(`not a readable capsule: ${inspection.error || 'malformed'}`);
  }
  if (inspection.signatureVerifies === false) {
    err('WARNING: this capsule\'s signature does not verify. It was altered after sealing, or was');
    err('not sealed by the key it claims. Opening it anyway is not advisable.');
    if (!(await prompt.confirm('Attempt to open it regardless?'))) {
      out('aborted');
      return;
    }
  }

  const record = store.loadVault();
  const passphrase = await prompt.passphrase('Vault passphrase');
  err('Unlocking (Argon2id)...');
  const unlocked = core.unlockVault(record, passphrase);

  let expectedSender = null;
  if (args.from) expectedSender = store.getContact(args.from);

  const opened = core.openCapsule({
    capsule: text,
    recipientSecret: unlocked.secret,
    expectedSenderContact: expectedSender,
  });

  // Plaintext to stdout only. It is never returned through an agent, never logged, never stored.
  err('');
  err(`--- message (capsule ${opened.capsuleId}) ---`);
  out(opened.payload);
  err('--- end message ---');
  err('');
  err(`sender signature: VERIFIED against ${opened.sender.fingerprint}`);
  if (opened.sender.matchesExpected === true) {
    err(`sender identity:  matches your contact "${args.from}"`);
  } else if (opened.sender.matchesExpected === false) {
    err(`sender identity:  DOES NOT MATCH contact "${args.from}" - treat as unknown`);
  } else {
    err('sender identity:  unconfirmed. The signature proves which KEY sealed this, not who holds');
    err(`                  it. Re-run with --from <contact> to check it against someone you know.`);
  }
  if (Object.keys(opened.meta).length) err(`visible metadata: ${JSON.stringify(opened.meta)}`);
}

async function cmdInspect(args) {
  const text = readInput(args.in || args._[0]);
  const report = core.inspectCapsule(text);

  out(`well formed:        ${report.wellFormed}`);
  if (!report.wellFormed) {
    out(`error:              ${report.error || 'malformed'}`);
    return;
  }
  out(`capsule id:         ${report.capsuleId}`);
  out(`signature verifies: ${report.signatureVerifies}`);
  out('');
  out('VISIBLE:');
  for (const [key, value] of Object.entries(report.visible)) {
    out(`  ${key.padEnd(22)} ${typeof value === 'object' ? JSON.stringify(value) : value}`);
  }
  out('');
  out('ENCRYPTED:');
  out(`  ciphertext bytes       ${report.encrypted.ciphertextBytes}`);
  out(`  approx plaintext bytes ${report.encrypted.approximatePlaintextBytes}`);
  out('');
  for (const finding of report.findings) out(`  [${finding.severity}] ${finding.detail}`);
  out('');
  for (const note of report.notes) out(`  - ${note}`);
}

async function cmdBackup(args) {
  const record = store.loadVault();
  out('Backing up your identity. The result contains your PRIVATE KEYS, passphrase-wrapped.');
  out('');
  const passphrase = await prompt.passphrase('Current vault passphrase');
  err('Unlocking...');
  const unlocked = core.unlockVault(record, passphrase);

  out('');
  out('Now choose a passphrase for the BACKUP. Make it different and longer - this file may');
  out('outlive this machine, and it should be written down somewhere physical.');
  const backupPassphrase = await prompt.newPassphrase('Backup passphrase', core.MIN_BACKUP_PASSPHRASE);

  // Include the contact book. Public keys, so no new secret in the file - but without it a
  // restore loses every contact, and sender verification quietly degrades to "unconfirmed".
  const contactBook = store.loadContacts();
  const contactCount = Object.keys(contactBook.contacts || {}).length;

  err('Deriving the backup key (deliberately slower than the vault)...');
  const backup = core.exportIdentityBackup({
    secret: unlocked.secret,
    publicIdentity: unlocked.public,
    passphrase: backupPassphrase,
    contacts: contactCount > 0 ? contactBook : null,
  });

  const written = writeOutput(backup.text, args.out);
  out('');
  if (written) out(`backup written to ${written} (mode 0600)`);
  out(`  includes: private keys + ${contactCount} contact(s)`);
  out('');
  out(`!! ${backup.warning}`);
  out('');
  out('Verify the backup actually works before you rely on it:');
  out(`  ${PROGRAM} verify-backup --in ${args.out || 'identity-backup.txt'}`);
}

async function cmdVerifyBackup(args) {
  const text = readInput(args.in || args._[0]);
  const passphrase = await prompt.passphrase('Backup passphrase');
  err('Deriving...');
  const restored = core.importIdentityBackup({ backup: text, passphrase });

  const live = store.publicIdentity();
  out('');
  out('backup decrypts: yes');
  out(`  signing fingerprint:    ${restored.public.signFingerprint}`);
  out(`  encryption fingerprint: ${restored.public.encryptFingerprint}`);
  if (live) {
    const matches = live.sign === restored.public.sign && live.encrypt === restored.public.encrypt;
    out(`  matches current identity: ${matches ? 'yes' : 'NO - this backup is for a different identity'}`);
  }
  out('');
  out('This backup can restore your identity. Keep it offline.');
}

async function cmdRestore(args) {
  if (store.vaultExists() && !args.force) {
    throw new Error(
      `an identity already exists at ${store.paths().vault}. Restoring would overwrite it.\n` +
        'Move it aside first, or pass --force if you are certain the existing one is expendable.'
    );
  }

  const text = readInput(args.in || args._[0]);
  const backupPassphrase = await prompt.passphrase('Backup passphrase');
  err('Deriving...');
  const restored = core.importIdentityBackup({ backup: text, passphrase: backupPassphrase });

  out('');
  out(`restoring identity ${restored.public.signFingerprint}`);
  out('Choose a vault passphrase for this machine.');
  const vaultPassphrase = await prompt.newPassphrase('Vault passphrase', core.MIN_PASSPHRASE_LENGTH);

  err('Deriving the vault key...');
  const record = core.createVault({
    identity: { public: restored.public, secret: restored.secret },
    passphrase: vaultPassphrase,
  });
  const file = store.saveVault(record, { allowOverwrite: Boolean(args.force) });

  // Restore the contact book too, if the backup carried one. Without it, sender verification
  // silently falls back to "unconfirmed" on a restored machine.
  let restoredContacts = 0;
  if (restored.contacts && restored.contacts.contacts) {
    store.saveContacts(restored.contacts);
    restoredContacts = Object.keys(restored.contacts.contacts).length;
  }

  out('');
  out(`identity restored to ${file}`);
  out(`  signing fingerprint:    ${restored.public.signFingerprint}`);
  out(`  encryption fingerprint: ${restored.public.encryptFingerprint}`);
  out(`  contacts restored:      ${restoredContacts}`);
  if (restoredContacts === 0) {
    out('');
    out('This backup carried no contacts, so sender verification will report "unconfirmed" until');
    out(`you re-import their cards: ${PROGRAM} add-contact <name> <file>`);
  }
  warnPermissions();
}

async function cmdPassphrase() {
  const record = store.loadVault();
  const current = await prompt.passphrase('Current vault passphrase');
  err('Unlocking...');
  core.unlockVault(record, current); // verify before asking for the new one
  const next = await prompt.newPassphrase('New vault passphrase', core.MIN_PASSPHRASE_LENGTH);
  err('Re-encrypting...');
  const updated = core.changeVaultPassphrase(record, current, next);
  store.saveVault(updated, { allowOverwrite: true });
  out('vault passphrase changed.');
  out('Existing backups still use their own passphrase and are unaffected.');
}

async function cmdStatus() {
  const { root, vault, contacts } = store.paths();
  const publicIdentity = store.publicIdentity();

  out(`home:      ${root}`);
  out(`vault:     ${fs.existsSync(vault) ? vault : '(none)'}`);
  out(`contacts:  ${fs.existsSync(contacts) ? `${store.listContacts().length} stored` : '(none)'}`);
  out('');
  if (publicIdentity) {
    out('identity (public half, readable without a passphrase):');
    out(`  label:                  ${publicIdentity.label || '(unnamed)'}`);
    out(`  signing fingerprint:    ${publicIdentity.signFingerprint}`);
    out(`  encryption fingerprint: ${publicIdentity.encryptFingerprint}`);
  } else {
    out(`no identity yet. Run: ${PROGRAM} init`);
  }
  const warnings = store.permissionWarnings();
  if (warnings.length) {
    out('');
    for (const warning of warnings) out(`warning: ${warning}`);
  }
}

async function cmdWizard(args) {
  const file = path.join(__dirname, '..', '..', 'wizard', 'wizard.html');
  if (!fs.existsSync(file)) throw new Error(`wizard not found at ${file}`);
  out(`wizard: ${file}`);
  if (args['no-open']) return;

  const opener = process.platform === 'darwin' ? 'open' : 'xdg-open';
  const child = spawn(opener, [file], { detached: true, stdio: 'ignore' });
  child.on('error', () => {
    err(`could not launch ${opener}. Open this file in a browser yourself:`);
    err(`  ${file}`);
  });
  child.unref();
}

function cmdHelp() {
  out(`${PROGRAM} - local secure message capsules`);
  out('');
  out('Encoding is not encryption. Parseltongue transforms change how text looks and provide no');
  out('secrecy. These commands are the part that actually makes a message unreadable.');
  out('');
  out('Setup');
  out('  init [--label <name>]              create an identity (asks for a passphrase)');
  out('  backup --out <file>                passphrase-wrapped copy of your private keys');
  out('  verify-backup --in <file>          prove a backup actually restores');
  out('  restore --in <file>                rebuild an identity from a backup');
  out('  passphrase                         change the vault passphrase');
  out('');
  out('Contacts');
  out('  card [--out <file>]                your public contact card - share this');
  out('  add-contact <name> [file]          import someone else\'s card');
  out('  contacts                           list imported contacts');
  out('');
  out('Messages');
  out('  seal --to <contact> [--message <text> | --in <file>] [--subject <s>] [--out <file>]');
  out('  open [--in <file>] [--from <contact>]');
  out('  inspect [--in <file>]              structure and signature, no passphrase needed');
  out('');
  out('Other');
  out('  status                             what exists on this machine');
  out('  wizard                             open the offline inspector in a browser');
  out('');
  out('Passphrases are typed at this terminal and never pass through an agent or a transcript.');
  out('Decrypted messages print here only. That is deliberate: a secure message piped through a');
  out('model\'s context is no longer secure.');
}

// ---------------------------------------------------------------- arg parsing

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        args[key] = true;
      } else {
        args[key] = next;
        i += 1;
      }
    } else {
      args._.push(token);
    }
  }
  return args;
}

const COMMANDS = {
  init: cmdInit,
  card: cmdCard,
  'add-contact': cmdAddContact,
  contacts: cmdContacts,
  seal: cmdSeal,
  open: cmdOpen,
  inspect: cmdInspect,
  backup: cmdBackup,
  'verify-backup': cmdVerifyBackup,
  restore: cmdRestore,
  passphrase: cmdPassphrase,
  status: cmdStatus,
  wizard: cmdWizard,
};

async function main() {
  const [command, ...rest] = process.argv.slice(2);

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    cmdHelp();
    return 0;
  }

  const handler = COMMANDS[command];
  if (!handler) {
    err(`unknown command: ${command}`);
    err(`try: ${PROGRAM} help`);
    return 2;
  }

  try {
    await handler(parseArgs(rest));
    return 0;
  } catch (error) {
    err(`error: ${error.message}`);
    return 1;
  }
}

if (require.main === module) {
  main().then((code) => process.exit(code));
}

module.exports = { main, parseArgs };
