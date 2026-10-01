'use strict';

/**
 * On-disk persistence for vaults, contacts and capsules.
 *
 * Deliberately a SEPARATE module that none of the crypto modules import. capsule.js, vault.js,
 * identity.js and backup.js stay pure functions over records, which keeps path handling - a
 * classic place to get traversal wrong - out of the cryptography. This module is the only place
 * that touches the filesystem.
 *
 * Layout, under PARSELTONGUE_HOME (default ~/.local/share/parseltongue):
 *
 *   identity.json      the vault: passphrase-wrapped private keys, 0600
 *   contacts.json      imported public contact cards, 0600 (public data, but it is a social graph)
 *   capsules/          optional saved capsules, 0700
 *
 * Names supplied by callers are slug-restricted rather than path-joined, so "../../etc/passwd"
 * cannot become a filename.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

class StoreError extends Error {}

function home() {
  const configured = process.env.PARSELTONGUE_HOME;
  if (configured) return path.resolve(configured);
  return path.join(os.homedir(), '.local', 'share', 'parseltongue');
}

function paths() {
  const root = home();
  return {
    root,
    vault: path.join(root, 'identity.json'),
    contacts: path.join(root, 'contacts.json'),
    capsules: path.join(root, 'capsules'),
  };
}

function ensureRoot() {
  const { root } = paths();
  fs.mkdirSync(root, { recursive: true, mode: DIR_MODE });
  // mkdirSync's mode is subject to umask; set it explicitly so a permissive umask cannot leave
  // the directory group- or world-readable.
  try {
    fs.chmodSync(root, DIR_MODE);
  } catch {
    /* best effort on exotic filesystems */
  }
  return root;
}

function writePrivateJson(file, value) {
  ensureRoot();
  const tmp = `${file}.tmp-${process.pid}`;
  // Create with restrictive permissions from the outset rather than widening then narrowing -
  // otherwise there is a window where the file is readable.
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: FILE_MODE });
  fs.chmodSync(tmp, FILE_MODE);
  fs.renameSync(tmp, file);
  return file;
}

function readJson(file) {
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new StoreError(`${file} is not readable JSON: ${err.message}`);
  }
}

/** Warn if a file that should be private is readable by anyone else. */
function permissionWarnings() {
  const warnings = [];
  const { vault, contacts, root } = paths();
  for (const [label, file] of [['vault', vault], ['contacts', contacts], ['directory', root]]) {
    if (!fs.existsSync(file)) continue;
    const mode = fs.statSync(file).mode & 0o777;
    if (mode & 0o077) {
      warnings.push(
        `${label} at ${file} has mode ${mode.toString(8)}; it is readable beyond your user. ` +
          `Run: chmod ${label === 'directory' ? '700' : '600'} ${file}`
      );
    }
  }
  return warnings;
}

// ---------- vault ----------

function vaultExists() {
  return fs.existsSync(paths().vault);
}

function loadVault() {
  const record = readJson(paths().vault);
  if (!record) throw new StoreError('no identity yet. Run: parseltongue-capsule init');
  return record;
}

function saveVault(record, { allowOverwrite = false } = {}) {
  const { vault } = paths();
  if (fs.existsSync(vault) && !allowOverwrite) {
    throw new StoreError(
      `${vault} already exists. Overwriting it would destroy the only copy of your private keys ` +
        'and make every capsule ever sealed to you permanently unreadable. Move it aside first if ' +
        'you really mean to replace it.'
    );
  }
  return writePrivateJson(vault, record);
}

/** The public half, readable without a passphrase. */
function publicIdentity() {
  if (!vaultExists()) return null;
  const record = loadVault();
  return record.identity || null;
}

// ---------- contacts ----------

function loadContacts() {
  return readJson(paths().contacts) || { v: 1, contacts: {} };
}

function saveContacts(book) {
  return writePrivateJson(paths().contacts, book);
}

/** Contact names become filenames nowhere, but they are still slug-restricted as a key. */
function normaliseName(name) {
  if (typeof name !== 'string') throw new StoreError('contact name must be a string');
  const slug = name.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  if (!slug) throw new StoreError('contact name must contain at least one letter or digit');
  if (slug.length > 64) throw new StoreError('contact name must be 64 characters or fewer');
  return slug;
}

function putContact(name, contact, { allowReplace = false } = {}) {
  const book = loadContacts();
  const key = normaliseName(name);
  const existing = book.contacts[key];

  if (existing && !allowReplace) {
    if (existing.sign === contact.sign && existing.encrypt === contact.encrypt) {
      return { key, status: 'unchanged', contact: existing };
    }
    throw new StoreError(
      `contact "${key}" already exists with DIFFERENT keys (stored signing fingerprint ` +
        `${existing.signFingerprint}, new ${contact.signFingerprint}). This is either a genuine ` +
        'key rotation or someone substituting their key for theirs. Confirm with them out of ' +
        'band, then re-import with replace enabled.'
    );
  }

  book.contacts[key] = {
    label: contact.label || '',
    sign: contact.sign,
    encrypt: contact.encrypt,
    signFingerprint: contact.signFingerprint,
    encryptFingerprint: contact.encryptFingerprint,
    id: contact.id,
    importedAt: new Date().toISOString(),
  };
  saveContacts(book);
  return { key, status: existing ? 'replaced' : 'added', contact: book.contacts[key] };
}

function getContact(name) {
  const book = loadContacts();
  const key = normaliseName(name);
  const contact = book.contacts[key];
  if (!contact) {
    const known = Object.keys(book.contacts);
    throw new StoreError(
      `no contact named "${key}"` +
        (known.length ? `. Known contacts: ${known.join(', ')}` : '. Add one with: parseltongue-capsule add-contact')
    );
  }
  return contact;
}

function listContacts() {
  const book = loadContacts();
  return Object.entries(book.contacts).map(([key, contact]) => ({ key, ...contact }));
}

function removeContact(name) {
  const book = loadContacts();
  const key = normaliseName(name);
  if (!book.contacts[key]) throw new StoreError(`no contact named "${key}"`);
  delete book.contacts[key];
  saveContacts(book);
  return key;
}

module.exports = {
  DIR_MODE,
  FILE_MODE,
  StoreError,
  ensureRoot,
  getContact,
  home,
  listContacts,
  loadContacts,
  loadVault,
  normaliseName,
  paths,
  permissionWarnings,
  publicIdentity,
  putContact,
  removeContact,
  saveContacts,
  saveVault,
  vaultExists,
};
