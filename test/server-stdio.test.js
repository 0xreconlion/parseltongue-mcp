'use strict';

/**
 * End-to-end test over real stdio JSON-RPC.
 *
 * Constructing the server object in-process proves almost nothing: the failure modes that matter
 * for an MCP server are protocol-level. Specifically, upstream's transform loader writes a
 * warning during load, and if anything of that kind reaches stdout the JSON-RPC stream is
 * corrupted and the symptom looks like an unrelated protocol error. So this drives the actual
 * child process the way a client does, and asserts stdout stayed clean.
 */

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { after, before, describe, it } = require('node:test');

const SERVER = path.join(__dirname, '..', 'servers', 'transforms', 'src', 'index.js');
const PROTOCOL_VERSION = '2025-06-18';

class Client {
  constructor() {
    this.child = spawn(process.execPath, [SERVER], { stdio: ['pipe', 'pipe', 'pipe'] });
    this.nextId = 1;
    this.buffer = '';
    this.stderr = '';
    this.pending = new Map();
    this.nonJsonStdout = [];

    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', (chunk) => this._onStdout(chunk));
    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', (chunk) => {
      this.stderr += chunk;
    });
  }

  _onStdout(chunk) {
    this.buffer += chunk;
    let index;
    while ((index = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, index).trim();
      this.buffer = this.buffer.slice(index + 1);
      if (!line) continue;

      let message;
      try {
        message = JSON.parse(line);
      } catch {
        // Anything non-JSON on stdout is the bug this test exists to catch.
        this.nonJsonStdout.push(line);
        continue;
      }
      const resolver = this.pending.get(message.id);
      if (resolver) {
        this.pending.delete(message.id);
        resolver(message);
      }
    }
  }

  request(method, params) {
    const id = this.nextId++;
    const promise = new Promise((resolve, reject) => {
      // Clear the timer on resolve. Leaving it armed keeps the event loop alive and makes the
      // whole suite sit idle for the full timeout after the last request.
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout waiting for ${method}; stderr: ${this.stderr}`));
      }, 30000);
      this.pending.set(id, (message) => {
        clearTimeout(timer);
        resolve(message);
      });
    });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    return promise;
  }

  notify(method, params) {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  async initialize() {
    const response = await this.request('initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'parseltongue-stdio-test', version: '0' },
    });
    this.notify('notifications/initialized', {});
    return response;
  }

  async callTool(name, args) {
    const response = await this.request('tools/call', { name, arguments: args });
    assert.ok(!response.error, `${name} errored: ${JSON.stringify(response.error)}`);
    return response.result;
  }

  close() {
    this.child.stdin.end();
    this.child.kill();
  }
}

describe('transforms server over stdio', () => {
  let client;

  before(async () => {
    client = new Client();
    const result = await client.initialize();
    assert.ok(result.result, `initialize failed: ${JSON.stringify(result)}`);
    assert.equal(result.result.serverInfo.name, 'parseltongue-transforms');
  });

  after(() => client && client.close());

  it('advertises exactly the five Phase A tools', async () => {
    const { result } = await client.request('tools/list', {});
    const names = result.tools.map((t) => t.name).sort();
    assert.deepEqual(names, [
      'auto_decode',
      'find_transform',
      'inspect_text',
      'list_transforms',
      'run_transform',
    ]);
  });

  it('marks every tool read-only and closed-world', async () => {
    const { result } = await client.request('tools/list', {});
    for (const tool of result.tools) {
      assert.equal(tool.annotations.readOnlyHint, true, `${tool.name} is not read-only`);
      assert.equal(tool.annotations.destructiveHint, false, `${tool.name} is destructive`);
      // No tool here reaches the network or any resource outside the local catalog.
      assert.equal(tool.annotations.openWorldHint, false, `${tool.name} claims an open world`);
    }
  });

  it('list_transforms returns the catalog with human-readable text', async () => {
    const result = await client.callTool('list_transforms', {});
    assert.ok(result.structuredContent.summary.total > 100);
    const text = result.content[0].text;
    assert.match(text, /Parseltongue catalog: \d+ transforms/);
    // The human path must not depend on a renderer; the text block carries the substance.
    assert.match(text, /NO confidentiality/);
    assert.match(text, /Decode fidelity/);
  });

  it('find_transform resolves a fuzzy query', async () => {
    const result = await client.callTool('find_transform', { query: 'base 64' });
    assert.equal(result.structuredContent.matches[0].key, 'base64');
    assert.match(result.content[0].text, /base64/);
  });

  it('run_transform encodes and states that this is not encryption', async () => {
    const result = await client.callTool('run_transform', {
      transform: 'base64',
      text: 'Attack at dawn',
    });
    assert.equal(result.structuredContent.output, 'QXR0YWNrIGF0IGRhd24=');
    assert.match(result.content[0].text, /NO confidentiality/);
  });

  it('run_transform round-trips through decode', async () => {
    const encoded = (
      await client.callTool('run_transform', { transform: 'base64', text: 'round trip 42' })
    ).structuredContent.output;
    const decoded = await client.callTool('run_transform', {
      transform: 'base64',
      text: encoded,
      action: 'decode',
    });
    assert.equal(decoded.structuredContent.output, 'round trip 42');
  });

  it('run_transform reports an error for an unknown transform instead of dying', async () => {
    const result = await client.callTool('run_transform', { transform: 'nope_not_real', text: 'x' });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /Unknown transform/);
    // The connection must survive a tool-level error.
    const after = await client.callTool('find_transform', { query: 'base64' });
    assert.ok(after.structuredContent.matches.length > 0);
  });

  it('auto_decode identifies base64 and declares its blind spot', async () => {
    const result = await client.callTool('auto_decode', { text: 'QXR0YWNrIGF0IGRhd24=' });
    assert.equal(result.structuredContent.best.text, 'Attack at dawn');
    assert.match(result.content[0].text, /steganograph/i);
  });

  it('inspect_text flags hidden characters in text that looks clean', async () => {
    const result = await client.callTool('inspect_text', { text: 'Pay​​ment to аccount' });
    assert.equal(result.structuredContent.verdict, 'hidden characters present');
    assert.match(result.content[0].text, /zero-width/);
    assert.match(result.content[0].text, /untrusted input/);
  });

  it('kept stdout clean of non-JSON output', () => {
    // Upstream's loader warns during transform load. If that ever lands on stdout instead of
    // stderr it corrupts the JSON-RPC stream, and the failure looks like a protocol bug.
    assert.deepEqual(
      client.nonJsonStdout,
      [],
      `non-JSON written to stdout:\n  ${client.nonJsonStdout.join('\n  ')}`
    );
  });

  it('did write the upstream warning to stderr, proving the test would catch a leak', () => {
    // Positive control for the assertion above: upstream genuinely does emit a warning. If this
    // is silent, the stdout-clean test above is passing vacuously and proves nothing.
    assert.match(
      client.stderr,
      /emojiData|⚠/,
      'expected upstream to warn on stderr during load; without it the stdout-clean ' +
        'assertion above has nothing to distinguish it from a no-op'
    );
  });
});
