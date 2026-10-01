#!/usr/bin/env node
'use strict';

const { serveStdio } = require('@modelcontextprotocol/server/stdio');
const { SERVER_NAME, createTransformsServer } = require('./server');

// The transform catalog is built lazily on first tool call, not here: upstream's loader evaluates
// ~222 files through node:vm, and on a Pi that is slow enough to run into a client's startup
// timeout if it happens during protocol negotiation.
const handle = serveStdio(() => createTransformsServer(), {
  onerror(error) {
    process.stderr.write(`[${SERVER_NAME}] ${error.message}\n`);
  },
});

// Some MCP clients spawn the child before writing their initialize request. Keep stdin
// referenced so Node does not exit during that window, and shut down cleanly when the client
// closes the stream.
process.stdin.resume();
process.stdin.once('end', () => {
  handle.close().catch((error) => {
    process.stderr.write(`[${SERVER_NAME}] shutdown: ${error.message}\n`);
  });
});
