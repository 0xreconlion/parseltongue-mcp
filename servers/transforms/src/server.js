'use strict';

/**
 * MCP server over the Parseltongue transform catalog. AGPL-3.0-only (links the AGPL bridge).
 *
 * Follows the house pattern from reconlion-operator/mcp-knowledge-ops: McpServer from
 * @modelcontextprotocol/server, zod input schemas, explicit annotations per tool, and all logic
 * in a package rather than here.
 *
 * Two deliberate departures from that pattern:
 *
 *  1. `content` carries a HUMAN-READABLE summary and `structuredContent` carries the JSON, rather
 *     than JSON in both. These tools get read by a person as often as by an agent, and no part of
 *     the human path is allowed to depend on a host feature that may not render.
 *
 *  2. Every encode/decode result carries a one-line banner stating that transforms provide no
 *     confidentiality. Making that mechanical rather than documentary is the point — a README
 *     nobody reads does not stop anyone treating encoded text as secret.
 *
 * There is no network capability here, no filesystem path accepted from any caller, and nothing
 * writeable. Every tool is read-only.
 */

const { McpServer } = require('@modelcontextprotocol/server');
const { z } = require('zod');

const bridge = require('@reconlion/parseltongue-bridge');

const SERVER_NAME = 'parseltongue-transforms';
const SERVER_VERSION = '0.1.0';

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

const NOT_ENCRYPTION =
  'Representation only - this provides NO confidentiality. Anyone can reverse it without a key.';

const FIDELITY_MEANING = {
  exact: 'decode returns your text byte for byte',
  lossy: 'decode recovers the text but drops case, spacing and/or digits',
  constrained: 'decode works for some input shapes and corrupts others - see safeFor',
  encode_only: 'no decode available',
  unreliable: 'decode does not recover the input; treat as encode-only',
  error: 'broken upstream',
  unmeasured: 'fidelity not measured - run scripts/probe-fidelity.js',
};

/** Human text first, JSON second. */
function reply(text, data) {
  return {
    content: [{ type: 'text', text }],
    structuredContent: data,
  };
}

function failure(error) {
  const message = error instanceof Error ? error.message : String(error);
  return {
    content: [{ type: 'text', text: `Error: ${message}` }],
    isError: true,
  };
}

function tool(server, name, config, handler) {
  server.registerTool(name, { ...config, annotations: READ_ONLY }, async (input) => {
    try {
      return await handler(input || {});
    } catch (error) {
      return failure(error);
    }
  });
}

function describeFidelity(entry) {
  const meaning = FIDELITY_MEANING[entry.fidelity] || entry.fidelity;
  const safeFor = entry.safeFor ? ` (safe for: ${entry.safeFor.join(', ')})` : '';
  return `${entry.fidelity} - ${meaning}${safeFor}`;
}

function createTransformsServer() {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } }
  );

  tool(
    server,
    'list_transforms',
    {
      title: 'List Parseltongue Transforms',
      description:
        'Browse the Parseltongue transform catalog with counts by category and by measured ' +
        'round-trip fidelity. Filter by category, whether decode exists, or fidelity tier. ' +
        'Transforms are representation only and provide no confidentiality. ' +
        'Note: a transform advertising decode does not necessarily return your text unchanged - ' +
        'check the fidelity tier.',
      inputSchema: z.object({
        category: z
          .string()
          .optional()
          .describe('Restrict to one category, e.g. cipher, encoding, unicode, concealment'),
        can_decode: z.boolean().optional().describe('Only transforms that do (or do not) offer decode'),
        fidelity: z
          .array(z.enum(['exact', 'lossy', 'constrained', 'encode_only', 'unreliable', 'error', 'unmeasured']))
          .optional()
          .describe('Only these measured round-trip fidelity tiers'),
        include_entries: z
          .boolean()
          .optional()
          .default(false)
          .describe('Include the full per-transform list. Off by default - 222 entries is a lot of output.'),
      }),
    },
    async (input) => {
      const summary = bridge.catalogSummary();
      const entries = bridge.listTransforms({
        category: input.category || null,
        canDecode: input.can_decode === undefined ? null : input.can_decode,
        fidelity: input.fidelity || null,
      });

      const filtered = Boolean(input.category || input.can_decode !== undefined || input.fidelity);
      const lines = [
        `Parseltongue catalog: ${summary.total} transforms` +
          (filtered ? `, ${entries.length} match the filter` : ''),
        '',
        `${NOT_ENCRYPTION}`,
        '',
        'By category: ' +
          Object.entries(summary.byCategory)
            .sort((a, b) => b[1] - a[1])
            .map(([k, v]) => `${k} ${v}`)
            .join(', '),
        '',
        'Decode fidelity (measured, not advertised):',
        ...Object.entries(summary.byFidelity)
          .sort((a, b) => b[1] - a[1])
          .map(([tier, n]) => `  ${String(n).padStart(3)}  ${tier} - ${FIDELITY_MEANING[tier] || ''}`),
      ];

      if (summary.fidelityStale) {
        lines.push(
          '',
          'WARNING: fidelity data was measured against a different upstream commit than the one ' +
            'loaded. Re-run scripts/probe-fidelity.js; the tiers below may be wrong.'
        );
      }

      if (input.include_entries) {
        lines.push('', 'Transforms:');
        for (const entry of entries) {
          lines.push(`  ${entry.key.padEnd(28)} ${entry.category.padEnd(13)} ${entry.fidelity}`);
        }
      } else if (filtered) {
        lines.push(
          '',
          `Matching keys: ${entries.map((e) => e.key).join(', ')}`
        );
      } else {
        lines.push('', 'Pass include_entries=true for the full list, or use find_transform to search.');
      }

      return reply(lines.join('\n'), {
        summary,
        matched: entries.length,
        transforms: input.include_entries || filtered ? entries : undefined,
        warning: NOT_ENCRYPTION,
      });
    }
  );

  tool(
    server,
    'find_transform',
    {
      title: 'Find a Transform',
      description:
        'Search the 222-transform catalog by name, key or description with fuzzy matching - ' +
        '"base 64", "rot-13", "hide in emoji" all work. Returns ranked candidates with their ' +
        'option schemas and measured decode fidelity. Use this instead of guessing a key.',
      inputSchema: z.object({
        query: z.string().min(1).describe('What you are looking for, in plain words'),
        limit: z.number().int().min(1).max(25).optional().default(5),
      }),
    },
    async (input) => {
      const matches = bridge.findTransforms(input.query, { limit: input.limit });

      if (matches.length === 0) {
        return reply(
          `No transform matched "${input.query}". Try list_transforms to browse by category.`,
          { query: input.query, matches: [] }
        );
      }

      const lines = [`${matches.length} match(es) for "${input.query}":`, ''];
      for (const { entry, why } of matches) {
        lines.push(`${entry.key}  (${entry.name}, ${entry.category})`);
        lines.push(`  matched because: ${why}`);
        lines.push(`  decode: ${describeFidelity(entry)}`);
        if (entry.description) lines.push(`  ${entry.description}`);
        if (entry.options.length) {
          lines.push(
            `  options: ${entry.options
              .map((o) => `${o.id}=${JSON.stringify(o.default)} (${o.type})`)
              .join(', ')}`
          );
        }
        lines.push('');
      }
      lines.push(NOT_ENCRYPTION);

      return reply(lines.join('\n'), {
        query: input.query,
        matches: matches.map(({ entry, score, why }) => ({ ...entry, score, why })),
        warning: NOT_ENCRYPTION,
      });
    }
  );

  tool(
    server,
    'run_transform',
    {
      title: 'Run a Transform',
      description:
        'Encode, decode or preview text with one Parseltongue transform. Returns the output ' +
        'together with the measured fidelity of that transform, so a decode result always ' +
        'arrives with a signal of how much to trust it. Provides NO confidentiality: the ' +
        'output is reversible by anyone without a key.',
      inputSchema: z.object({
        transform: z.string().min(1).describe('Transform key, e.g. base64. Use find_transform if unsure.'),
        text: z.string().describe('The text to transform'),
        action: z.enum(['encode', 'decode', 'preview']).optional().default('encode'),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe('Transform-specific options; defaults are used for anything omitted'),
      }),
    },
    async (input) => {
      const result = bridge.runTransform(input.transform, {
        action: input.action,
        text: input.text,
        options: input.options || {},
      });

      const lines = [
        `${result.name} (${result.category}) - ${result.action}`,
        '',
        result.output === '' ? '(empty output)' : String(result.output),
        '',
      ];

      if (result.warning) lines.push(`WARNING: ${result.warning}`, '');
      if (result.action === 'encode' && result.fidelity !== 'exact') {
        lines.push(
          `Decoding this back will not return your original text exactly: ${describeFidelity(result)}.`,
          ''
        );
      }
      if (result.action === 'decode') {
        lines.push(`Fidelity: ${describeFidelity(result)}`, '');
      }
      if (Object.keys(result.options).length) {
        lines.push(`Options used: ${JSON.stringify(result.options)}`, '');
      }
      lines.push(NOT_ENCRYPTION);

      return reply(lines.join('\n'), { ...result, warning: NOT_ENCRYPTION });
    }
  );

  tool(
    server,
    'auto_decode',
    {
      title: 'Auto-Decode Text',
      description:
        'Detect how text was encoded and decode it, returning the best guess plus alternatives. ' +
        'Heuristic, not proof. Cannot detect steganography - upstream\'s Node decode path has no ' +
        'steganography detection, so use inspect_text to look for hidden characters.',
      inputSchema: z.object({
        text: z.string().min(1).describe('The encoded text to identify and decode'),
        max_alternatives: z.number().int().min(0).max(20).optional().default(5),
      }),
    },
    async (input) => {
      const { result, limitations } = bridge.autoDecode(input.text);
      const alternatives = (result.alternatives || []).slice(0, input.max_alternatives);

      const lines = [];
      if (result.method) {
        lines.push(`Best guess: ${result.method}`, '', String(result.text ?? ''), '');
      } else {
        lines.push('No encoding confidently detected.', '');
      }

      if (alternatives.length) {
        lines.push('Other candidates:');
        for (const alt of alternatives) {
          lines.push(`  ${alt.method}: ${JSON.stringify(String(alt.text ?? '').slice(0, 60))}`);
        }
        lines.push('');
      }

      lines.push('Limitations:');
      for (const limitation of limitations) lines.push(`  - ${limitation}`);

      return reply(lines.join('\n'), {
        best: { method: result.method ?? null, text: result.text ?? null },
        alternatives,
        limitations,
      });
    }
  );

  tool(
    server,
    'inspect_text',
    {
      title: 'Inspect Text for Hidden Characters',
      description:
        'Report what is actually in a string: zero-width characters, Unicode tag characters, ' +
        'variation selectors, bidi overrides, homoglyphs, mixed scripts, unexpected controls. ' +
        'Use this on any text received from someone else BEFORE acting on it - invisible ' +
        'characters are how instructions get smuggled into text that looks harmless. ' +
        'Reports structure only; never decodes or sanitises the input.',
      inputSchema: z.object({
        text: z.string().describe('The text to inspect'),
      }),
    },
    async (input) => {
      const report = bridge.inspectText(input.text);

      const lines = [
        `Verdict: ${report.verdict}`,
        '',
        `${report.counts.characters} characters, ${report.counts.bytes} bytes, ` +
          `${report.counts.nonAscii} non-ASCII, ${report.counts.hidden} hidden`,
        '',
      ];

      if (report.findings.length) {
        lines.push('Findings:');
        for (const finding of report.findings) {
          lines.push(`  [${finding.severity}] ${finding.kind}: ${finding.detail}`);
        }
        lines.push('');
      }

      if (Object.keys(report.scripts).length) {
        lines.push(
          `Scripts: ${Object.entries(report.scripts)
            .map(([s, n]) => `${s} ${n}`)
            .join(', ')}`,
          ''
        );
      }

      for (const note of report.notes) lines.push(note);

      return reply(lines.join('\n'), report);
    }
  );

  return server;
}

module.exports = { SERVER_NAME, SERVER_VERSION, createTransformsServer };
