#!/usr/bin/env node
/**
 * tsp-mcp — TSP verification tools over the Model Context Protocol (stdio).
 *
 * Lets any MCP-speaking AI assistant verify TSP evidence natively:
 *   verify_envelope      one trust envelope against a known public key
 *   validate_manifest    a trust manifest's shape and key-material rules
 *   verify_evidence_log  a JSONL evidence log: per-envelope verify + ledger chain
 *   canonical_hash       sha256(canonicalize(value)) utility
 *
 * Verification only — this server holds no keys and signs nothing. All
 * verdicts come from the vendored spec-pinned verifier core (src/core/,
 * see PROVENANCE.md). Fail-closed: malformed input is an error result,
 * never a silent pass. Zero runtime dependencies, Node >= 20.
 */
import { createLineReader, writeMessage } from './jsonrpc.js';
import { verifyLocal } from './core/verify-local.js';
import { validateTrustManifest } from './core/schema-manifest.js';
import { canonicalize } from './core/canonical.js';
import { sha256Hex } from './core/hash.js';

const VERSION = '0.1.0';

const asObject = (value, label) => {
  if (typeof value === 'string') {
    try { return JSON.parse(value); } catch { throw new Error(`${label} is a string but not valid JSON`); }
  }
  if (typeof value === 'object' && value !== null) return value;
  throw new Error(`${label} must be a JSON object (or a JSON string)`);
};

const TOOLS = [
  {
    name: 'verify_envelope',
    description: 'Verify a TSP v3.0 trust envelope (schema, content hash, ledger hash, Ed25519 signatures) against a known public key JWK. Returns the granular check profile. Local-only mode: keyRef is carried but not authenticated; key binding to a published manifest is an online-mode property.',
    inputSchema: {
      type: 'object',
      properties: {
        envelope: { description: 'The trust envelope (object, or JSON string)' },
        publicKeyJwk: { description: 'Ed25519 public key JWK to verify signatures against (object, or JSON string)' },
      },
      required: ['envelope', 'publicKeyJwk'],
    },
    run: async (args) => {
      const envelope = asObject(args.envelope, 'envelope');
      const publicKeyJwk = asObject(args.publicKeyJwk, 'publicKeyJwk');
      const { valid, checks, warnings } = await verifyLocal(envelope, { knownPublicKey: publicKeyJwk });
      return { valid, checks, warnings };
    },
  },
  {
    name: 'validate_manifest',
    description: 'Validate a TSP trust manifest: shape, instance certificates, revocation entries, and the rule that public manifests must never contain private or symmetric key material.',
    inputSchema: {
      type: 'object',
      properties: { manifest: { description: 'The trust manifest (object, or JSON string)' } },
      required: ['manifest'],
    },
    run: async (args) => validateTrustManifest(asObject(args.manifest, 'manifest')),
  },
  {
    name: 'verify_evidence_log',
    description: 'Verify a JSONL evidence log (e.g. produced by tsp-gateway): every envelope is verified against the public key, and the ledger chain (each prevHash must equal the previous envelope ledger hash) is checked for continuity.',
    inputSchema: {
      type: 'object',
      properties: {
        jsonl: { type: 'string', description: 'The evidence log content: one JSON envelope per line' },
        publicKeyJwk: { description: 'Ed25519 public key JWK (object, or JSON string)' },
      },
      required: ['jsonl', 'publicKeyJwk'],
    },
    run: async (args) => {
      const publicKeyJwk = asObject(args.publicKeyJwk, 'publicKeyJwk');
      const lines = String(args.jsonl).split('\n').map((l) => l.trim()).filter(Boolean);
      if (lines.length === 0) throw new Error('evidence log is empty');
      const failures = [];
      let prev = null;
      for (let i = 0; i < lines.length; i++) {
        let envelope;
        try { envelope = JSON.parse(lines[i]); } catch { failures.push({ line: i + 1, reason: 'not valid JSON' }); continue; }
        const { valid, checks } = await verifyLocal(envelope, { knownPublicKey: publicKeyJwk });
        if (!valid) {
          const failed = Object.entries(checks)
            .filter(([k, v]) => k !== 'signatures' && v?.status === 'failed').map(([k]) => k);
          if (checks.signatures?.some((s) => s.status === 'failed')) failed.push('signatures');
          failures.push({ line: i + 1, reason: `verification failed: ${failed.join(', ')}` });
        }
        if (prev && envelope?.ledger?.prevHash !== prev?.ledger?.hash) {
          failures.push({ line: i + 1, reason: 'ledger chain broken: prevHash does not match previous envelope hash' });
        }
        prev = envelope;
      }
      return {
        envelopes: lines.length,
        allValid: failures.length === 0,
        chainIntact: !failures.some((f) => f.reason.startsWith('ledger chain broken')),
        failures,
      };
    },
  },
  {
    name: 'canonical_hash',
    description: 'Compute sha256(canonicalize(value)) per the TSP canonicalization rules (RFC 8785-style). Useful for checking content hashes by hand.',
    inputSchema: {
      type: 'object',
      properties: { value: { description: 'Any JSON value' } },
      required: ['value'],
    },
    run: async (args) => {
      const canonical = canonicalize(args.value);
      return { sha256: await sha256Hex(canonical), canonicalPreview: canonical.slice(0, 500), canonicalLength: canonical.length };
    },
  },
];

const toolResult = (id, payload) => ({
  jsonrpc: '2.0', id,
  result: { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], isError: false },
});
const toolError = (id, message) => ({
  jsonrpc: '2.0', id,
  result: { content: [{ type: 'text', text: `tsp-mcp error (fail-closed): ${message}` }], isError: true },
});

process.stdin.on('data', createLineReader(async (msg) => {
  try {
    if (msg.method === 'initialize') {
      writeMessage(process.stdout, {
        jsonrpc: '2.0', id: msg.id,
        result: {
          protocolVersion: msg.params?.protocolVersion ?? '2025-03-26',
          capabilities: { tools: {} },
          serverInfo: { name: 'tsp-mcp', version: VERSION },
        },
      });
    } else if (msg.method === 'tools/list') {
      writeMessage(process.stdout, {
        jsonrpc: '2.0', id: msg.id,
        result: { tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) },
      });
    } else if (msg.method === 'tools/call') {
      const tool = TOOLS.find((t) => t.name === msg.params?.name);
      if (!tool) { writeMessage(process.stdout, toolError(msg.id, `unknown tool "${msg.params?.name}"`)); return; }
      try {
        writeMessage(process.stdout, toolResult(msg.id, await tool.run(msg.params?.arguments ?? {})));
      } catch (error) {
        writeMessage(process.stdout, toolError(msg.id, error instanceof Error ? error.message : String(error)));
      }
    } else if (msg.id !== undefined) {
      writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: {} });
    }
  } catch (error) {
    if (msg?.id !== undefined) {
      writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: String(error) } });
    }
  }
}));
process.stderr.write(`tsp-mcp ${VERSION}: TSP verification tools over MCP stdio (verification only; holds no keys)\n`);
