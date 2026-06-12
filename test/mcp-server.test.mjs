import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createEnvelopeChain } from '../src/envelope.js';
import { generateSessionKeys } from '../src/core/sign.js';
import { sha256Hex } from '../src/core/hash.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const startServer = () => {
  const proc = spawn('node', [path.join(ROOT, 'src/mcp-server.js')], { stdio: ['pipe', 'pipe', 'ignore'] });
  const responses = new Map();
  let buf = '';
  proc.stdout.on('data', (c) => {
    buf += c.toString();
    let i;
    while ((i = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      try { const m = JSON.parse(line); if (m.id !== undefined) responses.set(m.id, m); } catch {}
    }
  });
  let nextId = 0;
  const call = async (method, params) => {
    const id = ++nextId;
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    const t0 = Date.now();
    while (!responses.has(id)) {
      if (Date.now() - t0 > 8000) throw new Error(`timeout on ${method}`);
      await new Promise((r) => setTimeout(r, 20));
    }
    return responses.get(id);
  };
  const callTool = async (name, args) => {
    const { result } = await call('tools/call', { name, arguments: args });
    return { isError: result.isError, payload: result.isError ? result.content[0].text : JSON.parse(result.content[0].text) };
  };
  return { proc, call, callTool };
};

test('tsp-mcp: initialize, list, and all four tools end-to-end', async () => {
  const keys = await generateSessionKeys();
  const chain = createEnvelopeChain({ sessionId: 'mcp00001', keys, policyVersion: 'cafebabe', gatewayVersion: '0.1.0' });
  const e1 = await chain.emit({ kind: 'tool_call', tool: 'echo', decision: 'allow', paramsHash: await sha256Hex('a') });
  const e2 = await chain.emit({ kind: 'tool_call', tool: 'rm', decision: 'block', paramsHash: await sha256Hex('b') });

  const { proc, call, callTool } = startServer();
  try {
    const init = await call('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    assert.equal(init.result.serverInfo.name, 'tsp-mcp');

    const list = await call('tools/list', {});
    assert.deepEqual(list.result.tools.map((t) => t.name).sort(),
      ['canonical_hash', 'validate_manifest', 'verify_envelope', 'verify_evidence_log']);

    // verify_envelope: valid, then tampered (accepts JSON-string inputs too)
    const ok = await callTool('verify_envelope', { envelope: JSON.stringify(e1), publicKeyJwk: keys.publicJwk });
    assert.equal(ok.isError, false);
    assert.equal(ok.payload.valid, true);

    const tampered = JSON.parse(JSON.stringify(e2));
    tampered.content.value = tampered.content.value.replace('"decision":"block"', '"decision":"allow"');
    const bad = await callTool('verify_envelope', { envelope: tampered, publicKeyJwk: keys.publicJwk });
    assert.equal(bad.payload.valid, false);
    assert.equal(bad.payload.checks.contentHash.status, 'failed');

    // verify_evidence_log: intact chain, then broken chain
    const log = [e1, e2].map((e) => JSON.stringify(e)).join('\n');
    const logOk = await callTool('verify_evidence_log', { jsonl: log, publicKeyJwk: keys.publicJwk });
    assert.equal(logOk.payload.allValid, true);
    assert.equal(logOk.payload.chainIntact, true);
    assert.equal(logOk.payload.envelopes, 2);

    const broken = [e2, e1].map((e) => JSON.stringify(e)).join('\n'); // reversed order breaks the chain
    const logBad = await callTool('verify_evidence_log', { jsonl: broken, publicKeyJwk: keys.publicJwk });
    assert.equal(logBad.payload.chainIntact, false);

    // validate_manifest: private key material must be rejected
    const badManifest = { tsp: '3.0', organization: { name: 'x', domain: 'x.test' }, rootKey: { kty: 'OKP', crv: 'Ed25519', x: 'abc', d: 'PRIVATE' }, instances: [], revoked: [], sequence: 1, issuedAt: new Date().toISOString(), acceptableAge: { seconds: 60 }, rootSignatureOverManifest: 'sig' };
    const vm = await callTool('validate_manifest', { manifest: badManifest });
    assert.equal(vm.payload.ok, false);
    assert.ok(vm.payload.errors.some((e) => e.includes('private JWK parameter')));

    // canonical_hash matches the core directly
    const ch = await callTool('canonical_hash', { value: { b: 1, a: 'x' } });
    assert.equal(ch.payload.sha256, await sha256Hex('{"a":"x","b":1}'));

    // fail-closed: garbage input is an error result, not a crash or a pass
    const garbage = await callTool('verify_envelope', { envelope: 'not json at all', publicKeyJwk: keys.publicJwk });
    assert.equal(garbage.isError, true);
    assert.match(garbage.payload, /fail-closed/);
  } finally {
    proc.kill();
  }
});
