import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyLocal } from '../src/core/verify-local.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const rpc = (proc, msg) => proc.stdin.write(JSON.stringify(msg) + '\n');

const collect = (proc) => {
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
  return responses;
};

const waitFor = async (map, id, ms = 5000) => {
  const t0 = Date.now();
  while (!map.has(id)) {
    if (Date.now() - t0 > ms) throw new Error(`timeout waiting for response ${id}`);
    await new Promise((r) => setTimeout(r, 25));
  }
  return map.get(id);
};

test('gateway end-to-end: mediation, filtering, and a verifiable evidence log', async () => {
  const evidenceDir = mkdtempSync(path.join(tmpdir(), 'tsp-evidence-'));
  const gw = spawn('node', [path.join(ROOT, 'src/main.js'), path.join(ROOT, 'gateway.config.json')], {
    cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env },
  });
  let sessionLine = '';
  gw.stderr.on('data', (c) => { sessionLine += c.toString(); });
  // override evidence dir via config? MVP: gateway.config.json points at ./evidence under cwd ROOT.
  const responses = collect(gw);

  rpc(gw, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'e2e', version: '0' } } });
  assert.equal((await waitFor(responses, 1)).result.serverInfo.name, 'toy-server');

  rpc(gw, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const tools = (await waitFor(responses, 2)).result.tools.map((t) => t.name);
  assert.ok(tools.includes('echo'), 'allowed tool advertised');
  assert.ok(!tools.includes('delete_everything'), 'blocked tool NOT advertised');

  rpc(gw, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { message: 'hei' } } });
  const ok = await waitFor(responses, 3);
  assert.equal(ok.result.isError, false);
  assert.match(ok.result.content[0].text, /hei/);

  rpc(gw, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'delete_everything', arguments: {} } });
  const blocked = await waitFor(responses, 4);
  assert.equal(blocked.result.isError, true);
  assert.match(blocked.result.content[0].text, /blocked by policy/);

  rpc(gw, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'send_email', arguments: { to: 'x@y.z' } } });
  const approval = await waitFor(responses, 5);
  assert.equal(approval.result.isError, true);
  assert.match(approval.result.content[0].text, /requires approval/);

  await new Promise((r) => setTimeout(r, 300));
  gw.kill();

  const m = sessionLine.match(/evidence -> (\S+)/);
  assert.ok(m, `no evidence path in stderr: ${sessionLine}`);
  const logPath = path.resolve(ROOT, m[1]);
  const keyPath = logPath.replace(/evidence-(\w+)\.jsonl$/, 'session-$1.publickey.json');
  const publicJwk = JSON.parse(readFileSync(keyPath, 'utf8'));
  const envelopes = readFileSync(logPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));

  assert.ok(envelopes.length >= 4, `expected >=4 envelopes, got ${envelopes.length}`);
  let prev = null;
  for (const env of envelopes) {
    const result = await verifyLocal(env, { knownPublicKey: publicJwk });
    assert.equal(result.valid, true, JSON.stringify(result.checks).slice(0, 300));
    if (prev) assert.equal(env.ledger.prevHash, prev.ledger.hash, 'ledger chain intact');
    prev = env;
  }
  const decisions = envelopes.map((e) => JSON.parse(e.content.value)).filter((r) => r.kind === 'tool_call').map((r) => `${r.tool}:${r.decision}`);
  assert.deepEqual(decisions, ['echo:allow', 'delete_everything:block', 'send_email:approval_required']);
});
