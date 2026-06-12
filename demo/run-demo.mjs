#!/usr/bin/env node
// Human-friendly demo: drives the gateway as an MCP client, then verifies
// the evidence log with the vendored spec verifier. Run: npm run demo
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyLocal } from '../src/core/verify-local.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const gw = spawn('node', ['src/main.js', 'gateway.config.json'], { cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'] });
let stderrBuf = '';
gw.stderr.on('data', (c) => { stderrBuf += c.toString(); });

const pending = new Map();
let buf = '';
gw.stdout.on('data', (c) => {
  buf += c.toString();
  let i;
  while ((i = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    try { const m = JSON.parse(line); if (pending.has(m.id)) pending.get(m.id)(m); } catch {}
  }
});
let nextId = 0;
const call = (method, params) => new Promise((resolve) => {
  const id = ++nextId;
  pending.set(id, resolve);
  gw.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
});

console.log('— tsp-gateway demo —\n');
await call('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'demo', version: '0' } });
const { result: list } = await call('tools/list');
console.log('tools visible through gateway:', list.tools.map((t) => t.name).join(', '));
console.log('  (delete_everything exists upstream — the gateway hides it)\n');

for (const [name, args] of [['echo', { message: 'trust is given' }], ['delete_everything', {}], ['send_email', { to: 'someone@example.com' }]]) {
  const { result } = await call('tools/call', { name, arguments: args });
  console.log(`${result.isError ? 'DENIED ' : 'ALLOWED'}  ${name.padEnd(18)} -> ${result.content[0].text}`);
}

await new Promise((r) => setTimeout(r, 300));
gw.kill();
const logPath = path.resolve(ROOT, stderrBuf.match(/evidence -> (\S+)/)[1]);
const keyPath = logPath.replace(/evidence-(\w+)\.jsonl$/, 'session-$1.publickey.json');
const publicJwk = JSON.parse(readFileSync(keyPath, 'utf8'));
const envelopes = readFileSync(logPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));

console.log(`\nevidence log: ${envelopes.length} signed envelopes (${path.basename(logPath)})`);
let allValid = true;
for (const env of envelopes) {
  const r = await verifyLocal(env, { knownPublicKey: publicJwk });
  allValid &&= r.valid;
  const rec = JSON.parse(env.content.value);
  console.log(`  ${r.valid ? 'VERIFIED' : 'INVALID '}  #${rec.sequence} ${rec.kind}${rec.tool ? ` ${rec.tool} -> ${rec.decision}` : ''}`);
}
console.log(allValid ? '\nall envelopes verify against the TSP v3.0 reference verifier ✓' : '\nVERIFICATION FAILURE');
process.exit(allValid ? 0 : 1);
