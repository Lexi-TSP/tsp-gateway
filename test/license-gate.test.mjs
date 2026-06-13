import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassThrough } from 'node:stream';
import { createLicenseGate, NO_LICENSE_GATE } from '../src/license-gate.js';
import { Policy } from '../src/policy.js';
import { startGateway } from '../src/proxy.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, 'test/fixtures/license-v1');
const readJson = (f) => JSON.parse(readFileSync(path.join(DIR, f), 'utf8'));

const rootFile = readJson('license-root-key.json');
const DEV_ROOTS = [{ rootKeyId: rootFile.rootKeyId, publicKey: rootFile.publicKey }];
const ORIGIN = 'https://customer.example';
const NOW = () => new Date('2026-07-01T00:00:00.000Z');
const sink = { write() {} };

const gateWith = (over = {}) =>
  createLicenseGate(
    { license: { origin: ORIGIN, devTrustedRootKeys: DEV_ROOTS, gatedModules: { read_note: 'gateway-pro' }, bundle: readJson('valid-pro.json'), ...over } },
    { now: NOW, stderr: sink },
  );

test('no license config -> licensing disabled, nothing gated, behavior unchanged', () => {
  const g = createLicenseGate({});
  assert.equal(g, NO_LICENSE_GATE);
  assert.equal(g.enabled, false);
  assert.equal(g.isGated('read_note'), false);
});

test('a distribution-pinned license-root enables licensing without dev keys', () => {
  // PINNED_LICENSE_ROOTS now carries the real ceremony root, so licensing
  // enables with no devTrustedRootKeys override (it would only fail closed if
  // the pin were empty AND no dev keys were supplied).
  const g = createLicenseGate({ license: { origin: ORIGIN, gatedModules: {} } }, { stderr: sink });
  assert.equal(g.enabled, true);
});

test('malformed license config -> throws (unknown key / missing origin / bad gatedModules)', () => {
  assert.throws(() => createLicenseGate({ license: { origin: ORIGIN, typo: 1, devTrustedRootKeys: DEV_ROOTS } }, { stderr: sink }), /unknown key/);
  assert.throws(() => createLicenseGate({ license: { devTrustedRootKeys: DEV_ROOTS } }, { stderr: sink }), /origin/);
  assert.throws(() => createLicenseGate({ license: { origin: ORIGIN, devTrustedRootKeys: DEV_ROOTS, gatedModules: [] } }, { stderr: sink }), /gatedModules/);
});

test('gated tool with a valid license -> allowed', async () => {
  const g = gateWith();
  assert.equal(g.enabled, true);
  assert.equal(g.isGated('read_note'), true);
  assert.equal(g.isGated('echo'), false);
  assert.deepEqual(g.gatedTools(), ['read_note']);
  const r = await g.check('read_note');
  assert.equal(r.ok, true);
});

test('ungated tool -> ok ungated (no license needed)', async () => {
  const r = await gateWith().check('echo');
  assert.equal(r.ok, true);
  assert.equal(r.reason, 'ungated');
});

test('gated tool requiring an unlicensed module -> unlicensed_platform (module_not_licensed)', async () => {
  const r = await gateWith({ gatedModules: { read_note: 'enterprise-policy' } }).check('read_note');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unlicensed_platform');
  assert.equal(r.licenseReason, 'module_not_licensed');
});

test('gated tool with NO license bundle -> unlicensed_platform (fail-closed)', async () => {
  const g = createLicenseGate(
    { license: { origin: ORIGIN, devTrustedRootKeys: DEV_ROOTS, gatedModules: { read_note: 'gateway-pro' } } },
    { now: NOW, stderr: sink },
  );
  const r = await g.check('read_note');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unlicensed_platform');
});

test('wrong configured origin -> unlicensed_platform (origin_mismatch)', async () => {
  const r = await gateWith({ origin: 'https://evil.example' }).check('read_note');
  assert.equal(r.ok, false);
  assert.equal(r.licenseReason, 'origin_mismatch');
});

// ---- in-process end-to-end: real proxy + real gate + real toy upstream, injected clock ----
const collect = (stream) => {
  const responses = new Map();
  let buf = '';
  stream.on('data', (c) => {
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
    if (Date.now() - t0 > ms) throw new Error(`timeout waiting for ${id}`);
    await new Promise((r) => setTimeout(r, 20));
  }
  return map.get(id);
};
const drive = async (licenseGate) => {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const evidenceDir = mkdtempSync(path.join(tmpdir(), 'tsp-lic-ev-'));
  const config = { upstream: { command: 'node', args: [path.join(ROOT, 'demo/toy-server.mjs')] }, evidenceDir, policy: { allow: ['echo', 'read_note'], block: ['delete_everything'], requireApproval: ['send_email'], default: 'block' } };
  const policy = new Policy(config);
  const responses = collect(stdout);
  const { upstream } = await startGateway({ config, policy, licenseGate, stdin, stdout, stderr });
  const send = (msg) => stdin.write(JSON.stringify(msg) + '\n');
  return { send, responses, stop: () => new Promise((res) => { upstream.once('exit', () => res()); upstream.stdin.end(); }) };
};

test('402 path e2e: gated tool blocked + hidden when unlicensed, allowed when licensed', async () => {
  // Scenario A — valid license for gateway-pro: read_note advertised and callable.
  {
    const { send, responses, stop } = await drive(gateWith());
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } } });
    await waitFor(responses, 1);
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const toolsA = (await waitFor(responses, 2)).result.tools.map((t) => t.name);
    assert.ok(toolsA.includes('read_note'), 'licensed gated tool advertised');
    assert.ok(toolsA.includes('echo'), 'ungated allowed tool advertised');
    assert.ok(!toolsA.includes('delete_everything'), 'policy-blocked tool not advertised');
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'read_note', arguments: {} } });
    const callA = await waitFor(responses, 3);
    assert.notEqual(callA.result.isError, true, 'licensed gated call succeeds');
    await stop();
  }

  // Scenario B — license lacks the required module: read_note hidden + fails closed 402.
  {
    const { send, responses, stop } = await drive(gateWith({ gatedModules: { read_note: 'enterprise-policy' } }));
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } } });
    await waitFor(responses, 1);
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const toolsB = (await waitFor(responses, 2)).result.tools.map((t) => t.name);
    assert.ok(!toolsB.includes('read_note'), 'unlicensed gated tool NOT advertised');
    assert.ok(toolsB.includes('echo'), 'ungated tool still advertised');
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'read_note', arguments: {} } });
    const callB = await waitFor(responses, 3);
    assert.equal(callB.result.isError, true, 'unlicensed gated call fails closed');
    assert.match(callB.result.content[0].text, /unlicensed \(402 unlicensed_platform\)/);
    send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'echo', arguments: { message: 'hi' } } });
    const callEcho = await waitFor(responses, 4);
    assert.notEqual(callEcho.result.isError, true, 'ungated tool unaffected by licensing');
    await stop();
  }
});
