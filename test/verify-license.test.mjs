import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyLicense } from '../src/core/verify-license.js';

const DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures/license-v1');
const readJson = (f) => JSON.parse(readFileSync(path.join(DIR, f), 'utf8'));

// Cross-implementation pin: the gateway's REAL verify_license() must produce
// the same { ok, reason } the spec's run-license.mjs asserts over the same
// checksum-pinned vectors (ADR-0008 discipline).
test('verify_license() matches the pinned tsp-spec license-v1 vectors', async () => {
  const spec = readJson('license-expectations.json');
  const rootFile = readJson(spec.rootKey);
  const trustedRootKeys = [{ rootKeyId: rootFile.rootKeyId, publicKey: rootFile.publicKey }];
  for (const vec of spec.vectors) {
    const bundle = readJson(vec.file);
    const config = { origin: vec.origin, trustedRootKeys, requiredModules: vec.requiredModules ?? [] };
    const r = await verifyLicense(bundle, config, vec.now);
    assert.equal(r.ok, vec.expect.ok, `${vec.file} ok [${vec.note}] -> ${r.reason}: ${r.detail}`);
    assert.equal(r.reason, vec.expect.reason, `${vec.file} reason [${vec.note}]`);
  }
});

test('verify_license() exposes valid_in_grace and a license summary on pass', async () => {
  const rootFile = readJson('license-root-key.json');
  const trustedRootKeys = [{ rootKeyId: rootFile.rootKeyId, publicKey: rootFile.publicKey }];
  const r = await verifyLicense(readJson('in-grace.json'), { origin: 'https://customer.example', trustedRootKeys }, '2026-06-10T00:00:00.000Z');
  assert.equal(r.ok, true);
  assert.equal(r.reason, 'valid_in_grace');
  assert.equal(r.inGrace, true);
  assert.equal(r.license.origin, 'https://customer.example');
});

test('verify_license() throws on misconfiguration (fail-closed at the call site)', async () => {
  const bundle = readJson('valid-pro.json');
  const ok = { origin: 'https://customer.example', trustedRootKeys: [{ rootKeyId: 'x', publicKey: {} }] };
  await assert.rejects(() => verifyLicense(bundle, { ...ok, origin: '' }, '2026-07-01T00:00:00.000Z'), /origin/);
  await assert.rejects(() => verifyLicense(bundle, { origin: 'https://x', trustedRootKeys: [] }, '2026-07-01T00:00:00.000Z'), /trustedRootKeys/);
  await assert.rejects(() => verifyLicense(bundle, ok, 'not-a-date'), /now/);
});
