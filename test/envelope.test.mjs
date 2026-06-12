import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createEnvelopeChain } from '../src/envelope.js';
import { generateSessionKeys } from '../src/core/sign.js';
import { verifyLocal } from '../src/core/verify-local.js';
import { sha256Hex } from '../src/core/hash.js';

test('emitted envelopes pass the vendored spec verifier and chain correctly', async () => {
  const keys = await generateSessionKeys();
  const chain = createEnvelopeChain({ sessionId: 'test1234', keys, policyVersion: 'deadbeef', gatewayVersion: '0.1.0' });

  const e1 = await chain.emit({ kind: 'tool_call', tool: 'echo', decision: 'allow', paramsHash: await sha256Hex('p') });
  const e2 = await chain.emit({ kind: 'tool_call', tool: 'rm', decision: 'block', paramsHash: await sha256Hex('q') });

  for (const env of [e1, e2]) {
    const result = await verifyLocal(env, { knownPublicKey: keys.publicJwk });
    assert.equal(result.checks.schema.status, 'passed', JSON.stringify(result.checks.schema));
    assert.equal(result.checks.contentHash.status, 'passed');
    assert.equal(result.checks.ledgerHash.status, 'passed');
    assert.equal(result.checks.signatures[0].status, 'passed');
    assert.equal(result.valid, true);
  }
  assert.equal(e2.ledger.prevHash, e1.ledger.hash, 'envelopes must ledger-chain');
});

test('tampering with a recorded decision fails verification (ADR-0002 profile)', async () => {
  const keys = await generateSessionKeys();
  const chain = createEnvelopeChain({ sessionId: 'tamper01', keys, policyVersion: 'deadbeef', gatewayVersion: '0.1.0' });
  const env = await chain.emit({ kind: 'tool_call', tool: 'delete_everything', decision: 'block', paramsHash: await sha256Hex('x') });

  const tampered = JSON.parse(JSON.stringify(env));
  tampered.content.value = tampered.content.value.replace('"decision":"block"', '"decision":"allow"');

  const result = await verifyLocal(tampered, { knownPublicKey: keys.publicJwk });
  assert.equal(result.valid, false);
  assert.equal(result.checks.schema.status, 'passed', 'tamper must fail crypto, not schema');
  assert.equal(result.checks.contentHash.status, 'failed');
});
