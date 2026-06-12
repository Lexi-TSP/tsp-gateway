import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Policy } from '../src/policy.js';

const cfg = (policy) => ({ policy });

test('decisions: allow, block, approval, fail-closed default', () => {
  const p = new Policy(cfg({ allow: ['echo'], block: ['rm'], requireApproval: ['mail'] }));
  assert.equal(p.decide('echo'), 'allow');
  assert.equal(p.decide('rm'), 'block');
  assert.equal(p.decide('mail'), 'approval_required');
  assert.equal(p.decide('never_heard_of_it'), 'block');
  assert.equal(p.decide(''), 'block');
  assert.equal(p.decide(undefined), 'block');
});

test('malformed policy refuses to start', () => {
  assert.throws(() => new Policy(cfg({ allow: ['x'], block: ['x'] })), /both allowed and blocked/);
  assert.throws(() => new Policy(cfg({ default: 'maybe' })), /invalid default/);
  assert.throws(() => new Policy(cfg({ typo_key: [] })), /unknown key/);
});

test('policy version is deterministic', () => {
  const a = new Policy(cfg({ allow: ['x'] }));
  const b = new Policy(cfg({ allow: ['x'] }));
  assert.equal(a.version, b.version);
});
