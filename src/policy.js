/**
 * Policy engine. Fail-closed by construction:
 * - unknown tool -> the configured default, which is BLOCK unless explicitly
 *   set to "allow" (dev-only escape hatch, warned loudly at startup);
 * - malformed policy -> constructor throws, gateway refuses to start;
 * - decision vocabulary is closed: allow | block | approval_required.
 */
import { createHash } from 'node:crypto';

const DECISIONS = new Set(['allow', 'block', 'approval_required']);

export class Policy {
  constructor(config) {
    if (typeof config !== 'object' || config === null) throw new Error('policy: config must be an object');
    const p = config.policy ?? {};
    for (const key of Object.keys(p)) {
      if (!['allow', 'block', 'requireApproval', 'default'].includes(key)) {
        throw new Error(`policy: unknown key "${key}"`);
      }
    }
    this.allow = new Set(p.allow ?? []);
    this.block = new Set(p.block ?? []);
    this.requireApproval = new Set(p.requireApproval ?? []);
    this.defaultDecision = p.default ?? 'block';
    if (!DECISIONS.has(this.defaultDecision)) throw new Error(`policy: invalid default "${this.defaultDecision}"`);
    for (const name of this.allow) {
      if (this.block.has(name)) throw new Error(`policy: "${name}" is both allowed and blocked`);
    }
    this.version = createHash('sha256').update(JSON.stringify(p)).digest('hex').slice(0, 16);
  }

  decide(toolName) {
    if (typeof toolName !== 'string' || toolName.length === 0) return 'block';
    if (this.block.has(toolName)) return 'block';
    if (this.requireApproval.has(toolName)) return 'approval_required';
    if (this.allow.has(toolName)) return 'allow';
    return this.defaultDecision;
  }
}
