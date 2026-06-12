/**
 * Trust envelope emission for gateway decisions.
 *
 * Every policy decision (allowed, blocked, approval-required) becomes a
 * TSP v3.0 trust envelope: canonicalized, hash-bound, Ed25519-signed with the
 * session key, ledger-chained to the previous envelope. Envelopes MUST pass
 * the vendored verifyLocal — test/envelope.test.mjs enforces the roundtrip.
 *
 * Fail-closed rule: if an envelope cannot be built or signed, the gateway
 * call fails. Evidence is not optional.
 */
import { canonicalize } from './core/canonical.js';
import { sha256Hex } from './core/hash.js';
import { buildLedgerDomain, buildSignatureDomain } from './core/domains.js';

const GENESIS = 'tsp-gateway-genesis-v1';

export const createEnvelopeChain = ({ sessionId, keys, policyVersion, gatewayVersion }) => {
  let prevHash = null;
  let sequence = 0;

  const emit = async (record) => {
    if (prevHash === null) prevHash = await sha256Hex(GENESIS + sessionId);
    sequence += 1;

    const value = JSON.stringify({ ...record, sequence });
    const contentHash = await sha256Hex(canonicalize(value));
    const envelope = {
      tsp: '3.0',
      content: { type: 'structured', value, hash: contentHash },
      declaration: {
        primarySource: { type: 'user-input', title: 'MCP tool-call mediation record' },
        citations: [],
      },
      process: {
        model: {
          provider: 'tsp-gateway',
          name: 'mcp-proxy',
          version: gatewayVersion,
          temperature: 0,
          contextWindow: 0,
        },
        systemPrompt: {
          hash: await sha256Hex('tsp-gateway: deterministic mediation, no prompt'),
          redacted: true,
          reason: 'gateway decision record; no model prompt involved',
        },
      },
      alignment: {
        uncertainty: [],
        humanReviewRequired: record.decision === 'approval_required',
        policy: { id: 'tsp-gateway-policy', version: policyVersion },
      },
      timestamp: {
        claimed: new Date().toISOString(),
        tsaToken: '__phase1__',
        tsaUrl: 'https://tsa.invalid/phase1',
      },
      ledger: { id: `tsp-gateway-${sessionId}`, prevHash, hash: '' },
      signatures: [],
      executionProvenance: {
        spatialBoundary: {
          gateway: `tsp-gateway/${gatewayVersion}`,
          toolsMounted: record.toolsMounted ?? [],
          toolsIsolated: true,
          o1ConstraintMet: true,
        },
        temporalBoundary: {
          engine: 'tsp-gateway/mediation',
          tier1AnchorHash: await sha256Hex(`policy:${policyVersion}`),
          totalContextTokens: 0,
          driftDetected: false,
        },
        deterministicOutput: { status: 'deterministic', payloadHash: contentHash },
      },
    };

    const signature = await keys.signCanonical(buildSignatureDomain(envelope));
    envelope.signatures.push({
      role: 'instance',
      algorithm: 'ed25519',
      keyRef: `https://gateway.invalid/.well-known/tsp-manifest.json#session-${sessionId}`,
      signature,
      certChain: [],
    });

    envelope.ledger.hash = await sha256Hex(canonicalize(buildLedgerDomain(envelope)));
    prevHash = envelope.ledger.hash;
    return envelope;
  };

  return { emit };
};
