/**
 * TSP v3.0 local verification — AUDITABLE REFERENCE VERIFIER CORE.
 *
 * This module is a reference verifier core, NOT the normative source of TSP
 * behaviour. Normative authority is the schema + fixtures + threat model in
 * Lexi-TSP/tsp-spec (see ADR-0008, Normative Authority Hierarchy): when this
 * implementation and the spec disagree, this implementation is wrong until the
 * spec is amended by ADR.
 *
 * Conformance is enforced mechanically, not by trust: scripts/conformance/
 * run-v3-fixtures.mjs runs the checksum-pinned tsp-spec fixture suite through
 * verifyLocal() on every push/PR and fails CI on any divergence — including the
 * two ADR-0002 executionProvenance vectors.
 */
import { canonicalize } from './canonical.js';
import { importPublicKeyJwk, verifyEd25519, base64ToBytes } from './crypto.js';
import { buildLedgerDomain, buildSignatureDomain } from './domains.js';
import { sha256Hex } from './hash.js';
import { validateTrustEnvelopeShape } from './schema.js';

const encoder = new TextEncoder();

const PASS = (detail) => ({ status: 'passed', detail });
const FAIL = (detail, evidence) => ({ status: 'failed', detail, evidence });
const SKIP = (detail) => ({ status: 'skipped', detail });

const initialChecks = () => ({
  schema: SKIP('not yet checked'),
  contentHash: SKIP('not yet checked'),
  ledgerHash: SKIP('not yet checked'),
  manifestFetch: SKIP('local-only mode: manifest fetch not performed'),
  rootSignature: SKIP('local-only mode: root signature not verified'),
  certChain: SKIP('local-only mode: cert chain not validated'),
  certValidity: SKIP('local-only mode: cert validity not checked'),
  revocation: SKIP('local-only mode: revocation not checked'),
  tsa: SKIP('local-only mode: TSA token not verified'),
  signatures: [],
});

export const verifyLocal = async (envelope, { knownPublicKey }) => {
  const checks = initialChecks();
  const warnings = [];

  const schemaErrors = validateTrustEnvelopeShape(envelope);
  if (schemaErrors.length > 0) {
    checks.schema = FAIL(`schema validation failed: ${schemaErrors.join('; ')}`, schemaErrors);
    return { valid: false, envelope, checks, warnings };
  }
  checks.schema = PASS('schema is well-formed');

  const expectedContentHash = await sha256Hex(canonicalize(envelope.content.value));
  checks.contentHash =
    expectedContentHash === envelope.content.hash
      ? PASS('content hash matches canonical(value)')
      : FAIL(`content hash mismatch: claimed ${envelope.content.hash}, computed ${expectedContentHash}`);

  const expectedLedgerHash = await sha256Hex(canonicalize(buildLedgerDomain(envelope)));
  checks.ledgerHash =
    expectedLedgerHash === envelope.ledger.hash
      ? PASS('ledger hash matches canonical(envelope without ledger.hash)')
      : FAIL(`ledger hash mismatch: claimed ${envelope.ledger.hash}, computed ${expectedLedgerHash}`);

  for (const signature of envelope.signatures) {
    if (signature.algorithm !== 'ed25519') {
      checks.signatures.push(FAIL(`unsupported algorithm: ${signature.algorithm}`));
      continue;
    }

    let publicKey;
    try {
      publicKey = await importPublicKeyJwk(knownPublicKey);
    } catch (error) {
      checks.signatures.push(FAIL(`could not import known public key: ${String(error)}`));
      continue;
    }

    let signatureBytes;
    try {
      signatureBytes = base64ToBytes(signature.signature);
    } catch (error) {
      checks.signatures.push(FAIL(`signature is not valid base64: ${String(error)}`));
      continue;
    }

    const ok = await verifyEd25519(
      publicKey,
      signatureBytes,
      encoder.encode(canonicalize(buildSignatureDomain(envelope))),
    );

    checks.signatures.push(
      ok
        ? PASS(`signature valid (role=${signature.role}, algorithm=${signature.algorithm})`)
        : FAIL(`signature invalid (role=${signature.role}, algorithm=${signature.algorithm})`),
    );
  }

  warnings.push('local-only verify: manifest, cert-chain, TSA, DANE, and revocation checks are not performed');
  warnings.push('local-only verify: signature.keyRef is carried but NOT authenticated — key-ref binding is an online-mode property');

  const requiredChecks = [checks.schema, checks.contentHash, checks.ledgerHash, ...checks.signatures];
  const valid = requiredChecks.every((check) => check.status === 'passed');

  return { valid, envelope, checks, warnings };
};
