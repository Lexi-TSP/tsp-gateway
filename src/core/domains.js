/**
 * TSP v3.0 canonical signing/ledger domain construction — SINGLE SOURCE.
 *
 * The domain rule is a crypto invariant (ADR-0002: executionProvenance is
 * bound into both the ledger and signature domains; optional envelope fields
 * are included if and only if present). It must exist exactly once so the
 * local and online verifiers cannot diverge. Semantics are pinned by the
 * tsp-spec v3.0 fixture suite (valid-with-provenance / tampered-provenance);
 * normative authority is tsp-spec per ADR-0008 — do not edit this module to
 * make a verifier pass, fix the verifier.
 */

/**
 * Ledger domain: everything the ledger hash covers — the envelope minus
 * ledger.hash itself. Includes signatures; includes executionProvenance
 * when present (ADR-0002).
 */
export const buildLedgerDomain = (envelope) => {
  const domain = {
    tsp: envelope.tsp,
    content: envelope.content,
    process: envelope.process,
    signatures: envelope.signatures,
    ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash },
  };

  if (envelope.declaration !== undefined) domain.declaration = envelope.declaration;
  if (envelope.alignment !== undefined) domain.alignment = envelope.alignment;
  if (envelope.timestamp !== undefined) domain.timestamp = envelope.timestamp;
  if (envelope.executionProvenance !== undefined) {
    domain.executionProvenance = envelope.executionProvenance;
  }

  return domain;
};

/**
 * Signature domain: what each Ed25519 envelope signature covers — excludes
 * the signatures array and the TSA token (timestamp is reduced to
 * { claimed, tsaUrl } so a later TSA attestation does not invalidate the
 * instance signature). Includes executionProvenance when present (ADR-0002).
 */
export const buildSignatureDomain = (envelope) => {
  const domain = {
    tsp: envelope.tsp,
    content: envelope.content,
    process: envelope.process,
    ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash },
  };

  if (envelope.declaration !== undefined) domain.declaration = envelope.declaration;
  if (envelope.alignment !== undefined) domain.alignment = envelope.alignment;
  if (envelope.timestamp !== undefined) {
    domain.timestamp = {
      claimed: envelope.timestamp.claimed,
      tsaUrl: envelope.timestamp.tsaUrl,
    };
  }
  if (envelope.executionProvenance !== undefined) {
    domain.executionProvenance = envelope.executionProvenance;
  }

  return domain;
};
