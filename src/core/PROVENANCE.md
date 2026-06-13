# Vendored TSP v3 verifier core

Copied verbatim from Lexi-TSP/Trust-Standard-Protocol `src/lib/tsp/v3` at
commit a68a3b0 (2026-06-12): canonical.js, hash.js, crypto.js, domains.js,
schema.js, verify-local.js; schema-manifest.js is manifest.js (vendored
2026-06-12 at b742957 for the tsp-mcp verification server). Normative authority is Lexi-TSP/tsp-spec
(ADR-0008); these files are spec-pinned by that repo's conformance suite.
Do not edit here — re-vendor on spec change. sign.js is gateway-local
(signing is not part of the verifier core).

## License verifier core (ADR-0010) — gateway-authored, spec-pinned

`license-domain.js`, `license-schema.js`, `verify-license.js`, and
`license-roots.js` are NOT vendored from the envelope verifier — they are the
TSP License Artifact v1 verifier, which ships FIRST in tsp-gateway per ADR-0010
(SDK ports follow). They reuse the vendored crypto substrate (canonical.js /
crypto.js / hash.js) and are independent of the TrustEnvelope schema and
verify-local.js, which are untouched. Normative authority is Lexi-TSP/tsp-spec
`fixtures/license-v1/` + `tsp-license-v1.schema.json` (ADR-0008); the pinned
fixture snapshot is vendored at `test/fixtures/license-v1/` and
`test/verify-license.test.mjs` checks this core against it. `license-gate.js` is
gateway-local enforcement (the 402 path), not part of the verifier core.
