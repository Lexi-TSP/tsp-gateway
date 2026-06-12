# Vendored TSP v3 verifier core

Copied verbatim from Lexi-TSP/Trust-Standard-Protocol `src/lib/tsp/v3` at
commit a68a3b0 (2026-06-12): canonical.js, hash.js, crypto.js, domains.js,
schema.js, verify-local.js; schema-manifest.js is manifest.js (vendored
2026-06-12 at b742957 for the tsp-mcp verification server). Normative authority is Lexi-TSP/tsp-spec
(ADR-0008); these files are spec-pinned by that repo's conformance suite.
Do not edit here — re-vendor on spec change. sign.js is gateway-local
(signing is not part of the verifier core).
