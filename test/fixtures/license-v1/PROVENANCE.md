# Vendored license-v1 fixtures

Pinned snapshot copied from `Lexi-TSP/tsp-spec` `fixtures/license-v1/` +
`conformance/license-expectations.json`. Normative authority is tsp-spec
(ADR-0008). Re-vendor on spec change. These drive
`test/verify-license.test.mjs`, which runs the gateway's REAL
`src/core/verify-license.js` against the same vectors the spec's
`run-license.mjs` asserts — the cross-implementation pin for verify_license().
