> ## ⚠️ TSP public alpha preview
>
> This repository contains historical TSP alpha-preview materials. It is not a final TSP release, is not certified for production use, and does not grant any right to claim TSP compatibility, TSP certification, TrustBadge authorization, or participation in the official TSP integrity domain.
>
> TSP v3.1+ is governed by the LexiCo TSP License and official conformance process.

<!-- tsp-alpha-banner:end -->

# TSP Gateway

An MCP proxy that mediates agent tool calls under a fail-closed policy and
emits signed [TSP v3.0](https://github.com/Lexi-TSP/tsp-spec) trust envelopes
as evidence exhaust.

```
agent (any MCP client) ──> tsp-gateway ──> your real MCP tool server
                              │
                              ├─ policy: allow / block / require-approval
                              └─ evidence: signed, ledger-chained envelopes
                                 verifiable by the public TSP verifier
```

**Why:** agents become risky when they call tools. The gateway gives you the
two things you want selfishly — least-privilege tool permissioning and a
replayable record of what actually happened — and produces, as a side effect,
machine-verifiable evidence of every decision (the thing auditors, customers,
and the EU AI Act's record-keeping obligations ask for). Evidence is exhaust,
not ceremony: zero configuration in dev (ephemeral session keys, public key
exported beside the log), deploy-time key binding in production.

**Fail-closed by construction:** unknown tools are blocked by default; blocked
tools are not even advertised in `tools/list`; a policy that fails to parse
refuses to start; an envelope that fails to sign fails the call.

## Quick start

```bash
npm test        # policy, envelope-vs-spec-verifier roundtrip, e2e through real stdio
npm run demo    # watch allowed/blocked/approval calls produce a verifiable log
```

Point your agent at the gateway instead of the tool server:

```json
{ "command": "tsp-gateway", "args": ["gateway.config.json"] }
```

```json
{
  "upstream": { "command": "node", "args": ["your-mcp-server.js"] },
  "evidenceDir": "./evidence",
  "policy": {
    "allow": ["read_file", "search"],
    "block": ["delete_file"],
    "requireApproval": ["send_email"],
    "default": "block"
  }
}
```

## tsp-mcp - verification tools for AI assistants

The same repo ships `tsp-mcp`, an MCP server exposing the TSP verifier as
tools - so any MCP-speaking assistant (Claude, etc.) can verify evidence
natively in conversation: `verify_envelope`, `validate_manifest`,
`verify_evidence_log` (per-envelope verdicts + ledger-chain continuity), and
`canonical_hash`. Verification only: the server holds no keys and signs
nothing. Add it to your assistant's MCP config:

```json
{ "command": "node", "args": ["src/mcp-server.js"] }
```

Paste an envelope, ask "is this genuine?" - the verdict comes from the same
spec-pinned core, not from the model's opinion.

## Licensing — `402 unlicensed_platform` (ADR-0010)

Licensing is **opt-in and off by default**: with no `license` block in the
config, no tool is gated and the gateway behaves exactly as before.

When a `license` block is present, listed *commercial* tools are gated. A gated
tool requires a valid TSP License Artifact v1 (`tsp.license.v1`) verified
**fully offline** by `verify_license()` (license -> issuer -> the gateway's
pinned license-root). If the license is missing, expired (past `validUntil`
with no signed `graceUntil`), bound to a different origin, or does not entitle
the required module, the call **fails closed** with `unlicensed_platform` (the
stdio analog of HTTP `402`) and the gated tool is hidden from `tools/list`.

```jsonc
// gateway.config.license-example.json
"license": {
  "origin": "https://customer.example",     // this deployment's trust-manifest origin
  "bundlePath": "./license.json",            // or env TSP_LICENSE_BUNDLE
  "gatedModules": { "read_note": "gateway-pro" }  // toolName -> required module (default-deny)
}
```

The pinned license-root set ships in the distribution (`src/core/license-roots.js`,
populated by the offline license-root ceremony, operator-run). `license.devTrustedRootKeys`
is a dev/test-only escape hatch, warned loudly at startup. Verification is free
and open; **issuance/renewal is the commercial layer** — see ADR-0010. The
license is a *sibling* artifact: the TrustEnvelope schema, `verify_local()`, and
the v3.0 conformance gate are untouched.

## Status

MVP (v0.1.0). Interactive approvals, real key binding to trust manifests, and
multi-upstream routing are next. The verifier core in `src/core/` is vendored
verbatim from the spec-pinned reference implementation (see
`src/core/PROVENANCE.md`); every emitted envelope must verify against it —
`test/envelope.test.mjs` enforces the roundtrip including the ADR-0002
tamper-rejection profile.

Trust is not earned. It is given — to what can be verified.
