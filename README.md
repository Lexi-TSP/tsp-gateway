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

## Status

MVP (v0.1.0). Interactive approvals, real key binding to trust manifests, and
multi-upstream routing are next. The verifier core in `src/core/` is vendored
verbatim from the spec-pinned reference implementation (see
`src/core/PROVENANCE.md`); every emitted envelope must verify against it —
`test/envelope.test.mjs` enforces the roundtrip including the ADR-0002
tamper-rejection profile.

Trust is not earned. It is given — to what can be verified.
