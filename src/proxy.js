/**
 * The mediation core. One gateway = one upstream MCP server (spawned child).
 *
 * Data path:  client (agent) <-> gateway stdio <-> upstream child stdio
 * Decisions:  tools/call is intercepted -> Policy.decide ->
 *   allow             forward; envelope binds params + result hashes
 *   block             fail-closed MCP error result; envelope records denial
 *   approval_required MVP: behaves as block with its own reason code
 * tools/list responses are filtered so blocked tools are never advertised.
 * Everything else passes through with id integrity preserved.
 *
 * Fail-closed: envelope build/sign failure fails the call; upstream death
 * fails all in-flight calls and exits non-zero.
 */
import { spawn } from 'node:child_process';
import { randomUUID, createHash } from 'node:crypto';
import { appendFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';

import { createLineReader, writeMessage } from './jsonrpc.js';
import { createEnvelopeChain } from './envelope.js';
import { generateSessionKeys } from './core/sign.js';
import { sha256Hex } from './core/hash.js';

export const GATEWAY_VERSION = '0.1.0';

const blockedResult = (id, toolName, reason) => ({
  jsonrpc: '2.0',
  id,
  result: {
    content: [{ type: 'text', text: `tsp-gateway: call to "${toolName}" ${reason === 'approval_required' ? 'requires approval' : 'blocked by policy'} (fail-closed)` }],
    isError: true,
  },
});

export const startGateway = async ({ config, policy, stdin = process.stdin, stdout = process.stdout, stderr = process.stderr, evidenceDir }) => {
  const sessionId = randomUUID().slice(0, 8);
  const keys = await generateSessionKeys();
  const dir = evidenceDir ?? config.evidenceDir ?? './evidence';
  mkdirSync(dir, { recursive: true });
  const logPath = path.join(dir, `evidence-${sessionId}.jsonl`);
  const keyPath = path.join(dir, `session-${sessionId}.publickey.json`);
  writeFileSync(keyPath, JSON.stringify(keys.publicJwk, null, 2) + '\n');

  const chain = createEnvelopeChain({ sessionId, keys, policyVersion: policy.version, gatewayVersion: GATEWAY_VERSION });
  const emit = async (record) => {
    const envelope = await chain.emit(record);
    appendFileSync(logPath, JSON.stringify(envelope) + '\n');
    return envelope;
  };

  const upstream = spawn(config.upstream.command, config.upstream.args ?? [], { stdio: ['pipe', 'pipe', 'inherit'] });
  const pendingToolCalls = new Map();
  const pendingToolLists = new Set();

  const hashOf = (value) => createHash('sha256').update(JSON.stringify(value ?? null)).digest('hex');

  // client -> gateway
  stdin.on('data', createLineReader(async (msg) => {
    try {
      if (msg.method === 'tools/call' && msg.id !== undefined) {
        const toolName = msg.params?.name;
        const decision = policy.decide(toolName);
        if (decision !== 'allow') {
          await emit({ kind: 'tool_call', tool: String(toolName), decision, paramsHash: hashOf(msg.params) });
          writeMessage(stdout, blockedResult(msg.id, String(toolName), decision));
          return;
        }
        pendingToolCalls.set(msg.id, { tool: toolName, paramsHash: hashOf(msg.params) });
        writeMessage(upstream.stdin, msg);
        return;
      }
      if (msg.method === 'tools/list' && msg.id !== undefined) pendingToolLists.add(msg.id);
      writeMessage(upstream.stdin, msg);
    } catch (error) {
      if (msg?.id !== undefined) {
        writeMessage(stdout, { jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: `tsp-gateway internal error (fail-closed): ${String(error)}` } });
      }
    }
  }));

  // upstream -> gateway
  upstream.stdout.on('data', createLineReader(async (msg) => {
    try {
      if (msg.id !== undefined && pendingToolCalls.has(msg.id)) {
        const { tool, paramsHash } = pendingToolCalls.get(msg.id);
        pendingToolCalls.delete(msg.id);
        await emit({ kind: 'tool_call', tool, decision: 'allow', paramsHash, resultHash: hashOf(msg.result ?? msg.error), upstreamError: msg.error !== undefined || msg.result?.isError === true });
        writeMessage(stdout, msg);
        return;
      }
      if (msg.id !== undefined && pendingToolLists.has(msg.id)) {
        pendingToolLists.delete(msg.id);
        if (Array.isArray(msg.result?.tools)) {
          msg.result.tools = msg.result.tools.filter((t) => policy.decide(t?.name) !== 'block');
        }
        writeMessage(stdout, msg);
        return;
      }
      writeMessage(stdout, msg);
    } catch (error) {
      stderr.write(`tsp-gateway: evidence emission failed, dropping response (fail-closed): ${String(error)}\n`);
      if (msg?.id !== undefined) {
        writeMessage(stdout, { jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: 'tsp-gateway: evidence emission failed (fail-closed)' } });
      }
    }
  }));

  upstream.on('exit', (code) => {
    stderr.write(`tsp-gateway: upstream exited (${code})\n`);
    process.exitCode = code === 0 ? 0 : 1;
  });

  await emit({ kind: 'session_start', tool: null, decision: 'allow', paramsHash: hashOf({ upstream: config.upstream.command }), toolsMounted: [...policy.allow] });
  return { sessionId, logPath, keyPath, upstream };
};
