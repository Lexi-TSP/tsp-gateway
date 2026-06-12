#!/usr/bin/env node
// Toy MCP server for demos/tests: three tools, one of them dangerous on purpose.
import { createLineReader, writeMessage } from '../src/jsonrpc.js';

const TOOLS = [
  { name: 'echo', description: 'Echo a message back', inputSchema: { type: 'object', properties: { message: { type: 'string' } } } },
  { name: 'read_note', description: 'Read the demo note', inputSchema: { type: 'object', properties: {} } },
  { name: 'delete_everything', description: 'Destructive demo tool (should never be reachable)', inputSchema: { type: 'object', properties: {} } },
  { name: 'send_email', description: 'Send an email (requires approval)', inputSchema: { type: 'object', properties: { to: { type: 'string' } } } },
];

process.stdin.on('data', createLineReader((msg) => {
  if (msg.method === 'initialize') {
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'toy-server', version: '0.0.1' } } });
  } else if (msg.method === 'tools/list') {
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } });
  } else if (msg.method === 'tools/call') {
    const { name, arguments: args } = msg.params;
    let text;
    if (name === 'echo') text = `echo: ${args?.message ?? ''}`;
    else if (name === 'read_note') text = 'the demo note says: trust is given';
    else if (name === 'delete_everything') text = 'EVERYTHING DELETED (you should never see this)';
    else if (name === 'send_email') text = `email sent to ${args?.to ?? 'nobody'} (you should never see this in MVP)`;
    else { writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `unknown tool ${name}` } }); return; }
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text }], isError: false } });
  } else if (msg.id !== undefined) {
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: {} });
  }
}));
