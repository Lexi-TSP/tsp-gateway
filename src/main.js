#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { Policy } from './policy.js';
import { startGateway } from './proxy.js';

const configPath = process.argv[2] ?? 'gateway.config.json';
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const policy = new Policy(config);
if (policy.defaultDecision === 'allow') {
  process.stderr.write('tsp-gateway: WARNING — policy default is "allow" (dev only; production default is block)\n');
}
startGateway({ config, policy }).then(({ sessionId, logPath }) => {
  process.stderr.write(`tsp-gateway: session ${sessionId} · evidence -> ${logPath}\n`);
});
