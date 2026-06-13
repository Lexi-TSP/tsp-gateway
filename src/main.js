#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { Policy } from './policy.js';
import { startGateway } from './proxy.js';
import { createLicenseGate } from './license-gate.js';

const configPath = process.argv[2] ?? 'gateway.config.json';
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const policy = new Policy(config);
if (policy.defaultDecision === 'allow') {
  process.stderr.write('tsp-gateway: WARNING — policy default is "allow" (dev only; production default is block)\n');
}
const licenseGate = createLicenseGate(config);
startGateway({ config, policy, licenseGate }).then(async ({ sessionId, logPath }) => {
  process.stderr.write(`tsp-gateway: session ${sessionId} · evidence -> ${logPath}\n`);
  process.stderr.write(`tsp-gateway: ${await licenseGate.startupStatus()}\n`);
});
