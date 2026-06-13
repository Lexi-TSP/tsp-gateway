/**
 * License gate — gateway-local enforcement wrapper for verify_license()
 * (ADR-0010, the `402 unlicensed_platform` path). NOT part of the verifier
 * core: it wires the free, open core verifier to the commercial gating policy.
 *
 * Fail-closed by construction:
 *  - no `license` config            -> NO_LICENSE_GATE (no tool is gated; backwards compatible)
 *  - `license` config present but   -> constructor THROWS, gateway refuses to start
 *    misconfigured / no pinned root
 *  - a gated tool with no/invalid   -> check() returns ok:false, reason 'unlicensed_platform'
 *    license at call time
 *
 * The pinned license-root set is the gateway DISTRIBUTION pin (core/license-roots.js).
 * `license.devTrustedRootKeys`, when set, REPLACES that pinned set with dev/test
 * pins (dev-only escape hatch, warned loudly) so a test root never collides with
 * a real distribution-pinned root that happens to share a rootKeyId.
 */
import { readFileSync } from 'node:fs';
import { verifyLicense } from './core/verify-license.js';
import { PINNED_LICENSE_ROOTS } from './core/license-roots.js';

export const NO_LICENSE_GATE = {
  enabled: false,
  status: 'licensing disabled (no license config)',
  isGated: () => false,
  gatedTools: () => [],
  async check() { return { ok: true, reason: 'ungated' }; },
  async startupStatus() { return 'licensing disabled (no license config)'; },
};

export const createLicenseGate = (config, { stderr = process.stderr, now = () => new Date() } = {}) => {
  const lc = config?.license;
  if (lc === undefined) return NO_LICENSE_GATE;
  if (typeof lc !== 'object' || lc === null) throw new Error('license: config.license must be an object');

  for (const key of Object.keys(lc)) {
    if (!['origin', 'gatedModules', 'bundle', 'bundlePath', 'devTrustedRootKeys'].includes(key)) {
      throw new Error(`license: unknown key "${key}"`);
    }
  }
  if (typeof lc.origin !== 'string' || lc.origin.length === 0) {
    throw new Error('license: license.origin (configured trust-manifest origin) is required');
  }
  const gatedModules = lc.gatedModules ?? {};
  if (typeof gatedModules !== 'object' || gatedModules === null || Array.isArray(gatedModules)) {
    throw new Error('license: license.gatedModules must be an object mapping toolName -> moduleId');
  }

  let trustedRootKeys = [...PINNED_LICENSE_ROOTS];
  if (Array.isArray(lc.devTrustedRootKeys) && lc.devTrustedRootKeys.length > 0) {
    stderr.write('tsp-gateway: WARNING — license.devTrustedRootKeys is set; REPLACING the distribution-pinned license-root set with dev/test pins (dev only)\n');
    trustedRootKeys = [...lc.devTrustedRootKeys];
  }
  if (trustedRootKeys.length === 0) {
    throw new Error('tsp-gateway: licensing enabled but the pinned license-root set is empty (run the license-root ceremony, or set license.devTrustedRootKeys for dev) — refusing to start (fail-closed)');
  }

  let bundle = lc.bundle ?? null;
  if (!bundle) {
    const p = lc.bundlePath ?? process.env.TSP_LICENSE_BUNDLE;
    if (p) {
      try { bundle = JSON.parse(readFileSync(p, 'utf8')); }
      catch (error) { throw new Error(`license: could not read license bundle at "${p}": ${String(error)}`); }
    }
  }

  const origin = lc.origin;
  const verify = (requiredModules) => verifyLicense(bundle, { origin, trustedRootKeys, requiredModules }, now());

  return {
    enabled: true,
    isGated: (toolName) => Object.hasOwn(gatedModules, toolName),
    gatedTools: () => Object.keys(gatedModules),

    async check(toolName) {
      const moduleId = gatedModules[toolName];
      if (moduleId === undefined) return { ok: true, reason: 'ungated' };
      if (!bundle) {
        return { ok: false, reason: 'unlicensed_platform', detail: 'no license bundle configured for a gated tool' };
      }
      const r = await verify([moduleId]);
      if (r.ok) return { ok: true, reason: r.reason, inGrace: r.inGrace === true };
      return { ok: false, reason: 'unlicensed_platform', detail: `${r.reason}: ${r.detail}`, licenseReason: r.reason };
    },

    async startupStatus() {
      const gated = Object.keys(gatedModules);
      if (gated.length === 0) return 'licensing enabled; no tools gated';
      if (!bundle) return `licensing enabled; ${gated.length} tool(s) gated; NO license bundle loaded -> gated tools fail closed (402 unlicensed_platform)`;
      const r = await verify([]);
      return r.ok
        ? `licensing enabled; license ${r.reason}${r.inGrace ? ' (in grace)' : ''}; gated tools: ${gated.join(', ')}`
        : `licensing enabled; license INVALID (${r.reason}: ${r.detail}) -> gated tools fail closed (402 unlicensed_platform)`;
    },
  };
};
