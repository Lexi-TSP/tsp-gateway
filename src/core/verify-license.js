/**
 * verify_license() — TSP License Artifact v1 offline verifier (ADR-0010).
 *
 * Normative invariant (ADR-0010): a license MUST be verifiable WITHOUT
 * contacting LexiCo. This function performs no network I/O. It validates a
 * `tsp.license-bundle.v1` through the two-tier offline trust hierarchy:
 *
 *     license  --signed by-->  issuer  --signed by-->  pinned license-root
 *
 * It reuses the TSP cryptographic substrate (canonicalize / Ed25519 / Web
 * Crypto) and is independent of verifyLocal() / the TrustEnvelope schema,
 * which are NOT touched (ADR-0010 Decision 1).
 *
 * Returns a deterministic { ok, reason, detail, ... } in a CLOSED vocabulary.
 * The gateway maps any ok=false to the fail-closed `unlicensed_platform`
 * decision at the 402 path; the granular `reason` is recorded for evidence.
 *
 * Reason vocabulary (closed):
 *   ok:true   -> 'valid' | 'valid_in_grace'
 *   ok:false  -> schema_invalid | unsupported_artifact | issuer_mismatch
 *              | license_signature_invalid | untrusted_root
 *              | issuer_credential_invalid | issuer_not_yet_valid
 *              | issuer_expired | license_not_yet_valid | license_expired
 *              | origin_mismatch | module_not_licensed
 */
import { canonicalize } from './canonical.js';
import { importPublicKeyJwk, verifyEd25519, base64ToBytes } from './crypto.js';
import { buildLicenseSigningDomain, buildIssuerCredentialSigningDomain } from './license-domain.js';
import { validateLicenseBundleShape, LICENSE_ARTIFACT_TYPE } from './license-schema.js';

const encoder = new TextEncoder();

const fail = (reason, detail) => ({ ok: false, reason, detail });
const pass = (reason, detail, extra) => ({ ok: true, reason, detail, ...extra });

const toMs = (value) => {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return value;
  return Date.parse(value);
};

const verifyCanonicalEd25519 = async (publicJwk, signatureBase64, body) => {
  const publicKey = await importPublicKeyJwk(publicJwk);
  const sigBytes = base64ToBytes(signatureBase64);
  return verifyEd25519(publicKey, sigBytes, encoder.encode(canonicalize(body)));
};

/**
 * @param {object} bundle   parsed tsp.license-bundle.v1
 * @param {object} config   { origin, trustedRootKeys: [{ rootKeyId, publicKey }], requiredModules?: string[] }
 * @param {Date|string|number} now
 */
export const verifyLicense = async (bundle, config, now) => {
  // --- config sanity: misconfiguration is a programmer error -> fail-closed at the call site ---
  if (typeof config !== 'object' || config === null) throw new Error('verifyLicense: config must be an object');
  if (typeof config.origin !== 'string' || config.origin.length === 0) {
    throw new Error('verifyLicense: config.origin (configured trust-manifest origin) is required');
  }
  if (!Array.isArray(config.trustedRootKeys) || config.trustedRootKeys.length === 0) {
    throw new Error('verifyLicense: config.trustedRootKeys must be a non-empty pinned root set');
  }
  const nowMs = toMs(now);
  if (Number.isNaN(nowMs)) throw new Error('verifyLicense: `now` is not a valid time');
  const requiredModules = config.requiredModules ?? [];

  // 1. Structural shape (closed allowlist) — must pass before any signature work.
  const schemaErrors = validateLicenseBundleShape(bundle);
  if (schemaErrors.length > 0) return fail('schema_invalid', schemaErrors.join('; '));

  const license = bundle.license;
  const cred = bundle.issuerCredential.credential;

  // 2. Artifact / version gate.
  if (license.artifact_type !== LICENSE_ARTIFACT_TYPE) {
    return fail('unsupported_artifact', `license.artifact_type ${license.artifact_type} is not supported`);
  }

  // 3. Verify license signature against the BUNDLED issuer public key.
  let licenseSigOk;
  try {
    licenseSigOk = await verifyCanonicalEd25519(
      cred.issuerPublicKey,
      bundle.licenseSignature.signature,
      buildLicenseSigningDomain(license),
    );
  } catch (error) {
    return fail('license_signature_invalid', `license signature could not be verified: ${String(error)}`);
  }
  if (!licenseSigOk) return fail('license_signature_invalid', 'license signature does not verify against the bundled issuer key');

  // 4. Verify the issuer credential against the PINNED license-root set.
  const root = config.trustedRootKeys.find((r) => r.rootKeyId === cred.rootKeyId);
  if (!root) return fail('untrusted_root', `issuer credential references root "${cred.rootKeyId}" which is not in the pinned root set`);
  let credSigOk;
  try {
    credSigOk = await verifyCanonicalEd25519(
      root.publicKey,
      bundle.issuerCredential.rootSignature.signature,
      buildIssuerCredentialSigningDomain(cred),
    );
  } catch (error) {
    return fail('issuer_credential_invalid', `issuer credential signature could not be verified: ${String(error)}`);
  }
  if (!credSigOk) return fail('issuer_credential_invalid', 'issuer credential does not verify against the pinned license-root');

  // 5. Issuer<->license binding.
  if (license.issuer_id !== cred.issuer_id) {
    return fail('issuer_mismatch', `license issuer_id "${license.issuer_id}" does not match credential issuer_id "${cred.issuer_id}"`);
  }

  // 6. Issuer validity window.
  const issuerFrom = toMs(cred.validFrom);
  const issuerUntil = toMs(cred.validUntil);
  if (nowMs < issuerFrom) return fail('issuer_not_yet_valid', `issuer credential not valid until ${cred.validFrom}`);
  if (nowMs > issuerUntil) return fail('issuer_expired', `issuer credential expired at ${cred.validUntil}`);

  // 7. License validity window, with signed-only grace.
  const licenseFrom = toMs(license.validFrom);
  const licenseUntil = toMs(license.validUntil);
  if (nowMs < licenseFrom) return fail('license_not_yet_valid', `license not valid until ${license.validFrom}`);
  let inGrace = false;
  if (nowMs > licenseUntil) {
    // Grace exists ONLY if explicitly encoded and signed; the verifier never invents it.
    if (license.graceUntil !== undefined && nowMs <= toMs(license.graceUntil)) {
      inGrace = true;
    } else {
      return fail('license_expired', `license expired at ${license.validUntil}${license.graceUntil ? ` (grace ended ${license.graceUntil})` : ''}`);
    }
  }

  // 8. Per-origin binding (tamper-evident, not copy-proof — ADR-0010 Decision 3).
  const allowed = [license.subject.origin, ...(license.subject.allowedOrigins ?? [])];
  if (!allowed.includes(config.origin)) {
    return fail('origin_mismatch', `license subject origin(s) ${JSON.stringify(allowed)} do not include configured origin "${config.origin}"`);
  }

  // 9. Module entitlement — default-deny per feature.
  const missing = requiredModules.filter((m) => !license.modules.includes(m));
  if (missing.length > 0) {
    return fail('module_not_licensed', `required module(s) not licensed: ${missing.join(', ')}`);
  }

  // 10. Deterministic pass.
  return pass(
    inGrace ? 'valid_in_grace' : 'valid',
    inGrace ? `license valid (in signed grace until ${license.graceUntil})` : 'license verified offline',
    {
      inGrace,
      license: {
        license_id: license.license_id,
        issuer_id: license.issuer_id,
        edition: license.edition,
        origin: license.subject.origin,
        modules: license.modules,
        validUntil: license.validUntil,
        graceUntil: license.graceUntil,
      },
    },
  );
};
