/**
 * TSP License Artifact v1 — structural / shape validation.
 *
 * Closed-allowlist shape validator for the `tsp.license-bundle.v1` container
 * and its two signed bodies (`tsp.license.v1`, `tsp.license-issuer-credential.v1`).
 * Mirrors core/schema.js discipline for the envelope: unknown fields are
 * rejected, so the full body can be safely signed/verified (see license-domain.js).
 *
 * ADR-0010 sibling artifact — this validator is independent of
 * validateTrustEnvelopeShape() and must never be merged into it.
 *
 * Normative authority for these shapes is the tsp-spec license-v1 fixture
 * track + SHA256SUMS (ADR-0008 discipline); this is the reference validator.
 */

const LICENSE_ARTIFACT = 'tsp.license.v1';
const ISSUER_CRED_ARTIFACT = 'tsp.license-issuer-credential.v1';
const BUNDLE_ARTIFACT = 'tsp.license-bundle.v1';

const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const editions = new Set(['trial', 'pro', 'enterprise']);
const PRIVATE_JWK_PARAMETERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

const isRecord = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const isString = (v) => typeof v === 'string';

const hasOnly = (value, path, allowed, errors) => {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) errors.push(`${path}.${key} is not allowed`);
  }
};

const recordAt = (parent, key, path, errors) => {
  const v = parent[key];
  if (!isRecord(v)) { errors.push(`${path}.${key} must be an object`); return undefined; }
  return v;
};

const stringAt = (parent, key, path, errors) => {
  const v = parent[key];
  if (!isString(v) || v.length === 0) { errors.push(`${path}.${key} must be a non-empty string`); return undefined; }
  return v;
};

const dateTimeAt = (parent, key, path, errors) => {
  const v = stringAt(parent, key, path, errors);
  if (v !== undefined && (!dateTimePattern.test(v) || Number.isNaN(Date.parse(v)))) {
    errors.push(`${path}.${key} must be an ISO-8601 date-time string`);
  }
};

const optionalDateTimeAt = (parent, key, path, errors) => {
  if (parent[key] !== undefined) dateTimeAt(parent, key, path, errors);
};

const stringArrayAt = (parent, key, path, errors, { optional = false } = {}) => {
  const v = parent[key];
  if (v === undefined && optional) return;
  if (!Array.isArray(v)) { errors.push(`${path}.${key} must be an array`); return; }
  v.forEach((entry, i) => {
    if (!isString(entry)) errors.push(`${path}.${key}[${i}] must be a string`);
  });
};

const ed25519PublicJwkAt = (parent, key, path, errors) => {
  const jwk = parent[key];
  if (!isRecord(jwk)) { errors.push(`${path}.${key} must be an object`); return; }
  const p = `${path}.${key}`;
  hasOnly(jwk, p, ['kty', 'crv', 'x', 'alg', 'use', 'kid', 'ext', 'key_ops'], errors);
  const priv = PRIVATE_JWK_PARAMETERS.filter((k) => Object.hasOwn(jwk, k));
  if (priv.length > 0) errors.push(`${p} must not contain private JWK parameter(s): ${priv.join(', ')}`);
  if (jwk.kty !== 'OKP') errors.push(`${p}.kty must be OKP for Ed25519 public keys`);
  if (jwk.crv !== 'Ed25519') errors.push(`${p}.crv must be Ed25519`);
  if (!isString(jwk.x) || jwk.x.length === 0) errors.push(`${p}.x must be a non-empty public key value`);
  if (jwk.alg !== undefined && jwk.alg !== 'Ed25519' && jwk.alg !== 'EdDSA') {
    errors.push(`${p}.alg must be Ed25519 or EdDSA when present`);
  }
};

const signatureBlockAt = (parent, key, path, errors) => {
  const block = recordAt(parent, key, path, errors);
  if (!block) return;
  const p = `${path}.${key}`;
  hasOnly(block, p, ['algorithm', 'signature'], errors);
  const alg = stringAt(block, 'algorithm', p, errors);
  if (alg !== undefined && alg !== 'ed25519') errors.push(`${p}.algorithm must be ed25519`);
  stringAt(block, 'signature', p, errors);
};

const validateLicenseBody = (license, errors) => {
  if (!license) return;
  hasOnly(
    license,
    'license',
    ['artifact_type', 'license_id', 'issuer_id', 'subject', 'edition', 'modules', 'features', 'issuedAt', 'validFrom', 'validUntil', 'graceUntil'],
    errors,
  );
  const at = stringAt(license, 'artifact_type', 'license', errors);
  if (at !== undefined && at !== LICENSE_ARTIFACT) errors.push(`license.artifact_type must be "${LICENSE_ARTIFACT}"`);
  stringAt(license, 'license_id', 'license', errors);
  stringAt(license, 'issuer_id', 'license', errors);

  const subject = recordAt(license, 'subject', 'license', errors);
  if (subject) {
    hasOnly(subject, 'license.subject', ['origin', 'allowedOrigins', 'organization'], errors);
    stringAt(subject, 'origin', 'license.subject', errors);
    stringAt(subject, 'organization', 'license.subject', errors);
    stringArrayAt(subject, 'allowedOrigins', 'license.subject', errors, { optional: true });
  }

  const edition = stringAt(license, 'edition', 'license', errors);
  if (edition !== undefined && !editions.has(edition)) {
    errors.push('license.edition must be trial, pro, or enterprise');
  }
  stringArrayAt(license, 'modules', 'license', errors);
  stringArrayAt(license, 'features', 'license', errors, { optional: true });
  dateTimeAt(license, 'issuedAt', 'license', errors);
  dateTimeAt(license, 'validFrom', 'license', errors);
  dateTimeAt(license, 'validUntil', 'license', errors);
  optionalDateTimeAt(license, 'graceUntil', 'license', errors);
};

const validateIssuerCredential = (issuerCredential, errors) => {
  if (!issuerCredential) return;
  hasOnly(issuerCredential, 'issuerCredential', ['credential', 'rootSignature'], errors);

  const cred = recordAt(issuerCredential, 'credential', 'issuerCredential', errors);
  if (cred) {
    hasOnly(cred, 'issuerCredential.credential', ['artifact_type', 'issuer_id', 'issuerPublicKey', 'validFrom', 'validUntil', 'rootKeyId'], errors);
    const at = stringAt(cred, 'artifact_type', 'issuerCredential.credential', errors);
    if (at !== undefined && at !== ISSUER_CRED_ARTIFACT) {
      errors.push(`issuerCredential.credential.artifact_type must be "${ISSUER_CRED_ARTIFACT}"`);
    }
    stringAt(cred, 'issuer_id', 'issuerCredential.credential', errors);
    ed25519PublicJwkAt(cred, 'issuerPublicKey', 'issuerCredential.credential', errors);
    dateTimeAt(cred, 'validFrom', 'issuerCredential.credential', errors);
    dateTimeAt(cred, 'validUntil', 'issuerCredential.credential', errors);
    stringAt(cred, 'rootKeyId', 'issuerCredential.credential', errors);
  }

  signatureBlockAt(issuerCredential, 'rootSignature', 'issuerCredential', errors);
};

export const validateLicenseBundleShape = (value) => {
  const errors = [];
  if (!isRecord(value)) return ['bundle must be an object'];

  hasOnly(value, 'bundle', ['artifact_type', 'license', 'licenseSignature', 'issuerCredential'], errors);
  const at = stringAt(value, 'artifact_type', 'bundle', errors);
  if (at !== undefined && at !== BUNDLE_ARTIFACT) errors.push(`bundle.artifact_type must be "${BUNDLE_ARTIFACT}"`);

  validateLicenseBody(recordAt(value, 'license', 'bundle', errors), errors);
  signatureBlockAt(value, 'licenseSignature', 'bundle', errors);
  validateIssuerCredential(recordAt(value, 'issuerCredential', 'bundle', errors), errors);

  return errors;
};

export const LICENSE_ARTIFACT_TYPE = LICENSE_ARTIFACT;
export const ISSUER_CREDENTIAL_ARTIFACT_TYPE = ISSUER_CRED_ARTIFACT;
export const LICENSE_BUNDLE_ARTIFACT_TYPE = BUNDLE_ARTIFACT;
