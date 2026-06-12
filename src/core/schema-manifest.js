const PRIVATE_JWK_PARAMETERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];
const manifestFields = [
  'tsp',
  'organization',
  'rootKey',
  'instances',
  'revoked',
  'sequence',
  'issuedAt',
  'acceptableAge',
  'rootSignatureOverManifest',
];
const organizationFields = ['name', 'domain'];
const acceptableAgeFields = ['seconds'];
const instanceFields = ['id', 'publicKey', 'validFrom', 'validUntil', 'rootSignature'];
const revokedFields = ['id', 'revokedAt', 'reason'];
const publicJwkFields = ['kty', 'crv', 'x', 'alg', 'use', 'kid', 'ext', 'key_ops'];

const isRecord = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const isString = (value) => typeof value === 'string';
const isoDateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

const hasOnly = (value, path, allowed, errors) => {
  const allowedSet = new Set(allowed);

  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) {
      errors.push(`${path}.${key} is not allowed`);
    }
  }
};

const requireRecord = (parent, key, path, errors) => {
  const value = parent[key];

  if (!isRecord(value)) {
    errors.push(`${path}.${key} must be an object`);
    return undefined;
  }

  return value;
};

const requireString = (parent, key, path, errors) => {
  const value = parent[key];

  if (!isString(value) || value.length === 0) {
    errors.push(`${path}.${key} must be a non-empty string`);
    return undefined;
  }

  return value;
};

const requireIsoDateTime = (parent, key, path, errors) => {
  const value = requireString(parent, key, path, errors);

  if (value !== undefined && (!isoDateTimePattern.test(value) || Number.isNaN(Date.parse(value)))) {
    errors.push(`${path}.${key} must be an ISO-8601 date-time string`);
  }
};

const validatePublicJwk = (jwk, path, errors) => {
  if (!isRecord(jwk)) {
    errors.push(`${path} must be an object`);
    return;
  }

  hasOnly(jwk, path, publicJwkFields, errors);

  const privateParameters = PRIVATE_JWK_PARAMETERS.filter((parameter) => Object.hasOwn(jwk, parameter));
  if (privateParameters.length > 0) {
    errors.push(`${path} must not contain private JWK parameter(s): ${privateParameters.join(', ')}`);
  }

  if (jwk.kty === 'oct' || Object.hasOwn(jwk, 'k')) {
    errors.push(`${path} must not contain symmetric key material`);
  }

  if (jwk.kty !== 'OKP') {
    errors.push(`${path}.kty must be OKP for Ed25519 public keys`);
  }

  if (jwk.crv !== 'Ed25519') {
    errors.push(`${path}.crv must be Ed25519`);
  }

  if (!isString(jwk.x) || jwk.x.length === 0) {
    errors.push(`${path}.x must be a non-empty public key value`);
  }

  if (jwk.alg !== undefined && jwk.alg !== 'Ed25519' && jwk.alg !== 'EdDSA') {
    errors.push(`${path}.alg must be Ed25519 or EdDSA when present`);
  }
};

const validateOrganization = (organization, errors) => {
  if (!organization) return;

  hasOnly(organization, 'manifest.organization', organizationFields, errors);
  requireString(organization, 'name', 'manifest.organization', errors);
  requireString(organization, 'domain', 'manifest.organization', errors);
};

const validateAcceptableAge = (acceptableAge, errors) => {
  if (!acceptableAge) return;

  hasOnly(acceptableAge, 'manifest.acceptableAge', acceptableAgeFields, errors);

  if (!Number.isFinite(acceptableAge.seconds) || acceptableAge.seconds <= 0) {
    errors.push('manifest.acceptableAge.seconds must be a positive number');
  }
};

const validateInstance = (instance, index, errors) => {
  const path = `manifest.instances[${index}]`;

  if (!isRecord(instance)) {
    errors.push(`${path} must be an object`);
    return;
  }

  hasOnly(instance, path, instanceFields, errors);
  requireString(instance, 'id', path, errors);
  validatePublicJwk(instance.publicKey, `${path}.publicKey`, errors);
  requireIsoDateTime(instance, 'validFrom', path, errors);
  requireIsoDateTime(instance, 'validUntil', path, errors);
  requireString(instance, 'rootSignature', path, errors);
};

const validateRevoked = (entry, index, errors) => {
  const path = `manifest.revoked[${index}]`;

  if (!isRecord(entry)) {
    errors.push(`${path} must be an object`);
    return;
  }

  hasOnly(entry, path, revokedFields, errors);
  requireString(entry, 'id', path, errors);
  requireIsoDateTime(entry, 'revokedAt', path, errors);
  requireString(entry, 'reason', path, errors);
};

export const validateTrustManifest = (manifest) => {
  const errors = [];

  if (!isRecord(manifest)) {
    return { errors: ['manifest must be a JSON object'], ok: false };
  }

  hasOnly(manifest, 'manifest', manifestFields, errors);

  if (manifest.tsp !== '3.0') {
    errors.push('manifest.tsp must be "3.0"');
  }

  validateOrganization(requireRecord(manifest, 'organization', 'manifest', errors), errors);
  validatePublicJwk(manifest.rootKey, 'manifest.rootKey', errors);

  if (!Array.isArray(manifest.instances) || manifest.instances.length === 0) {
    errors.push('manifest.instances must be a non-empty array');
  } else {
    const instanceIds = new Set();
    manifest.instances.forEach((instance, index) => {
      validateInstance(instance, index, errors);

      if (isRecord(instance) && isString(instance.id)) {
        if (instanceIds.has(instance.id)) {
          errors.push(`manifest.instances contains duplicate instance id "${instance.id}"`);
        }
        instanceIds.add(instance.id);
      }
    });
  }

  if (!Array.isArray(manifest.revoked)) {
    errors.push('manifest.revoked must be an array');
  } else {
    manifest.revoked.forEach((entry, index) => validateRevoked(entry, index, errors));
  }

  if (!Number.isInteger(manifest.sequence) || manifest.sequence < 0) {
    errors.push('manifest.sequence must be a non-negative integer');
  }

  requireIsoDateTime(manifest, 'issuedAt', 'manifest', errors);
  validateAcceptableAge(requireRecord(manifest, 'acceptableAge', 'manifest', errors), errors);
  requireString(manifest, 'rootSignatureOverManifest', 'manifest', errors);

  return { errors, ok: errors.length === 0 };
};
