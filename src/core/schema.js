const TSP_V3_VERSION = '3.0';
const sha256Pattern = /^[a-f0-9]{64}$/;
const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const lowercaseHexPattern = /^[a-f0-9]+$/;
const sourceTypes = new Set([
  'legal-database',
  'government-website',
  'official-document',
  'academic-paper',
  'verified-website',
  'model-knowledge',
  'user-input',
  'unknown',
]);
const contentTypes = new Set(['text', 'document', 'structured']);
const severities = new Set(['low', 'med', 'high']);
const signatureRoles = new Set(['instance', 'human-reviewer']);

const isRecord = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const isString = (value) => typeof value === 'string';

const hasOnly = (value, path, allowed, errors) => {
  const allowedSet = new Set(allowed);

  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) {
      errors.push(`${path}.${key} is not allowed`);
    }
  }
};

const recordAt = (parent, key, path, errors) => {
  const value = parent[key];

  if (!isRecord(value)) {
    errors.push(`${path}.${key} must be an object`);
    return undefined;
  }

  return value;
};

const arrayAt = (parent, key, path, errors) => {
  const value = parent[key];

  if (!Array.isArray(value)) {
    errors.push(`${path}.${key} must be an array`);
    return undefined;
  }

  return value;
};

const stringAt = (parent, key, path, errors) => {
  const value = parent[key];

  if (!isString(value)) {
    errors.push(`${path}.${key} must be a string`);
    return undefined;
  }

  return value;
};

const optionalStringAt = (parent, key, path, errors) => {
  if (parent[key] !== undefined && !isString(parent[key])) {
    errors.push(`${path}.${key} must be a string`);
  }
};

const booleanAt = (parent, key, path, errors) => {
  if (typeof parent[key] !== 'boolean') {
    errors.push(`${path}.${key} must be a boolean`);
  }
};

const numberAt = (parent, key, path, errors) => {
  if (typeof parent[key] !== 'number' || !Number.isFinite(parent[key])) {
    errors.push(`${path}.${key} must be a finite number`);
  }
};

const integerAt = (parent, key, path, errors) => {
  if (!Number.isInteger(parent[key])) {
    errors.push(`${path}.${key} must be an integer`);
  }
};

const sha256At = (parent, key, path, errors) => {
  const value = stringAt(parent, key, path, errors);

  if (value !== undefined && !sha256Pattern.test(value)) {
    errors.push(`${path}.${key} must be a lowercase sha256 hex string`);
  }
};

const dateTimeAt = (parent, key, path, errors) => {
  const value = stringAt(parent, key, path, errors);

  if (value !== undefined && (!dateTimePattern.test(value) || Number.isNaN(Date.parse(value)))) {
    errors.push(`${path}.${key} must be an ISO-8601 date-time string`);
  }
};

const lowercaseHexAt = (parent, key, path, errors) => {
  const value = stringAt(parent, key, path, errors);

  if (value !== undefined && !lowercaseHexPattern.test(value)) {
    errors.push(`${path}.${key} must be lowercase hexadecimal`);
  }
};

const uriAt = (parent, key, path, errors) => {
  const value = stringAt(parent, key, path, errors);

  if (value === undefined) {
    return;
  }

  try {
    new URL(value);
  } catch {
    errors.push(`${path}.${key} must be a URI`);
  }
};

export const validateTrustEnvelopeShape = (value) => {
  const errors = [];

  if (!isRecord(value)) {
    return ['envelope must be an object'];
  }

  hasOnly(
    value,
    'envelope',
    [
      'tsp',
      'content',
      'declaration',
      'process',
      'alignment',
      'timestamp',
      'ledger',
      'signatures',
      'executionProvenance',
    ],
    errors,
  );

  const tsp = stringAt(value, 'tsp', 'envelope', errors);
  if (tsp !== undefined && tsp !== TSP_V3_VERSION) {
    errors.push(`envelope.tsp must be "${TSP_V3_VERSION}"`);
  }

  validateContent(recordAt(value, 'content', 'envelope', errors), errors);
  validateDeclaration(recordAt(value, 'declaration', 'envelope', errors), errors);
  validateProcess(recordAt(value, 'process', 'envelope', errors), errors);
  validateAlignment(recordAt(value, 'alignment', 'envelope', errors), errors);
  validateTimestamp(recordAt(value, 'timestamp', 'envelope', errors), errors);
  validateLedger(recordAt(value, 'ledger', 'envelope', errors), errors);

  const signatures = arrayAt(value, 'signatures', 'envelope', errors);
  if (signatures !== undefined) {
    if (signatures.length === 0) {
      errors.push('envelope.signatures must contain at least one entry');
    }

    signatures.forEach((entry, index) => validateSignature(entry, `envelope.signatures[${index}]`, errors));
  }

  if (value.executionProvenance !== undefined) {
    validateExecutionProvenance(recordAt(value, 'executionProvenance', 'envelope', errors), errors);
  }

  return errors;
};

const validateContent = (value, errors) => {
  if (!value) return;

  hasOnly(value, 'content', ['type', 'value', 'hash'], errors);
  const type = stringAt(value, 'type', 'content', errors);
  if (type !== undefined && !contentTypes.has(type)) {
    errors.push('content.type must be text, document, or structured');
  }
  stringAt(value, 'value', 'content', errors);
  sha256At(value, 'hash', 'content', errors);
};

const validateDeclaration = (value, errors) => {
  if (!value) return;

  hasOnly(value, 'declaration', ['primarySource', 'citations'], errors);
  const primarySource = recordAt(value, 'primarySource', 'declaration', errors);
  if (primarySource) {
    hasOnly(primarySource, 'declaration.primarySource', ['type', 'url', 'title', 'retrieved'], errors);
    const type = stringAt(primarySource, 'type', 'declaration.primarySource', errors);
    if (type !== undefined && !sourceTypes.has(type)) {
      errors.push('declaration.primarySource.type is not a v3 source type');
    }
    optionalStringAt(primarySource, 'url', 'declaration.primarySource', errors);
    stringAt(primarySource, 'title', 'declaration.primarySource', errors);
    if (primarySource.retrieved !== undefined) {
      dateTimeAt(primarySource, 'retrieved', 'declaration.primarySource', errors);
    }
  }

  arrayAt(value, 'citations', 'declaration', errors)?.forEach((entry, index) => {
    const path = `declaration.citations[${index}]`;
    if (!isRecord(entry)) {
      errors.push(`${path} must be an object`);
      return;
    }
    hasOnly(entry, path, ['url', 'paragraph', 'quote', 'retrieved'], errors);
    stringAt(entry, 'url', path, errors);
    stringAt(entry, 'paragraph', path, errors);
    stringAt(entry, 'quote', path, errors);
    dateTimeAt(entry, 'retrieved', path, errors);
  });
};

const validateProcess = (value, errors) => {
  if (!value) return;

  hasOnly(value, 'process', ['model', 'systemPrompt', 'pipeline'], errors);
  const model = recordAt(value, 'model', 'process', errors);
  if (model) {
    hasOnly(model, 'process.model', ['provider', 'name', 'version', 'temperature', 'contextWindow'], errors);
    stringAt(model, 'provider', 'process.model', errors);
    stringAt(model, 'name', 'process.model', errors);
    stringAt(model, 'version', 'process.model', errors);
    numberAt(model, 'temperature', 'process.model', errors);
    integerAt(model, 'contextWindow', 'process.model', errors);
    if (typeof model.contextWindow === 'number' && model.contextWindow < 0) {
      errors.push('process.model.contextWindow must be non-negative');
    }
  }

  validateSystemPrompt(recordAt(value, 'systemPrompt', 'process', errors), errors);
};

const validateSystemPrompt = (value, errors) => {
  if (!value) return;

  sha256At(value, 'hash', 'process.systemPrompt', errors);
  if ('text' in value) {
    hasOnly(value, 'process.systemPrompt', ['hash', 'text'], errors);
    stringAt(value, 'text', 'process.systemPrompt', errors);
    return;
  }

  hasOnly(value, 'process.systemPrompt', ['hash', 'redacted', 'reason'], errors);
  if (value.redacted !== true) {
    errors.push('process.systemPrompt.redacted must be true');
  }
  stringAt(value, 'reason', 'process.systemPrompt', errors);
};

const validateAlignment = (value, errors) => {
  if (!value) return;

  hasOnly(value, 'alignment', ['uncertainty', 'flags', 'humanReviewRequired', 'policy', 'refusal'], errors);
  arrayAt(value, 'uncertainty', 'alignment', errors)?.forEach((entry, index) => {
    const path = `alignment.uncertainty[${index}]`;
    if (!isRecord(entry)) {
      errors.push(`${path} must be an object`);
      return;
    }
    hasOnly(entry, path, ['field', 'reason', 'severity'], errors);
    stringAt(entry, 'field', path, errors);
    stringAt(entry, 'reason', path, errors);
    const severity = stringAt(entry, 'severity', path, errors);
    if (severity !== undefined && !severities.has(severity)) {
      errors.push(`${path}.severity must be low, med, or high`);
    }
  });

  booleanAt(value, 'humanReviewRequired', 'alignment', errors);
  const policy = recordAt(value, 'policy', 'alignment', errors);
  if (policy) {
    hasOnly(policy, 'alignment.policy', ['id', 'version'], errors);
    stringAt(policy, 'id', 'alignment.policy', errors);
    stringAt(policy, 'version', 'alignment.policy', errors);
  }
};

const validateTimestamp = (value, errors) => {
  if (!value) return;

  hasOnly(value, 'timestamp', ['claimed', 'tsaToken', 'tsaUrl'], errors);
  dateTimeAt(value, 'claimed', 'timestamp', errors);
  stringAt(value, 'tsaToken', 'timestamp', errors);
  uriAt(value, 'tsaUrl', 'timestamp', errors);
};

const validateLedger = (value, errors) => {
  if (!value) return;

  hasOnly(value, 'ledger', ['id', 'prevHash', 'hash'], errors);
  stringAt(value, 'id', 'ledger', errors);
  sha256At(value, 'prevHash', 'ledger', errors);
  sha256At(value, 'hash', 'ledger', errors);
};

const validateSignature = (value, path, errors) => {
  if (!isRecord(value)) {
    errors.push(`${path} must be an object`);
    return;
  }

  hasOnly(value, path, ['role', 'algorithm', 'keyRef', 'signature', 'certChain'], errors);
  const role = stringAt(value, 'role', path, errors);
  if (role !== undefined && !signatureRoles.has(role)) {
    errors.push(`${path}.role must be instance or human-reviewer`);
  }
  const algorithm = stringAt(value, 'algorithm', path, errors);
  if (algorithm !== undefined && algorithm !== 'ed25519') {
    errors.push(`${path}.algorithm must be ed25519`);
  }
  uriAt(value, 'keyRef', path, errors);
  stringAt(value, 'signature', path, errors);
  arrayAt(value, 'certChain', path, errors)?.forEach((entry, index) => {
    if (!isString(entry)) {
      errors.push(`${path}.certChain[${index}] must be a string`);
    }
  });
};

const validateExecutionProvenance = (value, errors) => {
  if (!value) return;

  hasOnly(value, 'executionProvenance', ['spatialBoundary', 'temporalBoundary', 'deterministicOutput'], errors);
  const spatialBoundary = recordAt(value, 'spatialBoundary', 'executionProvenance', errors);
  if (spatialBoundary) {
    hasOnly(
      spatialBoundary,
      'executionProvenance.spatialBoundary',
      ['gateway', 'toolsMounted', 'toolsIsolated', 'o1ConstraintMet'],
      errors,
    );
    stringAt(spatialBoundary, 'gateway', 'executionProvenance.spatialBoundary', errors);
    arrayAt(spatialBoundary, 'toolsMounted', 'executionProvenance.spatialBoundary', errors)?.forEach((entry, index) => {
      if (!isString(entry)) {
        errors.push(`executionProvenance.spatialBoundary.toolsMounted[${index}] must be a string`);
      }
    });
    booleanAt(spatialBoundary, 'toolsIsolated', 'executionProvenance.spatialBoundary', errors);
    booleanAt(spatialBoundary, 'o1ConstraintMet', 'executionProvenance.spatialBoundary', errors);
  }

  const temporalBoundary = recordAt(value, 'temporalBoundary', 'executionProvenance', errors);
  if (temporalBoundary) {
    hasOnly(
      temporalBoundary,
      'executionProvenance.temporalBoundary',
      ['engine', 'tier1AnchorHash', 'totalContextTokens', 'driftDetected'],
      errors,
    );
    stringAt(temporalBoundary, 'engine', 'executionProvenance.temporalBoundary', errors);
    lowercaseHexAt(temporalBoundary, 'tier1AnchorHash', 'executionProvenance.temporalBoundary', errors);
    integerAt(temporalBoundary, 'totalContextTokens', 'executionProvenance.temporalBoundary', errors);
    if (typeof temporalBoundary.totalContextTokens === 'number' && temporalBoundary.totalContextTokens < 0) {
      errors.push('executionProvenance.temporalBoundary.totalContextTokens must be non-negative');
    }
    booleanAt(temporalBoundary, 'driftDetected', 'executionProvenance.temporalBoundary', errors);
  }

  const deterministicOutput = recordAt(value, 'deterministicOutput', 'executionProvenance', errors);
  if (deterministicOutput) {
    hasOnly(deterministicOutput, 'executionProvenance.deterministicOutput', ['status', 'payloadHash'], errors);
    stringAt(deterministicOutput, 'status', 'executionProvenance.deterministicOutput', errors);
    lowercaseHexAt(deterministicOutput, 'payloadHash', 'executionProvenance.deterministicOutput', errors);
  }
};
