const REQUIRES_ESCAPE = /[\x00-\x1f"\\]/g;

const ESCAPE_MAP = {
  '\b': '\\b',
  '\t': '\\t',
  '\n': '\\n',
  '\f': '\\f',
  '\r': '\\r',
  '"': '\\"',
  '\\': '\\\\',
};

const escapeChar = (char) => {
  if (char in ESCAPE_MAP) {
    return ESCAPE_MAP[char];
  }

  return `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`;
};

const canonicalString = (value) => `"${value.replace(REQUIRES_ESCAPE, escapeChar)}"`;

const canonicalNumber = (value) => {
  if (!Number.isFinite(value)) {
    throw new Error(`canonicalize: non-finite number not allowed: ${value}`);
  }

  if (Object.is(value, -0)) {
    return '0';
  }

  return JSON.stringify(value);
};

export const canonicalize = (value) => {
  if (value === null) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    return canonicalNumber(value);
  }

  if (typeof value === 'string') {
    return canonicalString(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value).sort((a, b) => {
      if (a < b) return -1;
      if (a > b) return 1;
      return 0;
    });

    return `{${keys.map((key) => `${canonicalString(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }

  throw new Error(`canonicalize: unsupported value type: ${typeof value}`);
};
