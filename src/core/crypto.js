const ED25519_ALGORITHM = { name: 'Ed25519' };

export const importPublicKeyJwk = (jwk) =>
  crypto.subtle.importKey('jwk', jwk, ED25519_ALGORITHM, true, ['verify']);

export const verifyEd25519 = (publicKey, signature, data) =>
  crypto.subtle.verify(ED25519_ALGORITHM, publicKey, signature, data);

export const base64ToBytes = (value) => {
  if (typeof atob === 'function') {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  }

  return Uint8Array.from(Buffer.from(value, 'base64'));
};
