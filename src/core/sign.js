/**
 * Gateway-local signing helpers (NOT part of the verifier core).
 * Ephemeral session keys: generated per gateway run, held in memory only,
 * public key exported beside the evidence log. Real deployments bind keys to
 * a published trust manifest at deploy time — never in code or config.
 */
import { canonicalize } from './canonical.js';

const ED25519 = { name: 'Ed25519' };
const encoder = new TextEncoder();

const bytesToBase64 = (bytes) => Buffer.from(bytes).toString('base64');

export const generateSessionKeys = async () => {
  const keyPair = await crypto.subtle.generateKey(ED25519, true, ['sign', 'verify']);
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return {
    publicJwk,
    signCanonical: async (payload) => {
      const sig = await crypto.subtle.sign(ED25519, keyPair.privateKey, encoder.encode(canonicalize(payload)));
      return bytesToBase64(new Uint8Array(sig));
    },
  };
};
