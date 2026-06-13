/**
 * Pinned license-root public key set — ADR-0010 Decision 2.
 *
 * The license-root is the offline trust anchor. Its PUBLIC key set is pinned
 * INTO the gateway distribution; the offline root signs short-lived issuer
 * credentials, and verify_license() validates license -> issuer -> this pinned
 * root entirely offline (no phone-home). Rotating this set is an emergency,
 * out-of-band event by design.
 *
 * PUBLIC keys only — never any private material (same rule as everywhere in TSP).
 * Each entry: { rootKeyId: string, publicKey: <Ed25519 public JWK> }.
 *
 * Populated from the offline license-root ceremony (operator-run). With an
 * empty pin and no dev override, enabling licensing fails closed at startup —
 * you cannot verify a chain to a root you do not trust.
 */
export const PINNED_LICENSE_ROOTS = [
  // Pinned from the offline license-root ceremony (2026-06-13). PUBLIC key only.
  {
    rootKeyId: 'tsp-license-root-2026',
    publicKey: { kty: 'OKP', crv: 'Ed25519', x: '_NYL4s-z7wifu0SYAJX797G4JVk10p3rllmQ-qwYMAg' },
  },
];
