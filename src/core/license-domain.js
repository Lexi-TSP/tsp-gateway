/**
 * TSP License Artifact v1 — signing-domain construction (SINGLE SOURCE).
 *
 * Mirrors core/domains.js for the envelope: the license and issuer-credential
 * signing domains are defined exactly once so the offline issuer/ceremony
 * signer and verify_license() cannot diverge. ADR-0010: a license is a SIBLING
 * artifact that reuses the TSP cryptographic substrate (canonicalization,
 * SHA-256, Ed25519, signing-domain discipline) and nothing of the
 * TrustEnvelope semantics. This module does NOT touch the envelope domains.
 *
 * The license body and the issuer-credential body are CLOSED allowlists
 * (see license-schema.js). The signature therefore covers the ENTIRE
 * validated body object — there are no excluded fields (unlike the envelope,
 * whose signatures[] and TSA token are excluded) because each signature lives
 * OUTSIDE the body, in the bundle. Consequence, load-bearing: schema
 * validation MUST run before signature verification, so an injected unknown
 * field is rejected structurally rather than riding along unsigned.
 */

/** Domain for the license signature (issuer-signed): the whole validated license body. */
export const buildLicenseSigningDomain = (license) => license;

/** Domain for the issuer-credential signature (root-signed): the whole validated credential body. */
export const buildIssuerCredentialSigningDomain = (credential) => credential;
