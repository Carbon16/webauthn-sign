/**
 * webauthnsign — server-side verification
 *
 * Import path: "webauthnsign/server"
 *
 * This module uses Node.js built-ins (node:crypto) and is NOT suitable for
 * browser bundles.  Run it only in a trusted server / edge-worker environment.
 */

import * as nodeCrypto from "node:crypto";
import { decodeCbor, decodeCborFirst, type CborValue } from "./cbor.js";
import {
  base64urlToBytes,
  bytesToBase64url,
  formatAaguid,
  concat,
} from "./utils.js";
import type {
  PasskeyCredential,
  ParsedAuthData,
  AuthenticatorFlags,
  VerifyHashOptions,
  VerifyHashResult,
  CoseAlgorithm,
} from "./types.js";

// ---------------------------------------------------------------------------
// SHA-256 (server side, synchronous)
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 digest using Node.js `crypto` (synchronous).
 *
 * Use this to hash your document / data before requesting a passkey signature.
 */
export function sha256(data: Uint8Array | Buffer | string): Uint8Array {
  return new Uint8Array(nodeCrypto.createHash("sha256").update(data).digest());
}

// ---------------------------------------------------------------------------
// Authenticator data parsing
// ---------------------------------------------------------------------------

/**
 * Parse the fixed header of authenticator data (always 37 bytes at the start).
 *
 * Structure (per WebAuthn spec §6.1):
 *   rpIdHash  [0..31]  – SHA-256(rpId)
 *   flags     [32]     – bit field
 *   signCount [33..36] – big-endian uint32
 */
export function parseAuthData(authData: Uint8Array): ParsedAuthData {
  if (authData.length < 37) {
    throw new Error(
      `Authenticator data is too short: got ${authData.length} bytes, need ≥ 37`
    );
  }

  const rpIdHash = authData.slice(0, 32);
  const flagByte = authData[32] as number;
  const view = new DataView(authData.buffer, authData.byteOffset + 33, 4);
  const signCount = view.getUint32(0, false); // big-endian

  const flags: AuthenticatorFlags = {
    up: (flagByte & 0x01) !== 0, // bit 0 – User Presence
    uv: (flagByte & 0x04) !== 0, // bit 2 – User Verification
    be: (flagByte & 0x08) !== 0, // bit 3 – Backup Eligibility
    bs: (flagByte & 0x10) !== 0, // bit 4 – Backup State
    at: (flagByte & 0x40) !== 0, // bit 6 – Attested Credential Data
    ed: (flagByte & 0x80) !== 0, // bit 7 – Extension Data
  };

  return { rpIdHash, flags, signCount };
}

// ---------------------------------------------------------------------------
// Attested credential data (registration only)
// ---------------------------------------------------------------------------

interface AttestedCredentialData {
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  /** Raw CBOR-encoded COSE public key bytes. */
  credentialPublicKeyBytes: Uint8Array;
}

/**
 * Parse the attested credential data that follows the 37-byte header in
 * registration authenticator data (AT flag must be set).
 */
function parseAttestedCredentialData(
  authData: Uint8Array
): AttestedCredentialData {
  // Minimum: 37 (header) + 16 (AAGUID) + 2 (credIdLen) = 55 bytes.
  if (authData.length < 55) {
    throw new Error("Authenticator data too short for attested credential data");
  }

  const aaguid = authData.slice(37, 53);
  const credIdLen = ((authData[53] as number) << 8) | (authData[54] as number);

  // WebAuthn §6.4.1: credential ID must be 1–1023 bytes.
  if (credIdLen === 0 || credIdLen > 1023) {
    throw new Error(
      `credentialId length out of bounds: ${credIdLen} (must be 1–1023 bytes per WebAuthn §6.4.1)`
    );
  }

  if (authData.length < 55 + credIdLen) {
    throw new Error(
      `Authenticator data truncated — credentialIdLength=${credIdLen} but only ${authData.length - 55} bytes remain`
    );
  }

  const credentialId = authData.slice(55, 55 + credIdLen);

  // Decode only the exact COSE key bytes — authData may have extension data
  // appended after the key.  decodeCborFirst returns the consumed byte count
  // so we store a precise slice, allowing decodeCbor's trailing-byte guard to
  // work correctly when the key bytes are later re-decoded for verification.
  const coseKeySlice = authData.slice(55 + credIdLen);
  if (coseKeySlice.length === 0) {
    throw new Error("Authenticator data truncated — no bytes remain for COSE public key");
  }
  const { bytesRead: coseKeyLen } = decodeCborFirst(coseKeySlice);
  const credentialPublicKeyBytes = coseKeySlice.slice(0, coseKeyLen);

  return { aaguid, credentialId, credentialPublicKeyBytes };
}

// ---------------------------------------------------------------------------
// Input size limits
// ---------------------------------------------------------------------------

/** Maximum size in bytes for opaque blobs we parse server-side. */
const MAX_CLIENT_DATA_JSON_BYTES = 4096;     // generous for a JSON object
const MAX_ATTESTATION_OBJECT_BYTES = 32_768; // 32 KB covers any real authenticator
const MAX_AUTH_DATA_BYTES = 32_768;
const MAX_SIGNATURE_BYTES = 1024;            // largest realistic DER-encoded signature

// ---------------------------------------------------------------------------
// clientDataJSON field type guards
// ---------------------------------------------------------------------------

/**
 * Assert that a value parsed from clientDataJSON is a non-empty string.
 * Throws with a clear message if not, preventing obscure downstream errors.
 */
function requireString(obj: Record<string, unknown>, key: string): string {
  const val = obj[key];
  if (typeof val !== "string") {
    throw new TypeError(
      `clientDataJSON.${key} must be a string, got ${val === null ? "null" : typeof val}`
    );
  }
  return val;
}

// ---------------------------------------------------------------------------
// Flag consistency check (shared between registration + assertion)
// ---------------------------------------------------------------------------

/**
 * Enforce per-spec flag invariants that are independent of the ceremony type.
 * §6.1.3: BS MUST NOT be set when BE is not set.
 */
function assertFlagConsistency(flags: AuthenticatorFlags): void {
  if (flags.bs && !flags.be) {
    throw new Error(
      "Authenticator data flag inconsistency: BS (Backup State) is set without BE (Backup Eligibility) — violates WebAuthn §6.1.3"
    );
  }
}

// ---------------------------------------------------------------------------
// COSE key → Node.js KeyObject
// ---------------------------------------------------------------------------

type CoseMap = Map<number, CborValue>;

interface ResolvedKey {
  key: nodeCrypto.KeyObject;
  algorithm: CoseAlgorithm;
}

/** Expected COSE alg value for each key type. */
const EXPECTED_ALG_FOR_KTY: Record<number, number> = {
  2: -7,   // EC2 → ES256
  1: -8,   // OKP → EdDSA
  3: -257, // RSA → RS256
};

/** Minimum RSA modulus length in bytes (2048 bits). */
const MIN_RSA_MODULUS_BYTES = 256;

/**
 * Convert COSE-encoded public key bytes to a Node.js `KeyObject` for
 * cryptographic verification.
 *
 * Supported key types:
 *   - EC2 / P-256 (ES256, alg -7)
 *   - OKP / Ed25519 (EdDSA, alg -8)
 *   - RSA (RS256, alg -257)
 *
 * Security checks performed here:
 *   - kty/alg cross-check: alg must match the expected value for the key type
 *   - RSA modulus length: must be ≥ 2048 bits
 */
function coseKeyToNodeKey(coseKeyBytes: Uint8Array): ResolvedKey {
  const raw = decodeCbor(coseKeyBytes);
  if (!(raw instanceof Map)) {
    throw new TypeError("COSE public key is not a CBOR map");
  }

  // CBOR keys in a COSE key map are integers.  Cast to the numeric-keyed Map.
  const coseKey: CoseMap = raw as unknown as CoseMap;

  const kty = coseKey.get(1) as number | undefined; // Key type
  const alg = coseKey.get(3) as number | undefined; // Algorithm

  // Cross-check: if alg is present it must match the expected algorithm for
  // this key type.  An EC2 key with alg=-257 (RS256) would pass key import
  // but be verified on the wrong crypto path.
  if (kty !== undefined) {
    const expectedAlg = EXPECTED_ALG_FOR_KTY[kty];
    if (expectedAlg !== undefined) {
      // alg MUST be present and MUST match the canonical algorithm for this kty.
      // Accepting a key with no alg field would allow algorithm substitution.
      if (alg === undefined) {
        throw new Error(
          `COSE key is missing the alg field (key 3); expected alg=${expectedAlg} for kty=${kty}`
        );
      }
      if (alg !== expectedAlg) {
        throw new Error(
          `COSE key type/algorithm mismatch: kty=${kty} requires alg=${expectedAlg}, got alg=${alg}`
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // EC2 key (kty = 2) — ES256 / P-256
  // ------------------------------------------------------------------
  if (kty === 2) {
    const crv = coseKey.get(-1);
    const xBytes = coseKey.get(-2);
    const yBytes = coseKey.get(-3);

    if (crv !== 1) {
      throw new Error(`Unsupported EC curve: ${crv} (only P-256 / crv=1 is supported)`);
    }
    if (!(xBytes instanceof Uint8Array) || !(yBytes instanceof Uint8Array)) {
      throw new TypeError("EC public key x / y must be byte strings");
    }
    if (xBytes.length !== 32 || yBytes.length !== 32) {
      throw new Error("P-256 x / y coordinates must each be 32 bytes");
    }

    const jwk: nodeCrypto.JsonWebKey = {
      kty: "EC",
      crv: "P-256",
      x: Buffer.from(xBytes).toString("base64url"),
      y: Buffer.from(yBytes).toString("base64url"),
    };
    const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    return { key, algorithm: -7 };
  }

  // ------------------------------------------------------------------
  // OKP key (kty = 1) — EdDSA / Ed25519
  // ------------------------------------------------------------------
  if (kty === 1) {
    const crv = coseKey.get(-1);
    const xBytes = coseKey.get(-2);

    if (crv !== 6) {
      throw new Error(`Unsupported OKP curve: ${crv} (only Ed25519 / crv=6 is supported)`);
    }
    if (!(xBytes instanceof Uint8Array)) {
      throw new TypeError("OKP public key x must be a byte string");
    }
    if (xBytes.length !== 32) {
      throw new Error("Ed25519 public key must be 32 bytes");
    }

    const jwk: nodeCrypto.JsonWebKey = {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(xBytes).toString("base64url"),
    };
    const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    return { key, algorithm: -8 };
  }

  // ------------------------------------------------------------------
  // RSA key (kty = 3) — RS256
  // ------------------------------------------------------------------
  if (kty === 3) {
    const nBytes = coseKey.get(-1);
    const eBytes = coseKey.get(-2);

    if (!(nBytes instanceof Uint8Array) || !(eBytes instanceof Uint8Array)) {
      throw new TypeError("RSA public key n / e must be byte strings");
    }

    // Reject undersized RSA keys (< 2048 bits = 256 bytes).
    if (nBytes.length < MIN_RSA_MODULUS_BYTES) {
      throw new Error(
        `RSA modulus is too short: got ${nBytes.length * 8} bits, minimum is ${MIN_RSA_MODULUS_BYTES * 8} bits`
      );
    }

    const jwk: nodeCrypto.JsonWebKey = {
      kty: "RSA",
      n: Buffer.from(nBytes).toString("base64url"),
      e: Buffer.from(eBytes).toString("base64url"),
    };
    const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    return { key, algorithm: -257 };
  }

  throw new Error(`Unsupported COSE key type (kty): ${kty}`);
}

// ---------------------------------------------------------------------------
// Timing-safe equality
// ---------------------------------------------------------------------------

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Length comparison is not secret, so no timing concern here.
  if (a.length !== b.length) return false;
  return nodeCrypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Registration verification
// ---------------------------------------------------------------------------

export interface ParseRegistrationOptions {
  /** The challenge your server generated and sent to the browser. */
  expectedChallenge: Uint8Array;
  /** Expected origin, e.g. "https://example.com". */
  expectedOrigin: string;
  /** Expected relying party ID, e.g. "example.com". */
  expectedRpId: string;
  /**
   * Whether User Verification must be confirmed (default `true`).
   * Set to `false` only for security keys that have no PIN/biometric.
   */
  requireUserVerification?: boolean;
}

/**
 * Parse and verify a raw registration response produced by
 * {@link registerPasskey} on the client.
 *
 * **You must persist the returned {@link PasskeyCredential}** — specifically
 * `id`, `publicKey`, `algorithm`, and `signCount` — so you can verify future
 * signatures from this credential.
 *
 * @throws if any security check fails.
 */
export async function parseRegistrationResponse(
  response: {
    attestationObject: Uint8Array;
    clientDataJSON: Uint8Array;
    transports?: string[];
  },
  opts: ParseRegistrationOptions
): Promise<PasskeyCredential> {
  // ------------------------------------------------------------------
  // 0. Input size limits — reject oversized blobs before any parsing.
  // ------------------------------------------------------------------
  if (response.clientDataJSON.length > MAX_CLIENT_DATA_JSON_BYTES) {
    throw new Error(
      `clientDataJSON is too large: ${response.clientDataJSON.length} bytes (max ${MAX_CLIENT_DATA_JSON_BYTES})`
    );
  }
  if (response.attestationObject.length > MAX_ATTESTATION_OBJECT_BYTES) {
    throw new Error(
      `attestationObject is too large: ${response.attestationObject.length} bytes (max ${MAX_ATTESTATION_OBJECT_BYTES})`
    );
  }

  // ------------------------------------------------------------------
  // 1. Verify clientDataJSON
  // ------------------------------------------------------------------
  let clientData: Record<string, unknown>;
  try {
    clientData = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response.clientDataJSON)) as Record<string, unknown>;
  } catch {
    throw new Error("clientDataJSON is not valid UTF-8 JSON");
  }

  // Type-guard all fields before use.
  const cdType     = requireString(clientData, "type");
  const cdChallenge = requireString(clientData, "challenge");
  const cdOrigin   = requireString(clientData, "origin");

  if (cdType !== "webauthn.create") {
    throw new Error(
      `clientData.type must be "webauthn.create", got "${cdType}"`
    );
  }

  // Verify the challenge matches what the server sent.
  const receivedChallenge = base64urlToBytes(cdChallenge);
  if (!timingSafeEqual(receivedChallenge, opts.expectedChallenge)) {
    throw new Error("Registration challenge mismatch");
  }

  // Exact origin check prevents cross-origin credential abuse.
  if (cdOrigin !== opts.expectedOrigin) {
    throw new Error(
      `Origin mismatch: expected "${opts.expectedOrigin}", got "${cdOrigin}"`
    );
  }

  // Reject cross-origin iframes.  Any truthy value (true, "true", 1 …) is
  // rejected — only absent or false is permitted.
  if (clientData["crossOrigin"] !== undefined && clientData["crossOrigin"] !== false) {
    throw new Error("Cross-origin registration is not allowed");
  }

  // ------------------------------------------------------------------
  // 2. Decode attestation object (CBOR)
  // ------------------------------------------------------------------
  const attestationObj = decodeCbor(response.attestationObject);
  if (!(attestationObj instanceof Map)) {
    throw new TypeError("Attestation object is not a CBOR map");
  }
  const attMap = attestationObj as Map<string, CborValue>;

  // Warn loudly if a non-"none" attestation format is present.
  // This library does not verify attestation statements; callers relying on
  // device-level attestation must use a library that does (e.g.
  // @simplewebauthn/server with full attestation verification).
  const fmt = attMap.get("fmt");
  if (typeof fmt === "string" && fmt !== "none") {
    throw new Error(
      `Attestation format "${fmt}" is not supported — this library only accepts attestation: "none". ` +
      "For device-level attestation verification, use @simplewebauthn/server."
    );
  }

  const authDataValue = attMap.get("authData");
  if (!(authDataValue instanceof Uint8Array)) {
    throw new TypeError("attestationObject.authData must be bytes");
  }
  const authData = authDataValue;

  // ------------------------------------------------------------------
  // 3. Parse authenticator data header
  // ------------------------------------------------------------------
  const parsed = parseAuthData(authData);

  // ------------------------------------------------------------------
  // 4. Verify rpIdHash
  // ------------------------------------------------------------------
  const expectedRpIdHash = sha256(opts.expectedRpId);
  if (!timingSafeEqual(parsed.rpIdHash, expectedRpIdHash)) {
    throw new Error("rpIdHash mismatch — RP ID does not match authenticator data");
  }

  // ------------------------------------------------------------------
  // 5. Verify flags
  // ------------------------------------------------------------------
  if (!parsed.flags.up) {
    throw new Error("User Presence (UP) flag is not set in authenticator data");
  }
  if ((opts.requireUserVerification ?? true) && !parsed.flags.uv) {
    throw new Error(
      "User Verification (UV) flag is not set — PIN or biometric check may not have occurred"
    );
  }
  if (!parsed.flags.at) {
    throw new Error(
      "Attested Credential Data (AT) flag is not set — missing public key"
    );
  }
  // §6.1.3: BS MUST NOT be set when BE is not set.
  assertFlagConsistency(parsed.flags);

  // ------------------------------------------------------------------
  // 6. Extract attested credential data
  // ------------------------------------------------------------------
  const { aaguid, credentialId, credentialPublicKeyBytes } =
    parseAttestedCredentialData(authData);

  // Verify the COSE key can be decoded and extract the algorithm.
  const { algorithm } = coseKeyToNodeKey(credentialPublicKeyBytes);

  return {
    id: bytesToBase64url(credentialId),
    rawId: credentialId,
    publicKey: credentialPublicKeyBytes,
    algorithm,
    signCount: parsed.signCount,
    aaguid: formatAaguid(aaguid),
    // exactOptionalPropertyTypes: only include the key when it has a value.
    ...(response.transports ? { transports: response.transports } : {}),
  };
}

// ---------------------------------------------------------------------------
// Assertion / hash-signature verification
// ---------------------------------------------------------------------------

/**
 * Verify a passkey signature over an arbitrary hash.
 *
 * ### What this verifies
 *
 * The WebAuthn authenticator signed:
 * ```
 *   authenticatorData  ||  SHA-256(clientDataJSON)
 * ```
 * using its private key.  This function checks that:
 *
 * 1. `clientDataJSON.challenge === base64url(hash)` — the signature commits
 *    to your exact hash value.
 * 2. `clientDataJSON.type === "webauthn.get"` — this is an assertion, not a
 *    registration ceremony.
 * 3. `clientDataJSON.origin === expectedOrigin` — prevents cross-site use.
 * 4. `rpIdHash === SHA-256(expectedRpId)` — correct relying party.
 * 5. User Presence flag is set.
 * 6. User Verification flag is set (if `requireUserVerification = true`).
 * 7. Sign count is strictly greater than stored count (cloned authenticator
 *    detection — skipped when either count is 0).
 * 8. Cryptographic signature is valid using the stored public key.
 *
 * @throws if any check fails.  On success, returns `{ verified: true, newSignCount }`.
 *         You **must** update your stored `signCount` to `newSignCount`.
 *
 * @example
 * ```ts
 * import { verifyHashSignature, sha256 } from "webauthnsign/server";
 *
 * const hash = sha256(documentBytes);
 * const result = await verifyHashSignature({
 *   hash,
 *   passkeySig: sigFromClient,
 *   credential: storedCredential,
 *   expectedOrigin: "https://example.com",
 *   expectedRpId: "example.com",
 * });
 *
 * if (!result.verified) throw new Error("Invalid signature");
 * // Update the stored sign count to detect cloned authenticators later:
 * await db.updateSignCount(storedCredential.id, result.newSignCount);
 * ```
 */
export async function verifyHashSignature(
  opts: VerifyHashOptions
): Promise<VerifyHashResult> {
  const {
    hash,
    passkeySig,
    credential,
    expectedOrigin,
    expectedRpId,
    requireUserVerification = true,
  } = opts;

  // ------------------------------------------------------------------
  // 0. Input size limits — reject oversized blobs before any parsing.
  // ------------------------------------------------------------------
  if (hash.length < 16) {
    throw new TypeError(
      `hash is too short: got ${hash.length} bytes, need ≥ 16`
    );
  }
  if (hash.length > 128) {
    throw new TypeError(
      `hash is too long: got ${hash.length} bytes, maximum is 128`
    );
  }
  if (passkeySig.clientDataJSON.length > MAX_CLIENT_DATA_JSON_BYTES) {
    throw new Error(
      `clientDataJSON is too large: ${passkeySig.clientDataJSON.length} bytes (max ${MAX_CLIENT_DATA_JSON_BYTES})`
    );
  }
  if (passkeySig.authenticatorData.length > MAX_AUTH_DATA_BYTES) {
    throw new Error(
      `authenticatorData is too large: ${passkeySig.authenticatorData.length} bytes (max ${MAX_AUTH_DATA_BYTES})`
    );
  }
  if (passkeySig.signature.length > MAX_SIGNATURE_BYTES) {
    throw new Error(
      `signature is too large: ${passkeySig.signature.length} bytes (max ${MAX_SIGNATURE_BYTES})`
    );
  }

  // ------------------------------------------------------------------
  // 1. Parse and verify clientDataJSON
  // ------------------------------------------------------------------
  let clientData: Record<string, unknown>;
  try {
    clientData = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(passkeySig.clientDataJSON)
    ) as Record<string, unknown>;
  } catch {
    throw new Error("clientDataJSON is not valid UTF-8 JSON");
  }

  // Type-guard all fields before use.
  const cdType      = requireString(clientData, "type");
  const cdChallenge = requireString(clientData, "challenge");
  const cdOrigin    = requireString(clientData, "origin");

  if (cdType !== "webauthn.get") {
    throw new Error(
      `clientData.type must be "webauthn.get", got "${cdType}"`
    );
  }

  // ------------------------------------------------------------------
  // 2. Verify the challenge equals the hash
  //    This is the core binding: signature ↔ hash
  // ------------------------------------------------------------------
  const receivedChallenge = base64urlToBytes(cdChallenge);
  if (!timingSafeEqual(receivedChallenge, hash)) {
    throw new Error(
      "Challenge in clientDataJSON does not match the provided hash — signature is not for this hash"
    );
  }

  // ------------------------------------------------------------------
  // 3. Verify origin (exact, case-sensitive)
  // ------------------------------------------------------------------
  if (cdOrigin !== expectedOrigin) {
    throw new Error(
      `Origin mismatch: expected "${expectedOrigin}", got "${cdOrigin}"`
    );
  }

  // Reject cross-origin assertions — they could be forwarded from another site.
  // Any truthy value (true, "true", 1 …) is rejected — only absent or false is permitted.
  if (clientData["crossOrigin"] !== undefined && clientData["crossOrigin"] !== false) {
    throw new Error("Cross-origin assertion rejected");
  }

  // ------------------------------------------------------------------
  // 4. Parse authenticator data
  // ------------------------------------------------------------------
  const parsed = parseAuthData(passkeySig.authenticatorData);

  // ------------------------------------------------------------------
  // 5. Verify rpIdHash
  // ------------------------------------------------------------------
  const expectedRpIdHash = sha256(expectedRpId);
  if (!timingSafeEqual(parsed.rpIdHash, expectedRpIdHash)) {
    throw new Error(
      "rpIdHash mismatch — assertion RP ID does not match expected"
    );
  }

  // ------------------------------------------------------------------
  // 6. Verify flags
  // ------------------------------------------------------------------
  if (!parsed.flags.up) {
    throw new Error("User Presence (UP) flag is not set");
  }
  if (requireUserVerification && !parsed.flags.uv) {
    throw new Error(
      "User Verification (UV) flag is not set — passkey signature does not prove PIN / biometric"
    );
  }
  // §6.1.3: BS MUST NOT be set when BE is not set.
  assertFlagConsistency(parsed.flags);

  // ------------------------------------------------------------------
  // 7. Sign-count check (cloned authenticator detection)
  // ------------------------------------------------------------------
  const storedSignCount = credential.signCount;
  const newSignCount = parsed.signCount;

  if (newSignCount !== 0 || storedSignCount !== 0) {
    if (newSignCount <= storedSignCount) {
      throw new Error(
        `Sign count regression detected: received ${newSignCount}, stored ${storedSignCount}. ` +
          "This may indicate a cloned authenticator.  Reject the assertion and " +
          "investigate before re-enabling this credential."
      );
    }
  }

  // ------------------------------------------------------------------
  // 8. Verify cryptographic signature
  //
  //    The authenticator signed:
  //      message = authenticatorData || SHA-256(clientDataJSON)
  //    using ECDSA/ES256 (or RS256 / EdDSA).
  //
  //    Node.js createVerify('SHA256') accepts `message` and internally
  //    hashes it once more with SHA-256 before verifying — this matches
  //    how ES256 (ECDSA with SHA-256) and RS256 (RSASSA-PKCS1-v1_5 with
  //    SHA-256) both work.  For EdDSA the algorithm handles its own
  //    digest internally.
  // ------------------------------------------------------------------
  const clientDataHash = sha256(passkeySig.clientDataJSON);
  const message = concat(passkeySig.authenticatorData, clientDataHash);

  const { key, algorithm: coseAlgorithm } = coseKeyToNodeKey(credential.publicKey);

  // Cross-check: the algorithm stored at registration must match the
  // algorithm extracted live from the COSE key bytes.  A drift here would
  // let an attacker substitute a key of a different type in the database.
  if (coseAlgorithm !== credential.algorithm) {
    throw new Error(
      `Algorithm mismatch: stored credential.algorithm (${credential.algorithm}) does not match ` +
      `the algorithm in the COSE public key (${coseAlgorithm}). The stored credential may be corrupt.`
    );
  }

  let verified = false;

  if (coseAlgorithm === -7) {
    // ES256 — ECDSA with P-256 / SHA-256
    verified = nodeCrypto
      .createVerify("SHA256")
      .update(message)
      .verify(key, Buffer.from(passkeySig.signature));
  } else if (coseAlgorithm === -257) {
    // RS256 — RSASSA-PKCS1-v1_5 with SHA-256
    verified = nodeCrypto
      .createVerify("SHA256")
      .update(message)
      .verify(key, Buffer.from(passkeySig.signature));
  } else if (coseAlgorithm === -8) {
    // EdDSA — Ed25519 uses its own internal hash; must use one-shot API.
    // createVerify("ed25519") double-hashes, producing incorrect results.
    verified = nodeCrypto.verify(
      null,
      message,
      key,
      Buffer.from(passkeySig.signature)
    );
  } else {
    throw new Error(`Unsupported algorithm: ${coseAlgorithm as number}`);
  }

  if (!verified) {
    throw new Error(
      "Cryptographic signature verification failed — the signature is not valid for this hash and credential"
    );
  }

  return { verified: true, newSignCount };
}

// Re-export types and utilities useful on the server side.
export { parseAuthData as parseAuthenticatorData };
export {
  bytesToBase64url,
  base64urlToBytes,
  bytesToHex,
  hexToBytes,
  formatAaguid,
} from "./utils.js";
export type {
  PasskeyCredential,
  PasskeySignature,
  VerifyHashOptions,
  VerifyHashResult,
  ParsedAuthData,
  AuthenticatorFlags,
  CoseAlgorithm,
} from "./types.js";
