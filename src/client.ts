/**
 * webauthnsign — browser / client side
 *
 * Import path: "webauthnsign/client"
 *
 * This module only uses Web Platform APIs (navigator.credentials, SubtleCrypto)
 * and has no Node.js dependencies.  Bundle it as part of your front-end code.
 */

import { base64urlToBytes, bytesToBase64url } from "./utils.js";
import type {
  PasskeyRegistrationOptions,
  RawRegistrationResponse,
  SignHashOptions,
  PasskeySignature,
} from "./types.js";

// ---------------------------------------------------------------------------
// Capability check
// ---------------------------------------------------------------------------

/**
 * Returns `true` if the current browser supports WebAuthn platform
 * authenticators (passkeys).
 */
export async function isPasskeySupported(): Promise<boolean> {
  if (
    typeof window === "undefined" ||
    !window.PublicKeyCredential ||
    typeof window.PublicKeyCredential
      .isUserVerifyingPlatformAuthenticatorAvailable !== "function"
  ) {
    return false;
  }
  return window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}

// ---------------------------------------------------------------------------
// SHA-256 helper (browser, uses SubtleCrypto)
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 digest in the browser.
 *
 * Use this to hash your document / data before passing it to {@link signHash}.
 */
export async function sha256Browser(data: Uint8Array): Promise<Uint8Array> {
  // .slice() creates a fresh Uint8Array<ArrayBuffer> (no SharedArrayBuffer).
  const digest = await crypto.subtle.digest("SHA-256", data.slice());
  return new Uint8Array(digest);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * Ask the browser to create a new passkey for the current user.
 *
 * The returned {@link RawRegistrationResponse} must be sent to the server and
 * verified with `parseRegistrationResponse()` from `"webauthnsign/server"`.
 *
 * @example
 * ```ts
 * import { registerPasskey } from "webauthnsign/client";
 *
 * const challenge = crypto.getRandomValues(new Uint8Array(32));
 * const raw = await registerPasskey({
 *   rpId: "example.com",
 *   rpName: "My App",
 *   userId: crypto.getRandomValues(new Uint8Array(16)),
 *   userName: "alice",
 *   challenge,
 * });
 * // POST raw + base64url(challenge) to your server for verification.
 * ```
 */
export async function registerPasskey(
  options: PasskeyRegistrationOptions
): Promise<RawRegistrationResponse> {
  if (!window.PublicKeyCredential) {
    throw new Error("WebAuthn is not supported in this browser.");
  }

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: options.challenge.slice(),
      rp: {
        id: options.rpId,
        name: options.rpName,
      },
      user: {
        id: options.userId.slice(),
        name: options.userName,
        displayName: options.userDisplayName ?? options.userName,
      },
      // Prefer ES256 (P-256) > EdDSA > RS256.
      // Listing multiple lets the authenticator choose the best it supports.
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256  — ECDSA / P-256
        { type: "public-key", alg: -8 },   // EdDSA  — Ed25519
        { type: "public-key", alg: -257 }, // RS256  — RSA-PKCS1v15
      ],
      authenticatorSelection: options.authenticatorSelection ?? {
        // Platform authenticator = built-in sensor (Touch ID, Windows Hello…).
        authenticatorAttachment: "platform",
        // Require a resident (discoverable) key so the user can sign later
        // without remembering a username.
        requireResidentKey: true,
        residentKey: "required",
        // Require biometric / PIN — the UV flag in every signature proves
        // the user explicitly consented.
        userVerification: "required",
      },
      attestation: options.attestation ?? "none",
      timeout: options.timeout ?? 60_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("Passkey creation was cancelled or failed.");
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    credentialId: bytesToBase64url(new Uint8Array(credential.rawId)),
    rawId: new Uint8Array(credential.rawId),
    attestationObject: new Uint8Array(response.attestationObject),
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    transports: response.getTransports?.(),
  };
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Sign an arbitrary hash with a passkey.
 *
 * ### Security model
 *
 * WebAuthn assertions sign:
 * ```
 *   authenticatorData  ||  SHA-256(clientDataJSON)
 * ```
 * where `clientDataJSON.challenge = base64url(hash)`.
 *
 * This cryptographically ties the authenticator's private-key signature to
 * the exact bytes of your `hash`.  A verifier that:
 *   1. checks `clientDataJSON.challenge === base64url(hash)`, and
 *   2. checks `clientDataJSON.origin === expectedOrigin`, and
 *   3. verifies the signature,
 *
 * has proof that the passkey holder deliberately signed that specific hash on
 * that specific origin.
 *
 * ### Replay-attack prevention
 *
 * Include a nonce, timestamp, or session token inside the data you hash.  Do
 * **not** re-use the same hash in multiple independent signing ceremonies.
 *
 * @param hash   The hash to commit the signature to (e.g. SHA-256 of your document).
 *               Recommended size: 32 bytes (SHA-256) or 64 bytes (SHA-512).
 * @param options Signing options.
 *
 * @example
 * ```ts
 * import { signHash, sha256Browser } from "webauthnsign/client";
 *
 * const docBytes = new TextEncoder().encode("important document");
 * const hash = await sha256Browser(docBytes);
 *
 * const sig = await signHash(hash, {
 *   rpId: "example.com",
 *   credentialIds: [storedCredentialId],
 * });
 * // POST { hash: bytesToBase64url(hash), sig } to the server.
 * ```
 */
export async function signHash(
  hash: Uint8Array,
  options: SignHashOptions
): Promise<PasskeySignature> {
  if (!window.PublicKeyCredential) {
    throw new Error("WebAuthn is not supported in this browser.");
  }
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

  const allowCredentials: PublicKeyCredentialDescriptor[] =
    options.credentialIds && options.credentialIds.length > 0
      ? options.credentialIds.map((id) => ({
          type: "public-key" as const,
          // .slice() produces Uint8Array<ArrayBuffer> required by BufferSource.
          id: base64urlToBytes(id).slice(),
        }))
      : [];

  const assertion = (await navigator.credentials.get({
    publicKey: {
      // *** The hash is used directly as the WebAuthn challenge ***
      // The authenticator will sign a payload that contains
      // base64url(hash) in clientDataJSON, which we verify server-side.
      challenge: hash.slice(),
      rpId: options.rpId,
      allowCredentials,
      userVerification: options.userVerification ?? "required",
      timeout: options.timeout ?? 60_000,
    },
  })) as PublicKeyCredential | null;

  if (!assertion) {
    throw new Error("Signing was cancelled or failed.");
  }

  const response = assertion.response as AuthenticatorAssertionResponse;

  const sig: PasskeySignature = {
    credentialId: bytesToBase64url(new Uint8Array(assertion.rawId)),
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    signature: new Uint8Array(response.signature),
    // exactOptionalPropertyTypes: only set the key when the value exists.
    ...(response.userHandle
      ? { userHandle: new Uint8Array(response.userHandle) }
      : {}),
  };
  return sig;
}

// Re-export utilities useful on the client side.
export { bytesToBase64url, base64urlToBytes, bytesToHex } from "./utils.js";
export type {
  PasskeyRegistrationOptions,
  RawRegistrationResponse,
  SignHashOptions,
  PasskeySignature,
  CoseAlgorithm,
} from "./types.js";
