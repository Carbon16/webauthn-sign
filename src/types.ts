// ---------------------------------------------------------------------------
// COSE algorithm identifiers (subset used by WebAuthn passkeys)
// ---------------------------------------------------------------------------

/** COSE algorithm numbers used in WebAuthn authenticators. */
export type CoseAlgorithm = -7 | -8 | -257;

/** Human-readable names for the supported algorithms. */
export const COSE_ALGORITHMS = {
  /** ECDSA using P-256 and SHA-256 */
  ES256: -7 as CoseAlgorithm,
  /** EdDSA using Curve25519 (Ed25519) */
  EdDSA: -8 as CoseAlgorithm,
  /** RSASSA-PKCS1-v1_5 using SHA-256 */
  RS256: -257 as CoseAlgorithm,
} as const;

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/** Options passed to {@link registerPasskey}. */
export interface PasskeyRegistrationOptions {
  /** Relying party ID (e.g. "example.com"). Must match the page origin. */
  rpId: string;
  /** Human-readable name shown in the authenticator UI. */
  rpName: string;
  /**
   * A stable, opaque byte identifier for this user account.
   * Do **not** use PII (no email, no username).
   */
  userId: Uint8Array;
  /** Username shown in the passkey chooser. */
  userName: string;
  /** Display name shown in the passkey chooser (falls back to userName). */
  userDisplayName?: string;
  /**
   * A random challenge to prevent replay of the registration response.
   * Generate server-side with `crypto.getRandomValues(new Uint8Array(32))`.
   */
  challenge: Uint8Array;
  /** Authenticator selection criteria (defaults to platform / resident key / UV required). */
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  /** Attestation format (defaults to "none" — passkeys don't need attestation). */
  attestation?: AttestationConveyancePreference;
  /** Timeout in ms (default 60 000). */
  timeout?: number;
}

/** Raw browser-side registration response, ready to be sent to the server. */
export interface RawRegistrationResponse {
  /** base64url-encoded credential ID. */
  credentialId: string;
  rawId: Uint8Array;
  attestationObject: Uint8Array;
  clientDataJSON: Uint8Array;
  /** Reported transport methods (e.g. "internal", "hybrid"). */
  transports?: string[];
}

/**
 * Verified credential record returned by {@link parseRegistrationResponse}.
 * Persist this in your database — you will need it for every verification.
 */
export interface PasskeyCredential {
  /** base64url-encoded credential ID (primary key for lookups). */
  id: string;
  rawId: Uint8Array;
  /**
   * Raw COSE-encoded public key bytes extracted from authenticator data.
   * Store as-is; passed back into {@link verifyHashSignature}.
   */
  publicKey: Uint8Array;
  /** COSE algorithm identifier. */
  algorithm: CoseAlgorithm;
  /**
   * Authenticator sign count.
   * Update this field in your DB every time {@link verifyHashSignature} succeeds.
   */
  signCount: number;
  /** AAGUID formatted as a UUID string (identifies the authenticator model). */
  aaguid: string;
  transports?: string[];
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/** Options passed to {@link signHash}. */
export interface SignHashOptions {
  /**
   * Relying party ID — must exactly match what was used at registration
   * and must be a registrable domain suffix of the page origin.
   */
  rpId: string;
  /**
   * base64url credential IDs to restrict which passkeys are offered.
   * Omit (or pass empty array) to allow any discoverable credential.
   */
  credentialIds?: string[];
  /**
   * User verification requirement.
   * Defaults to "required" — always require PIN / biometric so signatures
   * carry proof of user intent.
   */
  userVerification?: UserVerificationRequirement;
  /** Timeout in ms (default 60 000). */
  timeout?: number;
}

/**
 * Raw signature bundle returned by {@link signHash}.
 * Send the entire object plus the original `hash` to your server for verification.
 */
export interface PasskeySignature {
  /** base64url-encoded credential ID — use this to look up the stored credential. */
  credentialId: string;
  /** Authenticator data bytes (contains rpIdHash, flags, signCount). */
  authenticatorData: Uint8Array;
  /** Raw clientDataJSON bytes as returned by the authenticator. */
  clientDataJSON: Uint8Array;
  /** DER-encoded ECDSA signature (or raw bytes for RS256 / EdDSA). */
  signature: Uint8Array;
  /** Resident-key user handle, if returned by the authenticator. */
  userHandle?: Uint8Array;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/** Options passed to {@link verifyHashSignature}. */
export interface VerifyHashOptions {
  /**
   * The exact hash that was passed to {@link signHash} as the challenge.
   * This is the value your application committed to — it must equal
   * base64url-decode(clientDataJSON.challenge).
   */
  hash: Uint8Array;
  /** The signature bundle returned by {@link signHash}. */
  passkeySig: PasskeySignature;
  /**
   * The stored credential returned by {@link parseRegistrationResponse}.
   * Only `publicKey`, `algorithm`, and `signCount` are required.
   */
  credential: Pick<PasskeyCredential, "publicKey" | "algorithm" | "signCount">;
  /**
   * Expected origin of the signing page, e.g. "https://example.com".
   * Must be an exact, case-sensitive match.
   */
  expectedOrigin: string;
  /**
   * Expected relying party ID, e.g. "example.com".
   */
  expectedRpId: string;
  /**
   * Whether user verification (PIN / biometric) must be confirmed.
   * Defaults to `true` — leave this as true for any security-sensitive operation.
   */
  requireUserVerification?: boolean;
}

/** Result returned by {@link verifyHashSignature}. */
export interface VerifyHashResult {
  /** `true` if and only if the cryptographic signature is valid and all policy checks passed. */
  verified: boolean;
  /**
   * New sign count reported by the authenticator.
   * **You must update your stored `signCount` to this value** to enable
   * cloned-authenticator detection on future verifications.
   */
  newSignCount: number;
}

// ---------------------------------------------------------------------------
// Parsed authenticator data (internal + exported for advanced use)
// ---------------------------------------------------------------------------

/** Decoded flags field from authenticator data. */
export interface AuthenticatorFlags {
  /** User Presence — user physically interacted with the authenticator. */
  up: boolean;
  /** User Verification — user completed PIN / biometric check. */
  uv: boolean;
  /** Backup Eligibility — credential can be backed up. */
  be: boolean;
  /** Backup State — credential is currently backed up. */
  bs: boolean;
  /** Attested Credential Data present (registration only). */
  at: boolean;
  /** Extension data present. */
  ed: boolean;
}

/** Parsed authenticator data header (first 37 bytes). */
export interface ParsedAuthData {
  rpIdHash: Uint8Array;
  flags: AuthenticatorFlags;
  signCount: number;
}
