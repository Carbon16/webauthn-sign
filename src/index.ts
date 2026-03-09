/**
 * webauthnsign — top-level re-exports
 *
 * For tree-shaking, prefer the subpath imports:
 *   import { signHash }          from "webauthnsign/client"
 *   import { verifyHashSignature } from "webauthnsign/server"
 *
 * This barrel exports shared types only.  The platform-specific
 * implementations live in their own entry points.
 */

export type {
  CoseAlgorithm,
  PasskeyRegistrationOptions,
  RawRegistrationResponse,
  PasskeyCredential,
  SignHashOptions,
  PasskeySignature,
  VerifyHashOptions,
  VerifyHashResult,
  ParsedAuthData,
  AuthenticatorFlags,
} from "./types.js";

export { COSE_ALGORITHMS } from "./types.js";
export { bytesToBase64url, base64urlToBytes, bytesToHex, hexToBytes } from "./utils.js";
