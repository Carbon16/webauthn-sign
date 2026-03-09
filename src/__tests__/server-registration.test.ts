/**
 * Server-side registration parsing tests.
 *
 * These tests exercise parseRegistrationResponse by constructing mock
 * attestation objects with valid CBOR-encoded authenticator data.
 */

import * as nodeCrypto from "node:crypto";
import {
  sha256,
  parseRegistrationResponse,
  bytesToBase64url,
} from "../server.js";

// ---------------------------------------------------------------------------
// Helpers: build mock attestation objects
// ---------------------------------------------------------------------------

/** Manually CBOR-encode a minimal "none" attestation object. */
function buildAttestationObject(authData: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [];

  // Map header: 3 pairs {fmt, attStmt, authData}
  parts.push(new Uint8Array([0xa3]));

  // "fmt": "none"
  parts.push(cborText("fmt"));
  parts.push(cborText("none"));

  // "attStmt": {} (empty map)
  parts.push(cborText("attStmt"));
  parts.push(new Uint8Array([0xa0])); // empty map

  // "authData": bytes
  parts.push(cborText("authData"));
  parts.push(cborBstr(authData));

  return cat(...parts);
}

/** Build authenticator data with attested credential data. */
function buildRegistrationAuthData(opts: {
  rpId: string;
  flags?: number;
  signCount?: number;
  credentialId: Uint8Array;
  cosePublicKey: Uint8Array;
}): Uint8Array {
  const rpIdHash = sha256(opts.rpId);
  const flags = opts.flags ?? 0x45; // UP + UV + AT
  const signCount = opts.signCount ?? 0;

  // 37 bytes header + 16 bytes AAGUID + 2 bytes credIdLen + credentialId + COSE key
  const aaguid = new Uint8Array(16); // zeros
  const credIdLen = opts.credentialId.length;
  const total = 37 + 16 + 2 + credIdLen + opts.cosePublicKey.length;
  const buf = new Uint8Array(total);

  buf.set(rpIdHash, 0);
  buf[32] = flags;
  const view = new DataView(buf.buffer, 33, 4);
  view.setUint32(0, signCount, false);

  buf.set(aaguid, 37);
  buf[53] = (credIdLen >> 8) & 0xff;
  buf[54] = credIdLen & 0xff;
  buf.set(opts.credentialId, 55);
  buf.set(opts.cosePublicKey, 55 + credIdLen);

  return buf;
}

/** Build a COSE EC2 P-256 key from a Node.js KeyObject. */
function buildCoseEC2Key(pubKey: nodeCrypto.KeyObject): Uint8Array {
  const jwk = pubKey.export({ format: "jwk" });
  const x = Buffer.from(jwk.x!, "base64url");
  const y = Buffer.from(jwk.y!, "base64url");

  return cat(
    new Uint8Array([0xa5]),                    // map(5)
    new Uint8Array([0x01, 0x02]),              // 1: 2 (kty: EC2)
    new Uint8Array([0x03, 0x26]),              // 3: -7 (alg: ES256)
    new Uint8Array([0x20, 0x01]),              // -1: 1 (crv: P-256)
    new Uint8Array([0x21, 0x58, 0x20]),        // -2: bstr(32)
    new Uint8Array(x),
    new Uint8Array([0x22, 0x58, 0x20]),        // -3: bstr(32)
    new Uint8Array(y),
  );
}

/** Build clientDataJSON for registration. */
function buildClientDataJSON(opts: {
  type?: string;
  challenge: Uint8Array;
  origin: string;
  crossOrigin?: boolean;
}): Uint8Array {
  const clientData = {
    type: opts.type ?? "webauthn.create",
    challenge: bytesToBase64url(opts.challenge),
    origin: opts.origin,
    crossOrigin: opts.crossOrigin ?? false,
  };
  return new TextEncoder().encode(JSON.stringify(clientData));
}

// CBOR encoding helpers (minimal)
function cborText(str: string): Uint8Array {
  const bytes = new TextEncoder().encode(str);
  if (bytes.length < 24) {
    return cat(new Uint8Array([0x60 | bytes.length]), bytes);
  }
  if (bytes.length < 256) {
    return cat(new Uint8Array([0x78, bytes.length]), bytes);
  }
  return cat(
    new Uint8Array([0x79, (bytes.length >> 8) & 0xff, bytes.length & 0xff]),
    bytes,
  );
}

function cborBstr(data: Uint8Array): Uint8Array {
  if (data.length < 24) {
    return cat(new Uint8Array([0x40 | data.length]), data);
  }
  if (data.length < 256) {
    return cat(new Uint8Array([0x58, data.length]), data);
  }
  return cat(
    new Uint8Array([0x59, (data.length >> 8) & 0xff, data.length & 0xff]),
    data,
  );
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("parseRegistrationResponse", () => {
  const rpId = "example.com";
  const origin = "https://example.com";

  let keyPair: nodeCrypto.KeyPairKeyObjectResult;
  let cosePublicKey: Uint8Array;
  let challenge: Uint8Array;

  beforeAll(() => {
    keyPair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    cosePublicKey = buildCoseEC2Key(keyPair.publicKey);
    challenge = nodeCrypto.randomBytes(32);
  });

  function makeValidResponse() {
    const credentialId = nodeCrypto.randomBytes(32);
    const authData = buildRegistrationAuthData({
      rpId,
      credentialId,
      cosePublicKey,
    });
    const attestationObject = buildAttestationObject(authData);
    const clientDataJSON = buildClientDataJSON({ challenge, origin });

    return { attestationObject, clientDataJSON, credentialId };
  }

  test("parses a valid registration response", async () => {
    const { attestationObject, clientDataJSON, credentialId } = makeValidResponse();

    const credential = await parseRegistrationResponse(
      { attestationObject, clientDataJSON },
      {
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
      },
    );

    expect(credential.id).toBe(bytesToBase64url(credentialId));
    expect(credential.algorithm).toBe(-7);
    expect(credential.signCount).toBe(0);
    expect(credential.publicKey.length).toBeGreaterThan(0);
  });

  test("rejects wrong challenge", async () => {
    const { attestationObject, clientDataJSON } = makeValidResponse();

    await expect(
      parseRegistrationResponse(
        { attestationObject, clientDataJSON },
        {
          expectedChallenge: nodeCrypto.randomBytes(32),
          expectedOrigin: origin,
          expectedRpId: rpId,
        },
      )
    ).rejects.toThrow("challenge mismatch");
  });

  test("rejects wrong origin", async () => {
    const { attestationObject, clientDataJSON } = makeValidResponse();

    await expect(
      parseRegistrationResponse(
        { attestationObject, clientDataJSON },
        {
          expectedChallenge: challenge,
          expectedOrigin: "https://evil.com",
          expectedRpId: rpId,
        },
      )
    ).rejects.toThrow("Origin mismatch");
  });

  test("rejects wrong rpId", async () => {
    const { attestationObject, clientDataJSON } = makeValidResponse();

    await expect(
      parseRegistrationResponse(
        { attestationObject, clientDataJSON },
        {
          expectedChallenge: challenge,
          expectedOrigin: origin,
          expectedRpId: "evil.com",
        },
      )
    ).rejects.toThrow("rpIdHash mismatch");
  });

  test("rejects wrong ceremony type", async () => {
    const credentialId = nodeCrypto.randomBytes(32);
    const authData = buildRegistrationAuthData({
      rpId,
      credentialId,
      cosePublicKey,
    });
    const attestationObject = buildAttestationObject(authData);

    // Use wrong type
    const clientDataJSON = buildClientDataJSON({
      type: "webauthn.get",
      challenge,
      origin,
    });

    await expect(
      parseRegistrationResponse(
        { attestationObject, clientDataJSON },
        {
          expectedChallenge: challenge,
          expectedOrigin: origin,
          expectedRpId: rpId,
        },
      )
    ).rejects.toThrow("webauthn.create");
  });

  test("rejects cross-origin registration", async () => {
    const credentialId = nodeCrypto.randomBytes(32);
    const authData = buildRegistrationAuthData({
      rpId,
      credentialId,
      cosePublicKey,
    });
    const attestationObject = buildAttestationObject(authData);
    const clientDataJSON = buildClientDataJSON({
      challenge,
      origin,
      crossOrigin: true,
    });

    await expect(
      parseRegistrationResponse(
        { attestationObject, clientDataJSON },
        {
          expectedChallenge: challenge,
          expectedOrigin: origin,
          expectedRpId: rpId,
        },
      )
    ).rejects.toThrow("Cross-origin");
  });

  test("rejects when UP flag is missing", async () => {
    const credentialId = nodeCrypto.randomBytes(32);
    const authData = buildRegistrationAuthData({
      rpId,
      credentialId,
      cosePublicKey,
      flags: 0x44, // UV + AT but no UP
    });
    const attestationObject = buildAttestationObject(authData);
    const clientDataJSON = buildClientDataJSON({ challenge, origin });

    await expect(
      parseRegistrationResponse(
        { attestationObject, clientDataJSON },
        {
          expectedChallenge: challenge,
          expectedOrigin: origin,
          expectedRpId: rpId,
        },
      )
    ).rejects.toThrow("User Presence");
  });

  test("rejects when UV flag is missing and requireUserVerification is true", async () => {
    const credentialId = nodeCrypto.randomBytes(32);
    const authData = buildRegistrationAuthData({
      rpId,
      credentialId,
      cosePublicKey,
      flags: 0x41, // UP + AT but no UV
    });
    const attestationObject = buildAttestationObject(authData);
    const clientDataJSON = buildClientDataJSON({ challenge, origin });

    await expect(
      parseRegistrationResponse(
        { attestationObject, clientDataJSON },
        {
          expectedChallenge: challenge,
          expectedOrigin: origin,
          expectedRpId: rpId,
          requireUserVerification: true,
        },
      )
    ).rejects.toThrow("User Verification");
  });

  test("accepts when UV flag is missing and requireUserVerification is false", async () => {
    const credentialId = nodeCrypto.randomBytes(32);
    const authData = buildRegistrationAuthData({
      rpId,
      credentialId,
      cosePublicKey,
      flags: 0x41, // UP + AT, no UV
    });
    const attestationObject = buildAttestationObject(authData);
    const clientDataJSON = buildClientDataJSON({ challenge, origin });

    const credential = await parseRegistrationResponse(
      { attestationObject, clientDataJSON },
      {
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
        requireUserVerification: false,
      },
    );

    expect(credential.algorithm).toBe(-7);
  });

  test("includes transports when provided", async () => {
    const { attestationObject, clientDataJSON } = makeValidResponse();

    const credential = await parseRegistrationResponse(
      {
        attestationObject,
        clientDataJSON,
        transports: ["internal", "hybrid"],
      },
      {
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
      },
    );

    expect(credential.transports).toEqual(["internal", "hybrid"]);
  });

  test("omits transports when not provided", async () => {
    const { attestationObject, clientDataJSON } = makeValidResponse();

    const credential = await parseRegistrationResponse(
      { attestationObject, clientDataJSON },
      {
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
      },
    );

    expect(credential).not.toHaveProperty("transports");
  });
});
