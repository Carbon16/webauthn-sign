/**
 * Server-side verification tests.
 *
 * These tests exercise parseAuthData, sha256, hash length validation,
 * and — most importantly — an end-to-end sign + verify round-trip that
 * simulates a WebAuthn assertion using real Node.js crypto keys.
 */

import * as nodeCrypto from "node:crypto";
import {
  sha256,
  parseAuthenticatorData,
  verifyHashSignature,
  bytesToBase64url,
  base64urlToBytes,
} from "../server.js";
import type { PasskeyCredential } from "../types.js";
import { decodeCbor } from "../cbor.js";

// ---------------------------------------------------------------------------
// sha256
// ---------------------------------------------------------------------------

describe("sha256", () => {
  test("produces correct digest for empty input", () => {
    const digest = sha256(new Uint8Array(0));
    expect(digest.length).toBe(32);
    // Known SHA-256 of empty input
    const expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(Buffer.from(digest).toString("hex")).toBe(expected);
  });

  test("produces correct digest for known input", () => {
    const data = new TextEncoder().encode("hello");
    const digest = sha256(data);
    const expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    expect(Buffer.from(digest).toString("hex")).toBe(expected);
  });

  test("accepts string input", () => {
    const digest = sha256("hello");
    const expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    expect(Buffer.from(digest).toString("hex")).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// parseAuthenticatorData
// ---------------------------------------------------------------------------

describe("parseAuthenticatorData", () => {
  function makeAuthData(opts: {
    rpIdHash?: Uint8Array;
    flags?: number;
    signCount?: number;
  } = {}): Uint8Array {
    const rpIdHash = opts.rpIdHash ?? sha256("example.com");
    const flags = opts.flags ?? 0x05; // UP + UV
    const signCount = opts.signCount ?? 1;
    const buf = new Uint8Array(37);
    buf.set(rpIdHash, 0);
    buf[32] = flags;
    const view = new DataView(buf.buffer, 33, 4);
    view.setUint32(0, signCount, false);
    return buf;
  }

  test("parses valid 37-byte authenticator data", () => {
    const authData = makeAuthData({ signCount: 42 });
    const parsed = parseAuthenticatorData(authData);
    expect(parsed.rpIdHash).toEqual(sha256("example.com"));
    expect(parsed.flags.up).toBe(true);
    expect(parsed.flags.uv).toBe(true);
    expect(parsed.signCount).toBe(42);
  });

  test("reads flags correctly", () => {
    // UP only (0x01)
    const upOnly = makeAuthData({ flags: 0x01 });
    const parsed1 = parseAuthenticatorData(upOnly);
    expect(parsed1.flags.up).toBe(true);
    expect(parsed1.flags.uv).toBe(false);

    // UV only (0x04)
    const uvOnly = makeAuthData({ flags: 0x04 });
    const parsed2 = parseAuthenticatorData(uvOnly);
    expect(parsed2.flags.up).toBe(false);
    expect(parsed2.flags.uv).toBe(true);

    // All flags (0xFF)
    const all = makeAuthData({ flags: 0xff });
    const parsed3 = parseAuthenticatorData(all);
    expect(parsed3.flags.up).toBe(true);
    expect(parsed3.flags.uv).toBe(true);
    expect(parsed3.flags.be).toBe(true);
    expect(parsed3.flags.bs).toBe(true);
    expect(parsed3.flags.at).toBe(true);
    expect(parsed3.flags.ed).toBe(true);
  });

  test("rejects authenticator data shorter than 37 bytes", () => {
    expect(() => parseAuthenticatorData(new Uint8Array(36))).toThrow("too short");
    expect(() => parseAuthenticatorData(new Uint8Array(0))).toThrow("too short");
  });

  test("accepts authenticator data longer than 37 bytes", () => {
    // Longer data is valid (may contain attested credential data or extensions).
    const long = new Uint8Array(100);
    long.set(makeAuthData());
    expect(() => parseAuthenticatorData(long)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Hash length validation
// ---------------------------------------------------------------------------

describe("verifyHashSignature hash length validation", () => {
  const dummyOpts = {
    passkeySig: {
      credentialId: "test",
      authenticatorData: new Uint8Array(37),
      clientDataJSON: new Uint8Array(0),
      signature: new Uint8Array(0),
    },
    credential: {
      publicKey: new Uint8Array(0),
      algorithm: -7 as const,
      signCount: 0,
    },
    expectedOrigin: "https://example.com",
    expectedRpId: "example.com",
  };

  test("rejects hash shorter than 16 bytes", async () => {
    await expect(
      verifyHashSignature({ ...dummyOpts, hash: new Uint8Array(15) })
    ).rejects.toThrow("too short");

    await expect(
      verifyHashSignature({ ...dummyOpts, hash: new Uint8Array(1) })
    ).rejects.toThrow("too short");
  });

  test("rejects hash longer than 128 bytes", async () => {
    await expect(
      verifyHashSignature({ ...dummyOpts, hash: new Uint8Array(129) })
    ).rejects.toThrow("too long");
  });

  test("accepts hash of exactly 16 bytes", async () => {
    // Will fail later (bad clientDataJSON), but should pass the length check.
    await expect(
      verifyHashSignature({ ...dummyOpts, hash: new Uint8Array(16) })
    ).rejects.not.toThrow("too short");
  });

  test("accepts hash of exactly 32 bytes (SHA-256)", async () => {
    await expect(
      verifyHashSignature({ ...dummyOpts, hash: new Uint8Array(32) })
    ).rejects.not.toThrow("too short");
  });
});

// ---------------------------------------------------------------------------
// End-to-end EC256 sign + verify round-trip
// ---------------------------------------------------------------------------

describe("verifyHashSignature end-to-end (ES256)", () => {
  const rpId = "example.com";
  const origin = "https://example.com";

  /**
   * Build a COSE EC2 P-256 public key from a Node.js KeyObject.
   * This mimics what an authenticator would store.
   */
  function buildCoseEC2Key(pubKey: nodeCrypto.KeyObject): Uint8Array {
    const jwk = pubKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");

    // Manually encode as CBOR map: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    // Using raw CBOR encoding for a 5-pair map.
    const parts: Uint8Array[] = [];

    // Map header: 5 pairs
    parts.push(new Uint8Array([0xa5]));

    // 1: 2 (kty: EC2)
    parts.push(new Uint8Array([0x01, 0x02]));

    // 3: -7 (alg: ES256, encoded as CBOR neg int -7 = major1(6) = 0x26)
    parts.push(new Uint8Array([0x03, 0x26]));

    // -1: 1 (crv: P-256, key -1 = major1(0) = 0x20)
    parts.push(new Uint8Array([0x20, 0x01]));

    // -2: x (32 bytes, key -2 = major1(1) = 0x21, bstr(32) = 0x58 0x20)
    parts.push(new Uint8Array([0x21, 0x58, 0x20]));
    parts.push(new Uint8Array(x));

    // -3: y (32 bytes, key -3 = major1(2) = 0x22, bstr(32) = 0x58 0x20)
    parts.push(new Uint8Array([0x22, 0x58, 0x20]));
    parts.push(new Uint8Array(y));

    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  /**
   * Simulate a WebAuthn assertion: build authenticatorData and clientDataJSON,
   * then sign with the private key.
   */
  function simulateAssertion(
    privateKey: nodeCrypto.KeyObject,
    hash: Uint8Array,
    signCount: number,
  ) {
    // Build authenticator data (37 bytes)
    const rpIdHash = sha256(rpId);
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = 0x05; // UP + UV flags
    const scView = new DataView(authData.buffer, 33, 4);
    scView.setUint32(0, signCount, false);

    // Build clientDataJSON
    const clientData = {
      type: "webauthn.get",
      challenge: bytesToBase64url(hash),
      origin,
      crossOrigin: false,
    };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

    // Sign: authenticatorData || SHA-256(clientDataJSON)
    const clientDataHash = sha256(clientDataJSON);
    const message = Buffer.concat([authData, clientDataHash]);

    const signature = nodeCrypto.sign("SHA256", message, privateKey);

    return {
      authenticatorData: authData,
      clientDataJSON: new Uint8Array(clientDataJSON),
      signature: new Uint8Array(signature),
      credentialId: "test-credential",
    };
  }

  let keyPair: nodeCrypto.KeyPairKeyObjectResult;
  let cosePublicKey: Uint8Array;

  beforeAll(() => {
    keyPair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    cosePublicKey = buildCoseEC2Key(keyPair.publicKey);
  });

  test("verifies a valid signature", async () => {
    const hash = sha256("test document");
    const passkeySig = simulateAssertion(keyPair.privateKey, hash, 1);

    const credential: Pick<PasskeyCredential, "publicKey" | "algorithm" | "signCount"> = {
      publicKey: cosePublicKey,
      algorithm: -7,
      signCount: 0,
    };

    const result = await verifyHashSignature({
      hash,
      passkeySig,
      credential,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(result.verified).toBe(true);
    expect(result.newSignCount).toBe(1);
  });

  test("rejects when hash doesn't match challenge", async () => {
    const hash = sha256("document A");
    const passkeySig = simulateAssertion(keyPair.privateKey, hash, 1);

    const differentHash = sha256("document B");

    await expect(
      verifyHashSignature({
        hash: differentHash,
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -7, signCount: 0 },
        expectedOrigin: origin,
        expectedRpId: rpId,
      })
    ).rejects.toThrow("does not match");
  });

  test("rejects wrong origin", async () => {
    const hash = sha256("test");
    const passkeySig = simulateAssertion(keyPair.privateKey, hash, 1);

    await expect(
      verifyHashSignature({
        hash,
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -7, signCount: 0 },
        expectedOrigin: "https://evil.com",
        expectedRpId: rpId,
      })
    ).rejects.toThrow("Origin mismatch");
  });

  test("rejects wrong rpId", async () => {
    const hash = sha256("test");
    const passkeySig = simulateAssertion(keyPair.privateKey, hash, 1);

    await expect(
      verifyHashSignature({
        hash,
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -7, signCount: 0 },
        expectedOrigin: origin,
        expectedRpId: "evil.com",
      })
    ).rejects.toThrow("rpIdHash mismatch");
  });

  test("rejects sign-count regression", async () => {
    const hash = sha256("test");
    const passkeySig = simulateAssertion(keyPair.privateKey, hash, 5);

    await expect(
      verifyHashSignature({
        hash,
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -7, signCount: 10 },
        expectedOrigin: origin,
        expectedRpId: rpId,
      })
    ).rejects.toThrow("Sign count regression");
  });

  test("rejects tampered signature", async () => {
    const hash = sha256("test");
    const passkeySig = simulateAssertion(keyPair.privateKey, hash, 1);

    // Flip a byte in the signature
    passkeySig.signature[0] = (passkeySig.signature[0]! ^ 0xff);

    await expect(
      verifyHashSignature({
        hash,
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -7, signCount: 0 },
        expectedOrigin: origin,
        expectedRpId: rpId,
      })
    ).rejects.toThrow("signature verification failed");
  });

  test("rejects when UV flag is missing and requireUserVerification is true", async () => {
    const hash = sha256("test");
    const passkeySig = simulateAssertion(keyPair.privateKey, hash, 1);

    // Clear the UV flag (bit 2) in authenticator data
    passkeySig.authenticatorData[32] = 0x01; // UP only, no UV

    await expect(
      verifyHashSignature({
        hash,
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -7, signCount: 0 },
        expectedOrigin: origin,
        expectedRpId: rpId,
        requireUserVerification: true,
      })
    ).rejects.toThrow("User Verification");
  });

  test("accepts when UV flag is missing and requireUserVerification is false", async () => {
    const hash = sha256("test");

    // Build assertion manually with UP but no UV
    const rpIdHash = sha256(rpId);
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = 0x01; // UP only
    const scView = new DataView(authData.buffer, 33, 4);
    scView.setUint32(0, 1, false);

    const clientData = {
      type: "webauthn.get",
      challenge: bytesToBase64url(hash),
      origin,
      crossOrigin: false,
    };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
    const clientDataHash = sha256(clientDataJSON);
    const message = Buffer.concat([authData, clientDataHash]);
    const signature = nodeCrypto.sign("SHA256", message, keyPair.privateKey);

    const result = await verifyHashSignature({
      hash,
      passkeySig: {
        credentialId: "test",
        authenticatorData: authData,
        clientDataJSON: new Uint8Array(clientDataJSON),
        signature: new Uint8Array(signature),
      },
      credential: { publicKey: cosePublicKey, algorithm: -7, signCount: 0 },
      expectedOrigin: origin,
      expectedRpId: rpId,
      requireUserVerification: false,
    });

    expect(result.verified).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// End-to-end Ed25519 sign + verify round-trip
// ---------------------------------------------------------------------------

describe("verifyHashSignature end-to-end (EdDSA/Ed25519)", () => {
  const rpId = "example.com";
  const origin = "https://example.com";

  function buildCoseOKPKey(pubKey: nodeCrypto.KeyObject): Uint8Array {
    const jwk = pubKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x!, "base64url");

    const parts: Uint8Array[] = [];

    // Map header: 4 pairs
    parts.push(new Uint8Array([0xa4]));

    // 1: 1 (kty: OKP)
    parts.push(new Uint8Array([0x01, 0x01]));

    // 3: -8 (alg: EdDSA, encoded as CBOR neg int -8 = major1(7) = 0x27)
    parts.push(new Uint8Array([0x03, 0x27]));

    // -1: 6 (crv: Ed25519)
    parts.push(new Uint8Array([0x20, 0x06]));

    // -2: x (32 bytes)
    parts.push(new Uint8Array([0x21, 0x58, 0x20]));
    parts.push(new Uint8Array(x));

    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  function simulateEdDSAAssertion(
    privateKey: nodeCrypto.KeyObject,
    hash: Uint8Array,
    signCount: number,
  ) {
    const rpIdHash = sha256(rpId);
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = 0x05; // UP + UV
    const scView = new DataView(authData.buffer, 33, 4);
    scView.setUint32(0, signCount, false);

    const clientData = {
      type: "webauthn.get",
      challenge: bytesToBase64url(hash),
      origin,
      crossOrigin: false,
    };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
    const clientDataHash = sha256(clientDataJSON);
    const message = Buffer.concat([authData, clientDataHash]);

    // Ed25519 uses one-shot signing (no pre-hash)
    const signature = nodeCrypto.sign(null, message, privateKey);

    return {
      authenticatorData: authData,
      clientDataJSON: new Uint8Array(clientDataJSON),
      signature: new Uint8Array(signature),
      credentialId: "test-ed25519-credential",
    };
  }

  let keyPair: nodeCrypto.KeyPairKeyObjectResult;
  let cosePublicKey: Uint8Array;

  beforeAll(() => {
    keyPair = nodeCrypto.generateKeyPairSync("ed25519");
    cosePublicKey = buildCoseOKPKey(keyPair.publicKey);
  });

  test("verifies a valid Ed25519 signature", async () => {
    const hash = sha256("ed25519 test document");
    const passkeySig = simulateEdDSAAssertion(keyPair.privateKey, hash, 1);

    const result = await verifyHashSignature({
      hash,
      passkeySig,
      credential: { publicKey: cosePublicKey, algorithm: -8, signCount: 0 },
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(result.verified).toBe(true);
    expect(result.newSignCount).toBe(1);
  });

  test("rejects a tampered Ed25519 signature", async () => {
    const hash = sha256("ed25519 test");
    const passkeySig = simulateEdDSAAssertion(keyPair.privateKey, hash, 1);

    passkeySig.signature[0] = (passkeySig.signature[0]! ^ 0xff);

    await expect(
      verifyHashSignature({
        hash,
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -8, signCount: 0 },
        expectedOrigin: origin,
        expectedRpId: rpId,
      })
    ).rejects.toThrow("signature verification failed");
  });

  test("rejects when hash doesn't match (Ed25519)", async () => {
    const hash = sha256("doc A");
    const passkeySig = simulateEdDSAAssertion(keyPair.privateKey, hash, 1);

    await expect(
      verifyHashSignature({
        hash: sha256("doc B"),
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -8, signCount: 0 },
        expectedOrigin: origin,
        expectedRpId: rpId,
      })
    ).rejects.toThrow("does not match");
  });
});

// ---------------------------------------------------------------------------
// End-to-end RSA sign + verify round-trip
// ---------------------------------------------------------------------------

describe("verifyHashSignature end-to-end (RS256)", () => {
  const rpId = "example.com";
  const origin = "https://example.com";

  function buildCoseRSAKey(pubKey: nodeCrypto.KeyObject): Uint8Array {
    const jwk = pubKey.export({ format: "jwk" });
    const n = Buffer.from(jwk.n!, "base64url");
    const e = Buffer.from(jwk.e!, "base64url");

    const parts: Uint8Array[] = [];

    // Map header: 4 pairs
    parts.push(new Uint8Array([0xa4]));

    // 1: 3 (kty: RSA)
    parts.push(new Uint8Array([0x01, 0x03]));

    // 3: -257 (alg: RS256) — CBOR neg int -257 = major1(256) = 0x39 0x01 0x00
    parts.push(new Uint8Array([0x03, 0x39, 0x01, 0x00]));

    // -1: n (bstr)
    parts.push(new Uint8Array([0x20])); // key: -1
    // Encode byte string header for n
    if (n.length < 256) {
      parts.push(new Uint8Array([0x58, n.length]));
    } else {
      parts.push(new Uint8Array([0x59, (n.length >> 8) & 0xff, n.length & 0xff]));
    }
    parts.push(new Uint8Array(n));

    // -2: e (bstr)
    parts.push(new Uint8Array([0x21])); // key: -2
    parts.push(new Uint8Array([0x43])); // bstr(3) — e is typically 3 bytes
    parts.push(new Uint8Array(e));

    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  function simulateRSAAssertion(
    privateKey: nodeCrypto.KeyObject,
    hash: Uint8Array,
    signCount: number,
  ) {
    const rpIdHash = sha256(rpId);
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = 0x05;
    const scView = new DataView(authData.buffer, 33, 4);
    scView.setUint32(0, signCount, false);

    const clientData = {
      type: "webauthn.get",
      challenge: bytesToBase64url(hash),
      origin,
      crossOrigin: false,
    };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
    const clientDataHash = sha256(clientDataJSON);
    const message = Buffer.concat([authData, clientDataHash]);
    const signature = nodeCrypto.sign("SHA256", message, privateKey);

    return {
      authenticatorData: authData,
      clientDataJSON: new Uint8Array(clientDataJSON),
      signature: new Uint8Array(signature),
      credentialId: "test-rsa-credential",
    };
  }

  let keyPair: nodeCrypto.KeyPairKeyObjectResult;
  let cosePublicKey: Uint8Array;

  beforeAll(() => {
    keyPair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    cosePublicKey = buildCoseRSAKey(keyPair.publicKey);
  });

  test("verifies a valid RS256 signature", async () => {
    const hash = sha256("rsa test document");
    const passkeySig = simulateRSAAssertion(keyPair.privateKey, hash, 1);

    const result = await verifyHashSignature({
      hash,
      passkeySig,
      credential: { publicKey: cosePublicKey, algorithm: -257, signCount: 0 },
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(result.verified).toBe(true);
  });

  test("rejects a tampered RS256 signature", async () => {
    const hash = sha256("rsa test");
    const passkeySig = simulateRSAAssertion(keyPair.privateKey, hash, 1);

    passkeySig.signature[10] = (passkeySig.signature[10]! ^ 0xff);

    await expect(
      verifyHashSignature({
        hash,
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -257, signCount: 0 },
        expectedOrigin: origin,
        expectedRpId: rpId,
      })
    ).rejects.toThrow("signature verification failed");
  });
});

// ---------------------------------------------------------------------------
// Sign-count edge cases (test gaps #9, #10)
// ---------------------------------------------------------------------------

describe("verifyHashSignature sign-count edge cases", () => {
  const rpId = "example.com";
  const origin = "https://example.com";

  let keyPair: nodeCrypto.KeyPairKeyObjectResult;
  let cosePublicKey: Uint8Array;

  beforeAll(() => {
    keyPair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    // Reuse EC2 COSE key builder inline
    const jwk = keyPair.publicKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const parts = [
      new Uint8Array([0xa5]),
      new Uint8Array([0x01, 0x02]),
      new Uint8Array([0x03, 0x26]),
      new Uint8Array([0x20, 0x01]),
      new Uint8Array([0x21, 0x58, 0x20]), new Uint8Array(x),
      new Uint8Array([0x22, 0x58, 0x20]), new Uint8Array(y),
    ];
    const total = parts.reduce((n, p) => n + p.length, 0);
    cosePublicKey = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { cosePublicKey.set(p, off); off += p.length; }
  });

  function makeAssertion(hash: Uint8Array, signCount: number) {
    const rpIdHash = sha256(rpId);
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = 0x05;
    new DataView(authData.buffer, 33, 4).setUint32(0, signCount, false);
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({
      type: "webauthn.get",
      challenge: bytesToBase64url(hash),
      origin,
      crossOrigin: false,
    }));
    const message = Buffer.concat([authData, sha256(clientDataJSON)]);
    return {
      authenticatorData: authData,
      clientDataJSON: new Uint8Array(clientDataJSON),
      signature: new Uint8Array(nodeCrypto.sign("SHA256", message, keyPair.privateKey)),
      credentialId: "test",
    };
  }

  test("rejects sign count equal to stored (= is still a regression)", async () => {
    const hash = sha256("test");
    const passkeySig = makeAssertion(hash, 5); // reported = 5, stored = 5

    await expect(
      verifyHashSignature({
        hash,
        passkeySig,
        credential: { publicKey: cosePublicKey, algorithm: -7, signCount: 5 },
        expectedOrigin: origin,
        expectedRpId: rpId,
      })
    ).rejects.toThrow("Sign count regression");
  });

  test("skips sign-count check when both stored and received are 0", async () => {
    const hash = sha256("test");
    const passkeySig = makeAssertion(hash, 0); // both = 0

    const result = await verifyHashSignature({
      hash,
      passkeySig,
      credential: { publicKey: cosePublicKey, algorithm: -7, signCount: 0 },
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(result.verified).toBe(true);
    expect(result.newSignCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Assertion flag / ceremony-type edge cases (test gaps #11, #12, #13)
// ---------------------------------------------------------------------------

describe("verifyHashSignature flag and ceremony-type edge cases", () => {
  const rpId = "example.com";
  const origin = "https://example.com";

  let keyPair: nodeCrypto.KeyPairKeyObjectResult;
  let cosePublicKey: Uint8Array;

  beforeAll(() => {
    keyPair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = keyPair.publicKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const parts = [
      new Uint8Array([0xa5]),
      new Uint8Array([0x01, 0x02]),
      new Uint8Array([0x03, 0x26]),
      new Uint8Array([0x20, 0x01]),
      new Uint8Array([0x21, 0x58, 0x20]), new Uint8Array(x),
      new Uint8Array([0x22, 0x58, 0x20]), new Uint8Array(y),
    ];
    const total = parts.reduce((n, p) => n + p.length, 0);
    cosePublicKey = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { cosePublicKey.set(p, off); off += p.length; }
  });

  function makeCustomAssertion(hash: Uint8Array, opts: {
    flags?: number;
    type?: string;
    crossOrigin?: boolean;
  } = {}) {
    const rpIdHash = sha256(rpId);
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = opts.flags ?? 0x05;
    new DataView(authData.buffer, 33, 4).setUint32(0, 1, false);
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({
      type: opts.type ?? "webauthn.get",
      challenge: bytesToBase64url(hash),
      origin,
      crossOrigin: opts.crossOrigin ?? false,
    }));
    const message = Buffer.concat([authData, sha256(clientDataJSON)]);
    return {
      authenticatorData: authData,
      clientDataJSON: new Uint8Array(clientDataJSON),
      signature: new Uint8Array(nodeCrypto.sign("SHA256", message, keyPair.privateKey)),
      credentialId: "test",
    };
  }

  const credential = () => ({ publicKey: cosePublicKey, algorithm: -7 as const, signCount: 0 });

  test("rejects when UP flag is cleared (#11)", async () => {
    const hash = sha256("test");
    const passkeySig = makeCustomAssertion(hash, { flags: 0x04 }); // UV only, no UP
    await expect(
      verifyHashSignature({ hash, passkeySig, credential: credential(), expectedOrigin: origin, expectedRpId: rpId })
    ).rejects.toThrow("User Presence");
  });

  test("rejects crossOrigin: true in assertion (#12)", async () => {
    const hash = sha256("test");
    const passkeySig = makeCustomAssertion(hash, { crossOrigin: true });
    await expect(
      verifyHashSignature({ hash, passkeySig, credential: credential(), expectedOrigin: origin, expectedRpId: rpId })
    ).rejects.toThrow("Cross-origin");
  });

  test("rejects wrong ceremony type (webauthn.create) in assertion (#13)", async () => {
    const hash = sha256("test");
    const passkeySig = makeCustomAssertion(hash, { type: "webauthn.create" });
    await expect(
      verifyHashSignature({ hash, passkeySig, credential: credential(), expectedOrigin: origin, expectedRpId: rpId })
    ).rejects.toThrow("webauthn.get");
  });

  test("rejects BS=1 without BE=1 in assertion (§6.1.3)", async () => {
    const hash = sha256("test");
    // 0x05 = UP+UV, 0x10 = BS set, 0x08 = BE unset → flags = 0x05 | 0x10 = 0x15
    const passkeySig = makeCustomAssertion(hash, { flags: 0x15 }); // UP+UV+BS, no BE
    await expect(
      verifyHashSignature({ hash, passkeySig, credential: credential(), expectedOrigin: origin, expectedRpId: rpId })
    ).rejects.toThrow("BS");
  });
});

// ---------------------------------------------------------------------------
// Input size limit tests
// ---------------------------------------------------------------------------

describe("verifyHashSignature input size limits", () => {
  const base = {
    hash: new Uint8Array(32),
    credential: { publicKey: new Uint8Array(1), algorithm: -7 as const, signCount: 0 },
    expectedOrigin: "https://example.com",
    expectedRpId: "example.com",
  };

  test("rejects oversized clientDataJSON", async () => {
    await expect(
      verifyHashSignature({
        ...base,
        passkeySig: {
          credentialId: "x",
          authenticatorData: new Uint8Array(37),
          clientDataJSON: new Uint8Array(5000), // > 4096
          signature: new Uint8Array(64),
        },
      })
    ).rejects.toThrow("too large");
  });

  test("rejects oversized authenticatorData", async () => {
    await expect(
      verifyHashSignature({
        ...base,
        passkeySig: {
          credentialId: "x",
          authenticatorData: new Uint8Array(40000), // > 32768
          clientDataJSON: new Uint8Array(10),
          signature: new Uint8Array(64),
        },
      })
    ).rejects.toThrow("too large");
  });

  test("rejects oversized signature", async () => {
    await expect(
      verifyHashSignature({
        ...base,
        passkeySig: {
          credentialId: "x",
          authenticatorData: new Uint8Array(37),
          clientDataJSON: new Uint8Array(10),
          signature: new Uint8Array(2000), // > 1024
        },
      })
    ).rejects.toThrow("too large");
  });
});

// ---------------------------------------------------------------------------
// Stored algorithm vs COSE algorithm cross-check
// ---------------------------------------------------------------------------

describe("verifyHashSignature algorithm cross-check", () => {
  const rpId = "example.com";
  const origin = "https://example.com";

  let keyPair: nodeCrypto.KeyPairKeyObjectResult;
  let cosePublicKey: Uint8Array;

  beforeAll(() => {
    keyPair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = keyPair.publicKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const parts = [
      new Uint8Array([0xa5]),
      new Uint8Array([0x01, 0x02]),
      new Uint8Array([0x03, 0x26]),
      new Uint8Array([0x20, 0x01]),
      new Uint8Array([0x21, 0x58, 0x20]), new Uint8Array(x),
      new Uint8Array([0x22, 0x58, 0x20]), new Uint8Array(y),
    ];
    const total = parts.reduce((n, p) => n + p.length, 0);
    cosePublicKey = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { cosePublicKey.set(p, off); off += p.length; }
  });

  test("rejects when stored algorithm differs from COSE key algorithm", async () => {
    const hash = sha256("test");
    const rpIdHash = sha256(rpId);
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = 0x05;
    new DataView(authData.buffer, 33, 4).setUint32(0, 1, false);
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({
      type: "webauthn.get", challenge: bytesToBase64url(hash), origin, crossOrigin: false,
    }));
    const message = Buffer.concat([authData, sha256(clientDataJSON)]);
    const signature = nodeCrypto.sign("SHA256", message, keyPair.privateKey);

    // COSE key is EC2/ES256 (-7), but we claim stored algorithm is -257 (RS256)
    await expect(
      verifyHashSignature({
        hash,
        passkeySig: {
          credentialId: "test",
          authenticatorData: authData,
          clientDataJSON: new Uint8Array(clientDataJSON),
          signature: new Uint8Array(signature),
        },
        credential: { publicKey: cosePublicKey, algorithm: -257, signCount: 0 },
        expectedOrigin: origin,
        expectedRpId: rpId,
      })
    ).rejects.toThrow("Algorithm mismatch");
  });
});

