import {
  base64urlToBytes,
  bytesToBase64url,
  bytesToHex,
  hexToBytes,
  concat,
  formatAaguid,
} from "../utils.js";

// ---------------------------------------------------------------------------
// base64url round-trip
// ---------------------------------------------------------------------------

describe("bytesToBase64url / base64urlToBytes", () => {
  test("round-trips an empty Uint8Array", () => {
    const empty = new Uint8Array(0);
    expect(base64urlToBytes(bytesToBase64url(empty))).toEqual(empty);
  });

  test("round-trips a single byte", () => {
    const one = new Uint8Array([0xff]);
    expect(base64urlToBytes(bytesToBase64url(one))).toEqual(one);
  });

  test("round-trips 32 random bytes (SHA-256 size)", () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = i * 8;
    const encoded = bytesToBase64url(bytes);
    expect(base64urlToBytes(encoded)).toEqual(bytes);
  });

  test("produces unpadded base64url (no trailing =)", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const encoded = bytesToBase64url(bytes);
    expect(encoded).not.toContain("=");
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
  });

  test("accepts padded input", () => {
    // "AQID" is base64url for [1, 2, 3]; with padding "AQID=="
    const result = base64urlToBytes("AQID");
    expect(result).toEqual(new Uint8Array([1, 2, 3]));
  });

  test("handles URL-safe characters (- and _)", () => {
    // Create bytes that produce + and / in standard base64.
    const bytes = new Uint8Array([0xfb, 0xef, 0xbe]); // produces ++++ in std base64
    const encoded = bytesToBase64url(bytes);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    const decoded = base64urlToBytes(encoded);
    expect(decoded).toEqual(bytes);
  });
});

// ---------------------------------------------------------------------------
// base64url input validation
// ---------------------------------------------------------------------------

describe("base64urlToBytes input validation", () => {
  test("rejects strings with spaces", () => {
    expect(() => base64urlToBytes("AQ ID")).toThrow("illegal characters");
  });

  test("rejects strings with special characters", () => {
    expect(() => base64urlToBytes("AQ+ID")).toThrow("illegal characters");
    expect(() => base64urlToBytes("AQ/ID")).toThrow("illegal characters");
  });

  test("rejects strings with newlines", () => {
    expect(() => base64urlToBytes("AQ\nID")).toThrow("illegal characters");
  });

  test("accepts valid base64url characters", () => {
    expect(() => base64urlToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")).not.toThrow();
  });

  test("accepts empty string", () => {
    expect(base64urlToBytes("")).toEqual(new Uint8Array(0));
  });
});

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

describe("bytesToHex / hexToBytes", () => {
  test("round-trips empty", () => {
    expect(hexToBytes(bytesToHex(new Uint8Array(0)))).toEqual(new Uint8Array(0));
  });

  test("round-trips known values", () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(bytesToHex(bytes)).toBe("deadbeef");
    expect(hexToBytes("deadbeef")).toEqual(bytes);
  });

  test("pads single-digit hex values", () => {
    const bytes = new Uint8Array([0x01, 0x00, 0x0f]);
    expect(bytesToHex(bytes)).toBe("01000f");
  });

  test("rejects odd-length hex strings", () => {
    expect(() => hexToBytes("abc")).toThrow("odd length");
  });

  test("rejects invalid hex characters", () => {
    expect(() => hexToBytes("zzzz")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// concat
// ---------------------------------------------------------------------------

describe("concat", () => {
  test("concatenates zero arrays", () => {
    expect(concat()).toEqual(new Uint8Array(0));
  });

  test("concatenates one array", () => {
    const a = new Uint8Array([1, 2, 3]);
    expect(concat(a)).toEqual(a);
  });

  test("concatenates multiple arrays", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4, 5]);
    const c = new Uint8Array([6]);
    expect(concat(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
  });

  test("handles empty arrays in the mix", () => {
    const a = new Uint8Array([1]);
    const b = new Uint8Array(0);
    const c = new Uint8Array([2]);
    expect(concat(a, b, c)).toEqual(new Uint8Array([1, 2]));
  });
});

// ---------------------------------------------------------------------------
// formatAaguid
// ---------------------------------------------------------------------------

describe("formatAaguid", () => {
  test("formats 16 zero bytes as UUID", () => {
    const zeros = new Uint8Array(16);
    expect(formatAaguid(zeros)).toBe("00000000-0000-0000-0000-000000000000");
  });

  test("formats known AAGUID", () => {
    const bytes = hexToBytes("f8a011f38c0a4d15800617111f9edc7d");
    expect(formatAaguid(bytes)).toBe("f8a011f3-8c0a-4d15-8006-17111f9edc7d");
  });

  test("rejects non-16-byte input", () => {
    expect(() => formatAaguid(new Uint8Array(10))).toThrow("16 bytes");
    expect(() => formatAaguid(new Uint8Array(20))).toThrow("16 bytes");
  });
});
