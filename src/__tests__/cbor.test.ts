import { decodeCbor } from "../cbor.js";

// ---------------------------------------------------------------------------
// Helper: manually encode CBOR values for testing
// ---------------------------------------------------------------------------

/** Encode an unsigned integer (major type 0). */
function cborUint(n: number): Uint8Array {
  if (n < 24) return new Uint8Array([n]);
  if (n < 256) return new Uint8Array([24, n]);
  if (n < 65536) return new Uint8Array([25, (n >> 8) & 0xff, n & 0xff]);
  return new Uint8Array([
    26, (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff,
  ]);
}

/** Encode a negative integer (major type 1). Value is -1 - n. */
function cborNegInt(n: number): Uint8Array {
  const bytes = cborUint(n);
  bytes[0] = (bytes[0]! | 0x20); // Set major type 1
  return bytes;
}

/** Encode a byte string (major type 2). */
function cborBytes(data: Uint8Array): Uint8Array {
  const header = cborUint(data.length);
  header[0] = (header[0]! | 0x40); // Set major type 2
  const out = new Uint8Array(header.length + data.length);
  out.set(header);
  out.set(data, header.length);
  return out;
}

/** Encode a text string (major type 3). */
function cborText(str: string): Uint8Array {
  const textBytes = new TextEncoder().encode(str);
  const header = cborUint(textBytes.length);
  header[0] = (header[0]! | 0x60); // Set major type 3
  const out = new Uint8Array(header.length + textBytes.length);
  out.set(header);
  out.set(textBytes, header.length);
  return out;
}

/** Encode a CBOR array header (major type 4). Items must be appended separately. */
function cborArrayHeader(count: number): Uint8Array {
  const header = cborUint(count);
  header[0] = (header[0]! | 0x80); // Set major type 4
  return header;
}

/** Encode a CBOR map header (major type 5). Pairs must be appended separately. */
function cborMapHeader(count: number): Uint8Array {
  const header = cborUint(count);
  header[0] = (header[0]! | 0xa0); // Set major type 5
  return header;
}

/** Concatenate multiple Uint8Arrays. */
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
// Basic type decoding
// ---------------------------------------------------------------------------

describe("CBOR unsigned integers", () => {
  test("decodes small integers (0-23)", () => {
    expect(decodeCbor(new Uint8Array([0]))).toBe(0);
    expect(decodeCbor(new Uint8Array([1]))).toBe(1);
    expect(decodeCbor(new Uint8Array([23]))).toBe(23);
  });

  test("decodes 1-byte integers (24-255)", () => {
    expect(decodeCbor(new Uint8Array([24, 24]))).toBe(24);
    expect(decodeCbor(new Uint8Array([24, 255]))).toBe(255);
  });

  test("decodes 2-byte integers", () => {
    expect(decodeCbor(new Uint8Array([25, 1, 0]))).toBe(256);
  });

  test("decodes 4-byte integers", () => {
    expect(decodeCbor(new Uint8Array([26, 0, 1, 0, 0]))).toBe(65536);
  });
});

describe("CBOR negative integers", () => {
  test("decodes -1", () => {
    expect(decodeCbor(cborNegInt(0))).toBe(-1);
  });

  test("decodes -7", () => {
    expect(decodeCbor(cborNegInt(6))).toBe(-7);
  });

  test("decodes -257", () => {
    expect(decodeCbor(cborNegInt(256))).toBe(-257);
  });
});

describe("CBOR byte strings", () => {
  test("decodes empty byte string", () => {
    const result = decodeCbor(cborBytes(new Uint8Array(0)));
    expect(result).toEqual(new Uint8Array(0));
  });

  test("decodes byte string with data", () => {
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const result = decodeCbor(cborBytes(data));
    expect(result).toEqual(data);
  });
});

describe("CBOR text strings", () => {
  test("decodes empty text string", () => {
    expect(decodeCbor(cborText(""))).toBe("");
  });

  test("decodes ASCII text", () => {
    expect(decodeCbor(cborText("hello"))).toBe("hello");
  });

  test("decodes UTF-8 text", () => {
    expect(decodeCbor(cborText("日本語"))).toBe("日本語");
  });
});

// ---------------------------------------------------------------------------
// Compound types
// ---------------------------------------------------------------------------

describe("CBOR arrays", () => {
  test("decodes empty array", () => {
    expect(decodeCbor(cborArrayHeader(0))).toEqual([]);
  });

  test("decodes array of integers", () => {
    const encoded = cat(cborArrayHeader(3), cborUint(1), cborUint(2), cborUint(3));
    expect(decodeCbor(encoded)).toEqual([1, 2, 3]);
  });

  test("decodes nested array", () => {
    // [1, [2, 3]]
    const inner = cat(cborArrayHeader(2), cborUint(2), cborUint(3));
    const outer = cat(cborArrayHeader(2), cborUint(1), inner);
    expect(decodeCbor(outer)).toEqual([1, [2, 3]]);
  });
});

describe("CBOR maps", () => {
  test("decodes empty map", () => {
    const result = decodeCbor(cborMapHeader(0));
    expect(result).toBeInstanceOf(Map);
    expect((result as Map<unknown, unknown>).size).toBe(0);
  });

  test("decodes map with text keys", () => {
    // {"a": 1, "b": 2}
    const encoded = cat(
      cborMapHeader(2),
      cborText("a"), cborUint(1),
      cborText("b"), cborUint(2),
    );
    const result = decodeCbor(encoded) as Map<string, number>;
    expect(result.get("a")).toBe(1);
    expect(result.get("b")).toBe(2);
  });

  test("decodes map with integer keys (COSE-style)", () => {
    // {1: 2, 3: -7}
    const encoded = cat(
      cborMapHeader(2),
      cborUint(1), cborUint(2),
      cborUint(3), cborNegInt(6),
    );
    const result = decodeCbor(encoded) as Map<number, number>;
    expect(result.get(1)).toBe(2);
    expect(result.get(3)).toBe(-7);
  });
});

// ---------------------------------------------------------------------------
// Security limits
// ---------------------------------------------------------------------------

describe("CBOR depth limit", () => {
  test("rejects deeply nested structures", () => {
    // Build 12 levels of nested single-element arrays: [[[[[[[[[[[[0]]]]]]]]]]]]
    let payload = cborUint(0);
    for (let i = 0; i < 12; i++) {
      payload = cat(cborArrayHeader(1), payload);
    }
    expect(() => decodeCbor(payload)).toThrow("maximum nesting depth");
  });

  test("accepts structures within depth limit", () => {
    // 5 levels deep is fine
    let payload: Uint8Array = cborUint(42);
    for (let i = 0; i < 5; i++) {
      payload = cat(cborArrayHeader(1), payload);
    }
    expect(() => decodeCbor(payload)).not.toThrow();
  });
});

describe("CBOR item count limit", () => {
  test("rejects map with too many claimed pairs", () => {
    // Claim 1000 pairs but don't actually provide them — the limit should
    // trigger before any allocation/parsing of items.
    const header = cborMapHeader(1000);
    // Provide enough dummy data so it doesn't fail on "end of data" first.
    // Actually, the limit check happens before reading items, so just the
    // header is enough.
    expect(() => decodeCbor(header)).toThrow("exceeds maximum");
  });

  test("rejects array with too many claimed items", () => {
    const header = cborArrayHeader(1000);
    expect(() => decodeCbor(header)).toThrow("exceeds maximum");
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe("CBOR error handling", () => {
  test("rejects empty input", () => {
    expect(() => decodeCbor(new Uint8Array(0))).toThrow();
  });

  test("rejects truncated byte string", () => {
    // Claim 10 bytes, provide 2.
    const encoded = cat(cborBytes(new Uint8Array(0)));
    const fraudulent = new Uint8Array([0x4a, 0x01, 0x02]); // 0x4a = bstr(10)
    expect(() => decodeCbor(fraudulent)).toThrow();
  });

  test("rejects unsupported major type (6 = tags)", () => {
    // Major type 6 (tag), additional info 0 → tag(0)
    expect(() => decodeCbor(new Uint8Array([0xc0, 0x00]))).toThrow("unsupported major type");
  });

  test("rejects unsupported major type (7 = simple/float)", () => {
    // Major type 7, value true (0xf5)
    expect(() => decodeCbor(new Uint8Array([0xf5]))).toThrow("unsupported major type");
  });

  test("rejects duplicate map keys", () => {
    // CBOR map {1: "a", 1: "b"} — duplicate integer key 1
    // 0xa2 = map(2), 0x01 = uint(1), 0x61 0x61 = text("a"), 0x01 = uint(1), 0x61 0x62 = text("b")
    const duplicateMap = new Uint8Array([0xa2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62]);
    expect(() => decodeCbor(duplicateMap)).toThrow("duplicate map key");
  });
});
