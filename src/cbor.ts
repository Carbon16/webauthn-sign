/**
 * Minimal, zero-dependency CBOR decoder for WebAuthn use-cases.
 *
 * Supported major types:
 *   0 – unsigned integer
 *   1 – negative integer
 *   2 – byte string
 *   3 – text string
 *   4 – array
 *   5 – map
 *
 * This is intentionally NOT a full CBOR implementation.  It only handles the
 * subset produced by WebAuthn authenticators (attestation objects and COSE
 * public keys).  Unsupported types throw immediately so mis-routed data is
 * caught rather than silently mishandled.
 */

// Map key / value types we actually encounter in WebAuthn CBOR payloads.
export type CborPrimitive = number | Uint8Array | string;
export type CborValue =
  | CborPrimitive
  | CborValue[]
  | Map<CborPrimitive, CborValue>;

interface DecodeResult {
  value: CborValue;
  /** Number of bytes consumed from the input starting at `offset`. */
  bytesRead: number;
}

/** Maximum nesting depth for CBOR structures (arrays/maps). */
const MAX_DEPTH = 10;

/** Maximum number of items in a CBOR array or pairs in a CBOR map. */
const MAX_ITEMS = 256;

/**
 * Decode a single CBOR data-item from `data`, asserting that all bytes are
 * consumed.  Use this when `data` contains exactly one top-level CBOR item
 * (e.g., an attestation object or a standalone COSE public key).
 *
 * @throws if the data uses unsupported CBOR features, is malformed, or has
 *   trailing bytes after the root item.
 */
export function decodeCbor(data: Uint8Array): CborValue {
  const { value, bytesRead } = decodeAt(data, 0, 0);
  if (bytesRead !== data.length) {
    throw new RangeError(
      `CBOR: ${data.length - bytesRead} trailing byte(s) after root item — input must contain exactly one CBOR data item`
    );
  }
  return value;
}

/**
 * Decode the first CBOR data-item from `data`, returning both the value and
 * the number of bytes it consumed.  Use this when the CBOR item is embedded
 * inside a larger buffer (e.g., a COSE public key inside authenticator data).
 *
 * @throws if the data uses unsupported CBOR features or is malformed.
 */
export function decodeCborFirst(data: Uint8Array): { value: CborValue; bytesRead: number } {
  const { value, bytesRead } = decodeAt(data, 0, 0);
  return { value, bytesRead };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function decodeAt(data: Uint8Array, offset: number, depth: number): DecodeResult {
  if (depth > MAX_DEPTH) {
    throw new RangeError(
      `CBOR: maximum nesting depth (${MAX_DEPTH}) exceeded at offset ${offset}`
    );
  }
  if (offset >= data.length) {
    throw new RangeError(`CBOR: unexpected end of data at offset ${offset}`);
  }

  const initialByte = data[offset] as number;
  const majorType = (initialByte >> 5) & 0x07;
  const additionalInfo = initialByte & 0x1f;

  // Decode the "argument" (integer value, or length of the following item).
  const { arg, headerSize } = decodeArg(data, offset, additionalInfo);
  const bodyOffset = offset + headerSize;

  switch (majorType) {
    case 0: {
      // Unsigned integer — argument IS the value.
      return { value: arg, bytesRead: headerSize };
    }

    case 1: {
      // Negative integer — value is -1 - argument.
      return { value: -1 - arg, bytesRead: headerSize };
    }

    case 2: {
      // Byte string — argument is the byte count.
      assertEnoughBytes(data, bodyOffset, arg, "byte string");
      const bytes = data.slice(bodyOffset, bodyOffset + arg);
      return { value: bytes, bytesRead: headerSize + arg };
    }

    case 3: {
      // Text string — argument is the UTF-8 byte count.
      assertEnoughBytes(data, bodyOffset, arg, "text string");
      const textBytes = data.slice(bodyOffset, bodyOffset + arg);
      const text = new TextDecoder("utf-8", { fatal: true }).decode(textBytes);
      return { value: text, bytesRead: headerSize + arg };
    }

    case 4: {
      // Array — argument is the item count.
      if (arg > MAX_ITEMS) {
        throw new RangeError(
          `CBOR: array contains ${arg} items, exceeds maximum of ${MAX_ITEMS}`
        );
      }
      const items: CborValue[] = [];
      let pos = bodyOffset;
      for (let i = 0; i < arg; i++) {
        const item = decodeAt(data, pos, depth + 1);
        items.push(item.value);
        pos += item.bytesRead;
      }
      return { value: items, bytesRead: pos - offset };
    }

    case 5: {
      // Map — argument is the pair count.
      if (arg > MAX_ITEMS) {
        throw new RangeError(
          `CBOR: map contains ${arg} pairs, exceeds maximum of ${MAX_ITEMS}`
        );
      }
      const map = new Map<CborPrimitive, CborValue>();
      let pos = bodyOffset;
      for (let i = 0; i < arg; i++) {
        const keyResult = decodeAt(data, pos, depth + 1);
        pos += keyResult.bytesRead;
        const valResult = decodeAt(data, pos, depth + 1);
        pos += valResult.bytesRead;

        const key = keyResult.value;
        if (
          typeof key !== "number" &&
          typeof key !== "string" &&
          !(key instanceof Uint8Array)
        ) {
          throw new TypeError(
            "CBOR: only primitive map keys (int, text, bytes) are supported"
          );
        }
        // Reject duplicate keys — a crafted COSE map could shadow kty/alg
        // entries by repeating a key; last-write-wins is a security hole.
        if (map.has(key as CborPrimitive)) {
          throw new Error(
            `CBOR: duplicate map key "${String(key)}" at pair ${i}`
          );
        }
        map.set(key as CborPrimitive, valResult.value);
      }
      return { value: map, bytesRead: pos - offset };
    }

    default:
      throw new TypeError(
        `CBOR: unsupported major type ${majorType} at offset ${offset}`
      );
  }
}

/** Decode the argument (count/value) that follows the initial byte. */
function decodeArg(
  data: Uint8Array,
  offset: number,
  additionalInfo: number
): { arg: number; headerSize: number } {
  if (additionalInfo < 24) {
    return { arg: additionalInfo, headerSize: 1 };
  }

  const start = offset + 1;

  if (additionalInfo === 24) {
    assertEnoughBytes(data, start, 1, "1-byte argument");
    return { arg: data[start] as number, headerSize: 2 };
  }

  if (additionalInfo === 25) {
    assertEnoughBytes(data, start, 2, "2-byte argument");
    const arg = ((data[start] as number) << 8) | (data[start + 1] as number);
    return { arg, headerSize: 3 };
  }

  if (additionalInfo === 26) {
    assertEnoughBytes(data, start, 4, "4-byte argument");
    const view = new DataView(data.buffer, data.byteOffset + start, 4);
    return { arg: view.getUint32(0, false), headerSize: 5 };
  }

  if (additionalInfo === 27) {
    // 8-byte unsigned integer — only safe if the value fits in a JS number.
    assertEnoughBytes(data, start, 8, "8-byte argument");
    const view = new DataView(data.buffer, data.byteOffset + start, 8);
    const hi = view.getUint32(0, false);
    const lo = view.getUint32(4, false);
    if (hi > 0x1fffff) {
      throw new RangeError("CBOR: 64-bit integer too large to represent safely");
    }
    return { arg: hi * 0x1_0000_0000 + lo, headerSize: 9 };
  }

  throw new TypeError(
    `CBOR: unsupported additional info ${additionalInfo} at offset ${offset}`
  );
}

function assertEnoughBytes(
  data: Uint8Array,
  offset: number,
  needed: number,
  context: string
): void {
  if (offset + needed > data.length) {
    throw new RangeError(
      `CBOR: not enough bytes for ${context} (need ${needed} at offset ${offset}, have ${data.length - offset})`
    );
  }
}
