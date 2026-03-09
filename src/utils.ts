// ---------------------------------------------------------------------------
// Base64url encoding / decoding — works in both browser and Node.js
// ---------------------------------------------------------------------------

/**
 * Decode a base64url string to bytes.
 * Accepts padded or unpadded input.
 */
export function base64urlToBytes(str: string): Uint8Array {
  // Reject strings with characters outside the base64url alphabet.
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(str)) {
    throw new Error("Invalid base64url string: contains illegal characters");
  }

  // Normalise: replace URL-safe chars, add padding.
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "="
  );

  // Node.js path — Buffer is faster and handles all edge-cases.
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }

  // Browser path.
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode bytes to an unpadded base64url string.
 */
export function bytesToBase64url(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64url");
  }

  // Browser path.
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] as number);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => (b as number).toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string — odd length");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (isNaN(byte)) throw new Error(`Invalid hex character at position ${i * 2}`);
    bytes[i] = byte;
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Buffer concatenation
// ---------------------------------------------------------------------------

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// AAGUID formatting
// ---------------------------------------------------------------------------

/** Format 16 raw AAGUID bytes as a standard UUID string. */
export function formatAaguid(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new Error("AAGUID must be 16 bytes");
  const h = bytesToHex(bytes);
  return [h.slice(0, 8), h.slice(8, 12), h.slice(12, 16), h.slice(16, 20), h.slice(20)].join("-");
}
