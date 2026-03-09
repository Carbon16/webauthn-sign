# webauthnsign

**Sign arbitrary hashes with a WebAuthn passkey.**

A zero-runtime-dependency TypeScript package that lets your users digitally
sign any data (documents, transactions, consent records …) using the passkey
already stored on their device.  Includes browser-side signing and Node.js
server-side verification.

---

## Security model

WebAuthn was designed for authentication, but it can safely be used for
signing arbitrary hashes by exploiting the structure of the assertion.

When a user signs, the authenticator produces:

```
signature = Sign(privKey,  authenticatorData  ||  SHA-256(clientDataJSON))
```

`clientDataJSON` is a JSON object that contains (among other fields):

| Field | Value |
|---|---|
| `type` | `"webauthn.get"` |
| `origin` | The page origin, e.g. `"https://example.com"` |
| `challenge` | **`base64url(hash)`** — your document hash |

The server verifies that:

1. `clientDataJSON.challenge === base64url(hash)` — the signature commits to your exact hash.
2. `clientDataJSON.type === "webauthn.get"` — correct ceremony type.
3. `clientDataJSON.origin === expectedOrigin` — prevents cross-site abuse.
4. `rpIdHash === SHA-256(expectedRpId)` — correct relying party.
5. `UP` flag is set — the user physically interacted with the authenticator.
6. `UV` flag is set — the user completed PIN / biometric (proof of intent).
7. Sign count strictly increased — detects cloned authenticators.
8. Cryptographic signature is valid — the private key really signed the data.


### Replay-attack prevention

> **Include a nonce, timestamp, or binding context in the data you hash.**

The same hash value will produce different authenticator-data bytes each time
(sign count increments, fresh ceremony), so raw replay of a captured signature
is blocked.  However if you use `SHA-256(document)` alone, a second signing
ceremony on the same document is indistinguishable from the first.  Bind
additional context to prevent this:

```ts
const payload = JSON.stringify({
  document: base64url(docBytes),
  nonce:    crypto.randomUUID(),   // or a server-issued nonce
  issuedAt: Date.now(),
});
const hash = await sha256Browser(new TextEncoder().encode(payload));
```

---

## Installation

```bash
npm install webauthnsign
```

---

## Usage

### 1 — Register a passkey (one-time, per user)

#### Browser

```ts
import { registerPasskey } from "webauthnsign/client";

// Challenge must be generated server-side and be single-use.
const challenge = await fetchFromServer("/register/challenge");

const raw = await registerPasskey({
  rpId:     "example.com",
  rpName:   "My App",
  userId:   crypto.getRandomValues(new Uint8Array(16)), // opaque, not PII
  userName: "alice",
  challenge,
});

// Send to server:
await fetch("/register/verify", {
  method: "POST",
  body: JSON.stringify({
    credentialId:      raw.credentialId,
    attestationObject: bytesToBase64url(raw.attestationObject),
    clientDataJSON:    bytesToBase64url(raw.clientDataJSON),
    transports:        raw.transports,
  }),
});
```

#### Server (Node.js)

```ts
import { parseRegistrationResponse, sha256 } from "webauthnsign/server";
import { base64urlToBytes }                   from "webauthnsign/server";

const credential = await parseRegistrationResponse(
  {
    attestationObject: base64urlToBytes(body.attestationObject),
    clientDataJSON:    base64urlToBytes(body.clientDataJSON),
    transports:        body.transports,
  },
  {
    expectedChallenge:       storedChallenge, // Uint8Array from your DB
    expectedOrigin:          "https://example.com",
    expectedRpId:            "example.com",
    requireUserVerification: true,            // default: true
  }
);

// Persist `credential` in your database.
// You need: id, publicKey, algorithm, signCount.
await db.credentials.insert(credential);
```

---

### 2 — Sign a hash (per operation)

#### Browser

```ts
import { signHash, sha256Browser, bytesToBase64url } from "webauthnsign/client";

const document  = new TextEncoder().encode("Transfer $100 to Alice");
const nonce     = crypto.getRandomValues(new Uint8Array(16));
const payload   = JSON.stringify({
  doc:   bytesToBase64url(document),
  nonce: bytesToBase64url(nonce),
  ts:    Date.now(),
});
const hash = await sha256Browser(new TextEncoder().encode(payload));

const sig = await signHash(hash, {
  rpId:          "example.com",
  credentialIds: [storedCredentialId],  // omit for any discoverable credential
  // defaults to userVerification: "required" — do NOT weaken this
});

await fetch("/sign/verify", {
  method: "POST",
  body: JSON.stringify({
    hash:             bytesToBase64url(hash),
    payload,                              // send so server can re-derive hash
    sig: {
      credentialId:    sig.credentialId,
      authenticatorData: bytesToBase64url(sig.authenticatorData),
      clientDataJSON:    bytesToBase64url(sig.clientDataJSON),
      signature:         bytesToBase64url(sig.signature),
    },
  }),
});
```

#### Server (Node.js)

```ts
import {
  verifyHashSignature,
  sha256,
  base64urlToBytes,
} from "webauthnsign/server";

// 1. Re-derive the hash from the payload (don't trust the client-supplied hash).
const hash = sha256(new TextEncoder().encode(body.payload));

// 2. Load the stored credential from your database.
const credential = await db.credentials.findById(sig.credentialId);
if (!credential) throw new Error("Unknown credential");

// 3. Verify.
const result = await verifyHashSignature({
  hash,
  passkeySig: {
    credentialId:      sig.credentialId,
    authenticatorData: base64urlToBytes(sig.authenticatorData),
    clientDataJSON:    base64urlToBytes(sig.clientDataJSON),
    signature:         base64urlToBytes(sig.signature),
  },
  credential,                           // { publicKey, algorithm, signCount }
  expectedOrigin:          "https://example.com",
  expectedRpId:            "example.com",
  requireUserVerification: true,
});

if (!result.verified) {
  throw new Error("Signature verification failed");
}

// 4. IMPORTANT: update sign count to enable cloned-authenticator detection.
await db.credentials.updateSignCount(credential.id, result.newSignCount);

// Signature is valid — proceed with the operation.
```

---

## API reference

### `webauthnsign/client`

| Export | Description |
|---|---|
| `isPasskeySupported()` | `Promise<boolean>` — checks platform authenticator availability |
| `registerPasskey(opts)` | Initiates a registration ceremony; returns raw response to send to server |
| `signHash(hash, opts)` | Signs `hash` using a passkey; returns `PasskeySignature` |
| `sha256Browser(data)` | SHA-256 via SubtleCrypto |
| `bytesToBase64url(bytes)` | Encode `Uint8Array` → base64url string |
| `base64urlToBytes(str)` | Decode base64url string → `Uint8Array` |

### `webauthnsign/server`

| Export | Description |
|---|---|
| `parseRegistrationResponse(response, opts)` | Verify attestation, extract and return `PasskeyCredential` |
| `verifyHashSignature(opts)` | Verify a `PasskeySignature` against a hash; returns `{ verified, newSignCount }` |
| `sha256(data)` | SHA-256 via Node.js `crypto` (synchronous) |
| `parseAuthenticatorData(authData)` | Parse the 37-byte authenticator data header |
| `bytesToBase64url` / `base64urlToBytes` / `bytesToHex` / `hexToBytes` / `formatAaguid` | Utilities |

### Shared types (`webauthnsign`)

`PasskeyRegistrationOptions`, `RawRegistrationResponse`, `PasskeyCredential`,
`SignHashOptions`, `PasskeySignature`, `VerifyHashOptions`, `VerifyHashResult`,
`ParsedAuthData`, `AuthenticatorFlags`, `CoseAlgorithm`, `COSE_ALGORITHMS`.

---

## Supported algorithms

| COSE alg | Name | Notes |
|---|---|---|
| `-7` | ES256 | ECDSA / P-256 / SHA-256 (preferred, used by Touch ID, Face ID, Android) |
| `-8` | EdDSA | Ed25519 (some hardware security keys) |
| `-257` | RS256 | RSA / PKCS#1v1.5 / SHA-256 (Windows Hello) |

---

## Security considerations

### What this package does NOT provide

- **Non-repudiation at a legal standard** — passkey signatures prove device
  consent but, unlike a qualified electronic signature (eIDAS, ESIGN Act),
  they do not have legal weight out-of-the-box.  Consult your legal team.
- **Long-term key storage** — if the user deletes their passkey or resets
  their device, the private key is gone.  Archive signed payloads, not keys.
- **Attestation verification** — `parseRegistrationResponse` validates the
  *structure* of the attestation object but does not verify attestation
  statements (e.g. "packed", "tpm").  Pass `attestation: "none"` (default)
  unless your threat model requires device-level attestation.

### Hardening checklist

- Generate challenges server-side with `crypto.getRandomValues` (≥ 32 bytes).
- Consume challenges exactly once (store in DB, delete on use).
- Include a nonce / timestamp in every payload you hash.
- Store `signCount` and update it after every successful verification.
- Lock `expectedOrigin` to your exact production HTTPS origin.
- Keep `requireUserVerification: true` (the default) for every sign operation.
- Reject credentials whose `signCount` regresses (cloned authenticator).
- Serve the relying party over HTTPS (WebAuthn requires a secure context).

---

## License

MIT
