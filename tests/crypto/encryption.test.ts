/**
 * DEK / zero-knowledge encryption tests.
 *
 * Scope: every public function in `src/crypto/encryption.ts` — KEK
 * extraction from URL fragment, AES-256-GCM DEK unwrap, and graceful
 * degradation when WebCrypto is unavailable.
 *
 * Vectors: deterministic. A fixed 32-byte KEK wraps a fixed 32-byte DEK
 * under a fixed nonce using Node's WebCrypto (same implementation as
 * `src/crypto/encryption.ts`'s `crypto.subtle`). Producing the wrapped
 * blob at test time means the vector always matches the server-side wrap
 * format (base64(nonce || ciphertext || tag)) without static fixture drift.
 */
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest"
import { webcrypto as nodeWebCrypto } from "node:crypto"
import {
  extractKEKFromFragment,
  kekBase64ToBytes,
  unwrapDEK,
} from "../../src/crypto/encryption"

// ---------- Shared vector fixtures ----------

function fixtureKEK(): Uint8Array {
  const b = new Uint8Array(32)
  for (let i = 0; i < 32; i++) b[i] = i + 1
  return b
}
function fixtureDEK(): Uint8Array {
  const b = new Uint8Array(32)
  for (let i = 0; i < 32; i++) b[i] = 255 - i
  return b
}

/** base64 (standard) encode bytes -- matches `atob` / `btoa`. */
function toBase64(bytes: Uint8Array): string {
  let s = ""
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

/**
 * Wrap `dek` with `kek` using AES-256-GCM. Returns base64(nonce||ciphertext),
 * the exact format the Atol server emits in the `atol:wrapped_dek` claim.
 */
async function wrapDEK(
  kek: Uint8Array,
  dek: Uint8Array,
  nonce: Uint8Array,
): Promise<string> {
  const key = await nodeWebCrypto.subtle.importKey(
    "raw",
    kek,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  )
  const ciphertext = new Uint8Array(
    await nodeWebCrypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, dek),
  )
  const out = new Uint8Array(nonce.length + ciphertext.length)
  out.set(nonce, 0)
  out.set(ciphertext, nonce.length)
  return toBase64(out)
}

function fixtureNonce(): Uint8Array {
  const n = new Uint8Array(12)
  for (let i = 0; i < 12; i++) n[i] = 7 * i + 3
  return n
}

// jsdom's crypto has no real subtle. Swap Node's in for this file.
const originalCrypto = globalThis.crypto
beforeAll(() => {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: nodeWebCrypto,
  })
})
afterAll(() => {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: originalCrypto,
  })
})

// ---------- extractKEKFromFragment ----------

describe("extractKEKFromFragment", () => {
  beforeEach(() => {
    window.location.hash = ""
  })

  it("returns null when the fragment is missing", () => {
    expect(extractKEKFromFragment()).toBeNull()
  })

  it("returns null when the fragment has no atol_enc_key", () => {
    window.location.hash = "#foo=bar&baz=qux"
    expect(extractKEKFromFragment()).toBeNull()
  })

  it("extracts the KEK and strips it from the URL", () => {
    const kek = toBase64(fixtureKEK())
    window.location.hash = `#atol_enc_key=${encodeURIComponent(kek)}`
    expect(extractKEKFromFragment()).toBe(kek)
    expect(window.location.hash).toBe("")
  })

  it("preserves non-atol fragment entries after stripping the KEK", () => {
    const kek = toBase64(fixtureKEK())
    window.location.hash = `#code=abc&atol_enc_key=${encodeURIComponent(kek)}&state=xyz`
    expect(extractKEKFromFragment()).toBe(kek)
    const remaining = new URLSearchParams(window.location.hash.substring(1))
    expect(remaining.get("atol_enc_key")).toBeNull()
    expect(remaining.get("code")).toBe("abc")
    expect(remaining.get("state")).toBe("xyz")
  })

  it("returns null for an empty atol_enc_key value", () => {
    window.location.hash = "#atol_enc_key="
    expect(extractKEKFromFragment()).toBeNull()
  })
})

// ---------- unwrapDEK ----------

describe("unwrapDEK", () => {
  it("round-trips a correctly-wrapped DEK", async () => {
    const kek = fixtureKEK()
    const dek = fixtureDEK()
    const wrapped = await wrapDEK(kek, dek, fixtureNonce())
    const unwrapped = await unwrapDEK(toBase64(kek), wrapped)
    expect(unwrapped).toEqual(dek)
  })

  it("accepts base64url-encoded KEK (SDK reads from URL fragment)", async () => {
    const kek = fixtureKEK()
    const dek = fixtureDEK()
    const wrapped = await wrapDEK(kek, dek, fixtureNonce())
    const kekUrl = toBase64(kek)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "")
    const unwrapped = await unwrapDEK(kekUrl, wrapped)
    expect(unwrapped).toEqual(dek)
  })

  it("rejects when the KEK is wrong (AES-GCM auth tag mismatch)", async () => {
    const dek = fixtureDEK()
    const wrapped = await wrapDEK(fixtureKEK(), dek, fixtureNonce())
    const wrongKEK = new Uint8Array(32) // all zeros
    await expect(unwrapDEK(toBase64(wrongKEK), wrapped)).rejects.toBeDefined()
  })

  it("rejects when a ciphertext byte is flipped", async () => {
    const kek = fixtureKEK()
    const wrapped = await wrapDEK(kek, fixtureDEK(), fixtureNonce())
    const raw = Uint8Array.from(atob(wrapped), (c) => c.charCodeAt(0))
    raw[20] ^= 0x01
    const tampered = toBase64(raw)
    await expect(unwrapDEK(toBase64(kek), tampered)).rejects.toBeDefined()
  })

  it("rejects when the auth tag is flipped", async () => {
    const kek = fixtureKEK()
    const wrapped = await wrapDEK(kek, fixtureDEK(), fixtureNonce())
    const raw = Uint8Array.from(atob(wrapped), (c) => c.charCodeAt(0))
    raw[raw.length - 1] ^= 0x80
    const tampered = toBase64(raw)
    await expect(unwrapDEK(toBase64(kek), tampered)).rejects.toBeDefined()
  })

  it("rejects when the wrapped blob is shorter than the nonce+tag", async () => {
    const tiny = toBase64(new Uint8Array(8))
    await expect(unwrapDEK(toBase64(fixtureKEK()), tiny)).rejects.toThrow(
      /shorter than nonce\+tag/,
    )
  })

  it("throws when the KEK is malformed base64", async () => {
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    await expect(unwrapDEK("not!base64!", wrapped)).rejects.toBeDefined()
  })

  it("rejects a KEK of an invalid AES key length with an actionable error", async () => {
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    await expect(unwrapDEK(toBase64(new Uint8Array(31)), wrapped)).rejects.toThrow(
      /KEK must be 16\/24\/32 bytes/,
    )
  })

  it("accepts a 16-byte (AES-128) KEK", async () => {
    const kek = new Uint8Array(16).fill(0x11)
    const dek = fixtureDEK()
    const wrapped = await wrapDEK(kek, dek, fixtureNonce())
    expect(await unwrapDEK(toBase64(kek), wrapped)).toEqual(dek)
  })
})

// ---------- kekBase64ToBytes ----------

describe("kekBase64ToBytes", () => {
  it("decodes standard base64 with padding", () => {
    const bytes = fixtureKEK()
    expect(kekBase64ToBytes(toBase64(bytes))).toEqual(bytes)
  })

  it("decodes base64url (no padding)", () => {
    const bytes = fixtureKEK()
    const b64url = toBase64(bytes)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "")
    expect(kekBase64ToBytes(b64url)).toEqual(bytes)
  })

  it("returns an empty Uint8Array for empty input", () => {
    expect(kekBase64ToBytes("")).toEqual(new Uint8Array(0))
  })

  it("throws on non-base64 characters", () => {
    expect(() => kekBase64ToBytes("not valid!")).toThrow()
  })
})

// ---------- WebCrypto-unavailable fallback ----------

describe("unwrapDEK without WebCrypto", () => {
  it("rejects cleanly when crypto.subtle is missing", async () => {
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    const saved = globalThis.crypto
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: { ...nodeWebCrypto, subtle: undefined },
    })
    try {
      await expect(unwrapDEK(toBase64(fixtureKEK()), wrapped)).rejects.toBeDefined()
    } finally {
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: saved,
      })
    }
  })
})
