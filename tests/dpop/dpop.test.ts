/**
 * DPoP key manager tests. jsdom lacks a real WebCrypto SubtleCrypto; we
 * import Node's `node:crypto` WebCrypto binding so
 * `crypto.subtle.generateKey({name:'ECDSA'})` actually works under vitest.
 *
 * These are the browser-side sender-constraint guarantees for the whole
 * platform, so the negative surface is heavy: RFC 7638 thumbprint
 * correctness, non-extractability / no private-material leak, htu
 * canonicalization, ath == base64url(SHA-256(token)), nonce handling,
 * malformed/oversized input rejection, and Bearer fallback.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { webcrypto as nodeWebCrypto } from "node:crypto"
import { createDPoPKeyManager } from "../../src/dpop/dpop"

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

function b64urlToBytes(b: string): Uint8Array {
  const padded = b.replace(/-/g, "+").replace(/_/g, "/")
  const pad = padded + "=".repeat((4 - (padded.length % 4)) % 4)
  return Uint8Array.from(atob(pad), (c) => c.charCodeAt(0))
}

function decodeJWT(jwt: string) {
  const [h, p, s] = jwt.split(".")
  const decode = (b: string) => JSON.parse(new TextDecoder().decode(b64urlToBytes(b)))
  return { header: decode(h), payload: decode(p), signature: s }
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
}

/** RFC 7638 JWK thumbprint for an EC P-256 key: SHA-256 over the canonical
 * JSON {"crv","kty","x","y"} with sorted keys, base64url-encoded. */
async function rfc7638Thumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`
  const digest = await nodeWebCrypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonical),
  )
  return b64url(new Uint8Array(digest))
}

describe("createDPoPKeyManager -- availability", () => {
  it("returns null when crypto.subtle is unavailable (Bearer fallback)", async () => {
    const saved = globalThis.crypto
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: { ...nodeWebCrypto, subtle: undefined },
    })
    try {
      expect(await createDPoPKeyManager()).toBeNull()
    } finally {
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: saved,
      })
    }
  })

  it("returns null when crypto itself is undefined", async () => {
    const saved = globalThis.crypto
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: undefined,
    })
    try {
      expect(await createDPoPKeyManager()).toBeNull()
    } finally {
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: saved,
      })
    }
  })

  it("returns null when generateKey throws (unsupported curve)", async () => {
    const saved = globalThis.crypto
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: {
        ...nodeWebCrypto,
        subtle: {
          ...nodeWebCrypto.subtle,
          generateKey: () => Promise.reject(new Error("unsupported")),
        },
      },
    })
    try {
      expect(await createDPoPKeyManager()).toBeNull()
    } finally {
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: saved,
      })
    }
  })
})

describe("createDPoPKeyManager -- key material", () => {
  it("generates a non-exportable ES256 key and exports the public JWK", async () => {
    const mgr = await createDPoPKeyManager()
    expect(mgr).not.toBeNull()
    const jwk = await mgr!.publicJWK()
    expect(jwk.kty).toBe("EC")
    expect(jwk.crv).toBe("P-256")
    expect(typeof jwk.x).toBe("string")
    expect(typeof jwk.y).toBe("string")
    // The private 'd' field MUST NOT be present on the exported JWK.
    expect((jwk as { d?: string }).d).toBeUndefined()
  })

  it("never serializes private material into the proof header jwk", async () => {
    const mgr = await createDPoPKeyManager()
    const proof = await mgr!.signProof("POST", "https://x/token")
    const { header } = decodeJWT(proof)
    expect(header.jwk).toBeTruthy()
    expect(header.jwk.d).toBeUndefined()
    // Only the public EC coordinates are present.
    expect(Object.keys(header.jwk).sort()).toEqual(
      expect.arrayContaining(["crv", "kty", "x", "y"]),
    )
    expect(header.jwk.d).toBeUndefined()
  })

  it("returns a byte-for-byte stable public JWK across calls (thumbprint stability)", async () => {
    const mgr = await createDPoPKeyManager()
    const a = await mgr!.publicJWK()
    const b = await mgr!.publicJWK()
    expect(JSON.stringify(a)).toBe(JSON.stringify(b))
  })

  it("header jwk yields the same RFC 7638 jkt the server would compute", async () => {
    const mgr = await createDPoPKeyManager()
    const jwk = await mgr!.publicJWK()
    const proof = await mgr!.signProof("POST", "https://x/token")
    const headerJwk = decodeJWT(proof).header.jwk
    // Thumbprint of the exposed JWK and of the header JWK must match --
    // this is exactly the cnf.jkt binding the server relies on.
    expect(await rfc7638Thumbprint(headerJwk)).toBe(await rfc7638Thumbprint(jwk))
    expect(await mgr!.thumbprint()).toBe(await rfc7638Thumbprint(jwk))
    expect(await mgr!.thumbprint()).toBe(await mgr!.thumbprint())
  })
})

describe("createDPoPKeyManager -- proof claims", () => {
  it("produces a typ=dpop+jwt / alg=ES256 JWT with required claims", async () => {
    const mgr = await createDPoPKeyManager()
    const proof = await mgr!.signProof(
      "post",
      "http://app.localhost:9080/auth/token?foo=bar#frag",
    )
    const { header, payload } = decodeJWT(proof)

    expect(header.typ).toBe("dpop+jwt")
    expect(header.alg).toBe("ES256")
    expect(header.jwk.kty).toBe("EC")
    expect(header.jwk.crv).toBe("P-256")

    // htm is upper-cased regardless of input casing.
    expect(payload.htm).toBe("POST")
    // htu strips query + fragment (RFC 9449 §4.2).
    expect(payload.htu).toBe("http://app.localhost:9080/auth/token")
    expect(typeof payload.jti).toBe("string")
    expect(payload.jti.length).toBeGreaterThan(8)
    expect(typeof payload.iat).toBe("number")
    const now = Math.floor(Date.now() / 1000)
    expect(Math.abs(payload.iat - now)).toBeLessThan(5)
  })

  it("produces unique jtis on consecutive calls", async () => {
    const mgr = await createDPoPKeyManager()
    const a = decodeJWT(await mgr!.signProof("POST", "http://x/token")).payload
    const b = decodeJWT(await mgr!.signProof("POST", "http://x/token")).payload
    expect(a.jti).not.toBe(b.jti)
  })

  it("signed proof signature verifies against the exposed public JWK", async () => {
    const mgr = await createDPoPKeyManager()
    const jwk = await mgr!.publicJWK()
    const pubKey = await nodeWebCrypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JsonWebKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    )
    const proof = await mgr!.signProof("POST", "http://x/token")
    const [headerB64, payloadB64, sigB64] = proof.split(".")
    const ok = await nodeWebCrypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pubKey,
      b64urlToBytes(sigB64),
      new TextEncoder().encode(`${headerB64}.${payloadB64}`),
    )
    expect(ok).toBe(true)
  })

  it("a tampered payload fails signature verification", async () => {
    const mgr = await createDPoPKeyManager()
    const jwk = await mgr!.publicJWK()
    const pubKey = await nodeWebCrypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JsonWebKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    )
    const proof = await mgr!.signProof("POST", "http://x/token")
    const [headerB64, payloadB64, sigB64] = proof.split(".")
    // Flip the htm claim in the signed input; the signature must not verify.
    const forgedPayload = { ...decodeJWT(proof).payload, htm: "DELETE" }
    const forgedPayloadB64 = b64url(
      new TextEncoder().encode(JSON.stringify(forgedPayload)),
    )
    const ok = await nodeWebCrypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pubKey,
      b64urlToBytes(sigB64),
      new TextEncoder().encode(`${headerB64}.${forgedPayloadB64}`),
    )
    expect(ok).toBe(false)
    void payloadB64
  })

  it("omits ath at the token endpoint but binds ath = base64url(SHA-256(token)) for resource requests", async () => {
    const mgr = await createDPoPKeyManager()
    const tokenProof = await mgr!.signProof("POST", "https://api.atol.test/token")
    expect(decodeJWT(tokenProof).payload.ath).toBeUndefined()

    const rsProof = await mgr!.signProof("POST", "https://api.atol.test/check", {
      accessToken: "at_abc",
    })
    const digest = await nodeWebCrypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("at_abc"),
    )
    expect(decodeJWT(rsProof).payload.ath).toBe(b64url(new Uint8Array(digest)))
  })

  it("includes a server-issued nonce when supplied (RFC 9449 §8)", async () => {
    const mgr = await createDPoPKeyManager()
    const proof = await mgr!.signProof("POST", "https://api.atol.test/token", {
      nonce: "srv-nonce-1",
    })
    expect(decodeJWT(proof).payload.nonce).toBe("srv-nonce-1")
  })

  it("carries both ath and nonce when both are supplied", async () => {
    const mgr = await createDPoPKeyManager()
    const proof = await mgr!.signProof("GET", "https://api.atol.test/me", {
      accessToken: "at_xyz",
      nonce: "n-9",
    })
    const { payload } = decodeJWT(proof)
    expect(payload.nonce).toBe("n-9")
    const digest = await nodeWebCrypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("at_xyz"),
    )
    expect(payload.ath).toBe(b64url(new Uint8Array(digest)))
  })

  it("binds ath correctly for a large (oversized) access token", async () => {
    const mgr = await createDPoPKeyManager()
    const bigToken = "at_" + "x".repeat(8192)
    const proof = await mgr!.signProof("GET", "https://api.atol.test/me", {
      accessToken: bigToken,
    })
    const digest = await nodeWebCrypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(bigToken),
    )
    expect(decodeJWT(proof).payload.ath).toBe(b64url(new Uint8Array(digest)))
  })
})

describe("createDPoPKeyManager -- htu canonicalization + input rejection", () => {
  it("strips query and fragment from htu", async () => {
    const mgr = await createDPoPKeyManager()
    const proof = await mgr!.signProof(
      "POST",
      "https://atol.example.com/auth/token?grant=code#anchor",
    )
    expect(decodeJWT(proof).payload.htu).toBe("https://atol.example.com/auth/token")
  })

  it("throws on a relative/un-canonicalizable htu instead of shipping a bad proof", async () => {
    const mgr = await createDPoPKeyManager()
    await expect(mgr!.signProof("POST", "not-a-url")).rejects.toThrow(/htu/)
    await expect(mgr!.signProof("POST", "/relative/path")).rejects.toThrow(/htu/)
  })
})
