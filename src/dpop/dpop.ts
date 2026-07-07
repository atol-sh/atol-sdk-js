/**
 * DPoP (RFC 9449) client implementation.
 *
 * This module owns the per-tab ES256 keypair used for sender-constrained
 * tokens, plus the proof-JWT builder that clients send on every
 * /auth/token call (and, in future, on every resource-server request).
 *
 * Design choices:
 *   - Keys are non-exportable CryptoKey objects (`extractable: false`).
 *     XSS can use them to sign but cannot exfiltrate the private bytes.
 *   - Keys are regenerated per-tab on provider mount. A page reload ==
 *     a new keypair. The cost is one extra round-trip after reload;
 *     the benefit is no persistence surface for key material at all.
 *   - ES256 / P-256 only. Universal WebCrypto support, matches what the
 *     server's DPoP validator accepts first.
 *
 * The module is a no-op fallback when WebCrypto is unavailable (SSR,
 * extremely old browsers). Callers treat a null manager as "Bearer mode".
 */

import { bytesToBase64Url, stringToBase64Url } from "../crypto/base64url"

/** Optional per-proof inputs (RFC 9449 resource access + server nonce). */
export interface DPoPProofOptions {
  /**
   * Access token being presented. When set, the proof carries an `ath`
   * claim (base64url(SHA-256(accessToken))) binding the proof to that
   * token, as required for DPoP-authenticated resource-server requests
   * (RFC 9449 §4.3 / §7). Omit at the token endpoint.
   */
  accessToken?: string
  /**
   * Server-issued nonce (RFC 9449 §8). When the AS/RS rejects a proof
   * with `use_dpop_nonce` + a `DPoP-Nonce` header, re-sign with that
   * nonce and retry.
   */
  nonce?: string
}

export interface DPoPKeyManager {
  /** Sign a proof for a specific (method, url) pair, plus optional ath/nonce. */
  signProof(method: string, url: string, options?: DPoPProofOptions): Promise<string>
  /** Public JWK -- used by the server to compute `cnf.jkt`. */
  publicJWK(): Promise<JsonWebKey>
}

/**
 * Create a per-tab DPoP key manager. Returns null when WebCrypto is not
 * available -- the caller should fall back to Bearer mode silently.
 */
export async function createDPoPKeyManager(): Promise<DPoPKeyManager | null> {
  if (typeof crypto === "undefined" || typeof crypto.subtle === "undefined") {
    return null
  }
  let keyPair: CryptoKeyPair
  try {
    keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false, // non-exportable
      ["sign"],
    )
  } catch {
    return null
  }

  // Cache the public JWK so we serialize it once per tab. The proof
  // header's `jwk` field must be byte-for-byte stable for the server's
  // thumbprint to match across calls.
  let cachedJWK: JsonWebKey | null = null
  async function pubJWK(): Promise<JsonWebKey> {
    if (cachedJWK) return cachedJWK
    // For the proof header we need an extractable PUBLIC key -- the
    // private side stays non-exportable. WebCrypto only exports extractable
    // keys; the public key of a non-extractable pair is considered
    // exportable because it carries no secret, and browsers honor that.
    cachedJWK = (await crypto.subtle.exportKey(
      "jwk",
      keyPair.publicKey,
    )) as JsonWebKey
    // Strip private-ish fields just in case.
    delete (cachedJWK as { d?: string }).d
    return cachedJWK
  }

  return {
    async publicJWK() {
      return pubJWK()
    },
    async signProof(method: string, url: string, options?: DPoPProofOptions): Promise<string> {
      const jwk = await pubJWK()
      const header = {
        typ: "dpop+jwt",
        alg: "ES256",
        jwk,
      }
      const payload: Record<string, unknown> = {
        jti: newJTI(),
        htm: method.toUpperCase(),
        htu: canonicalizeURL(url),
        iat: Math.floor(Date.now() / 1000),
      }
      // RFC 9449 §4.3 / §7: bind the proof to the access token on
      // resource-server requests so a stolen-but-bound token cannot be
      // replayed with a different proof. Omitted at the token endpoint.
      if (options?.accessToken) {
        payload.ath = await accessTokenHash(options.accessToken)
      }
      // RFC 9449 §8: include the server-issued nonce when retrying after
      // a `use_dpop_nonce` challenge.
      if (options?.nonce) {
        payload.nonce = options.nonce
      }
      const headerB64 = stringToBase64Url(JSON.stringify(header))
      const payloadB64 = stringToBase64Url(JSON.stringify(payload))
      const signingInput = `${headerB64}.${payloadB64}`

      const sigRaw = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.privateKey,
        new TextEncoder().encode(signingInput),
      )
      // WebCrypto returns IEEE P1363 (r||s) signatures, which is what
      // JOSE ES256 expects. No re-encoding needed.
      const sigB64 = bytesToBase64Url(new Uint8Array(sigRaw))
      return `${signingInput}.${sigB64}`
    },
  }
}

/** RFC 9449 §4.2 htu canonicalization: scheme + authority + path, no query/fragment. */
function canonicalizeURL(raw: string): string {
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    // A non-canonical htu (query/fragment still attached, or a relative
    // URL) is rejected by the server. Fail loud here rather than ship a
    // malformed proof that produces a confusing 400 at the endpoint.
    throw new Error(`DPoP: cannot canonicalize htu, invalid URL: ${raw}`)
  }
  u.search = ""
  u.hash = ""
  return u.toString()
}

/** base64url(SHA-256(accessToken)) for the RFC 9449 `ath` claim. */
async function accessTokenHash(accessToken: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(accessToken),
  )
  return bytesToBase64Url(new Uint8Array(digest))
}

/** A reasonably unique jti. The server's replay cache does the enforcement. */
function newJTI(): string {
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID()
  }
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return bytesToBase64Url(bytes)
}
