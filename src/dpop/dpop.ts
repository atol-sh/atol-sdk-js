/**
 * DPoP (RFC 9449) client implementation.
 *
 * This module owns the per-tab ES256 keypair used for sender-constrained
 * tokens, plus the proof-JWT builder used for token-endpoint and protected
 * resource requests.
 *
 * Design choices:
 *   - Keys are non-exportable CryptoKey objects (`extractable: false`).
 *     XSS can use them to sign but cannot exfiltrate the private bytes.
 *   - Every authorization gets a new key. A full redirect stages only its
 *     opaque CryptoKey handles in IndexedDB until the matching callback
 *     consumes them; iframe grants keep the key in memory.
 *   - ES256 / P-256 only. Universal WebCrypto support, matches what the
 *     server's DPoP validator accepts first.
 *
 * The module is a no-op fallback when WebCrypto is unavailable (SSR,
 * extremely old browsers). Callers treat a null manager as "Bearer mode".
 */

import { bytesToBase64Url, stringToBase64Url } from "../crypto/base64url"
import { calculateJwkThumbprint, type JWK } from "jose"

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
  /** RFC 7638 SHA-256 thumbprint expected in a bound token's `cnf.jkt`. */
  thumbprint(): Promise<string>
}

const managerKeys = new WeakMap<DPoPKeyManager, CryptoKeyPair>()
const P256_COORDINATE = /^[A-Za-z0-9_-]{43}$/

function canonicalPublicJWK(exported: JsonWebKey): JsonWebKey {
  if (
    exported.kty !== "EC" ||
    exported.crv !== "P-256" ||
    typeof exported.x !== "string" ||
    !P256_COORDINATE.test(exported.x) ||
    typeof exported.y !== "string" ||
    !P256_COORDINATE.test(exported.y) ||
    typeof exported.d === "string"
  ) {
    throw new Error("DPoP: exported public key is invalid")
  }
  return {
    crv: "P-256",
    kty: "EC",
    x: exported.x,
    y: exported.y,
  }
}

function validP256KeyPair(keyPair: CryptoKeyPair): boolean {
  const privateAlgorithm = keyPair.privateKey.algorithm as EcKeyAlgorithm
  const publicAlgorithm = keyPair.publicKey.algorithm as EcKeyAlgorithm
  return (
    keyPair.privateKey.type === "private" &&
    keyPair.privateKey.extractable === false &&
    keyPair.privateKey.usages.length === 1 &&
    keyPair.privateKey.usages[0] === "sign" &&
    privateAlgorithm.name === "ECDSA" &&
    privateAlgorithm.namedCurve === "P-256" &&
    keyPair.publicKey.type === "public" &&
    publicAlgorithm.name === "ECDSA" &&
    publicAlgorithm.namedCurve === "P-256"
  )
}

/**
 * Rebuild a manager around a structured-cloned, non-exportable key pair.
 *
 * This is package-internal authorization-navigation plumbing. It is not
 * exported from the package root: callers should never receive raw private
 * key handles.
 */
export function restoreDPoPKeyManager(keyPair: CryptoKeyPair): DPoPKeyManager {
  if (!validP256KeyPair(keyPair)) {
    throw new Error("DPoP: stored authorization key is invalid")
  }

  // Cache only the canonical public members. WebCrypto exports metadata such
  // as `key_ops: []` for a signing-only key pair; that metadata is not part of
  // the public verification key and must not enter a DPoP proof header.
  let cachedJWK: JsonWebKey | null = null
  let cachedThumbprint: string | null = null
  async function pubJWK(): Promise<JsonWebKey> {
    if (!cachedJWK) {
      cachedJWK = canonicalPublicJWK(
        (await crypto.subtle.exportKey(
          "jwk",
          keyPair.publicKey,
        )) as JsonWebKey,
      )
    }
    return { ...cachedJWK }
  }

  const manager: DPoPKeyManager = {
    async publicJWK() {
      return pubJWK()
    },
    async thumbprint() {
      if (!cachedThumbprint) {
        cachedThumbprint = await calculateJwkThumbprint(
          (await pubJWK()) as JWK,
          "sha256",
        )
      }
      return cachedThumbprint
    },
    async signProof(
      method: string,
      url: string,
      options?: DPoPProofOptions,
    ): Promise<string> {
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
      if (options?.accessToken) {
        payload.ath = await accessTokenHash(options.accessToken)
      }
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
      const sigB64 = bytesToBase64Url(new Uint8Array(sigRaw))
      return `${signingInput}.${sigB64}`
    },
  }
  managerKeys.set(manager, keyPair)
  return manager
}

/** Return the opaque key handles for package-internal navigation storage. */
export function dpopKeyPair(manager: DPoPKeyManager): CryptoKeyPair {
  const keyPair = managerKeys.get(manager)
  if (!keyPair) {
    throw new Error("DPoP: key manager was not created by this SDK")
  }
  return keyPair
}

/**
 * Create a per-tab DPoP key manager. Returns null when WebCrypto is not
 * available. The caller decides whether that means Bearer fallback or a
 * fatal error according to its public configuration.
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
  return restoreDPoPKeyManager(keyPair)
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
