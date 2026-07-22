/**
 * JWT signature verification against the IdP's JWKS.
 *
 * Used before an ID token from a callback or silent token exchange enters
 * live session state. Cross-tab messages carry no tokens.
 *
 * Verification is delegated to `jose` (RFC 7515/7517/7519). The JWKS is
 * fetched from the issuer's discovery document and cached with rotation
 * handling by `createRemoteJWKSet`.
 */

import {
  createRemoteJWKSet,
  errors,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from 'jose'
import { NetworkError } from '../oidc/token-recovery'

interface Discovered {
  /** The issuer string the IdP advertises -- matched against the `iss` claim. */
  issuer: string
  /** Cached remote JWKS resolver (handles key rotation + cooldown internally). */
  jwks: JWTVerifyGetKey
}

/**
 * Per-authority discovery cache. Keyed by the raw `authority` string the
 * provider was configured with. A rejected discovery is NOT cached so a
 * transient network failure can be retried on the next broadcast.
 */
const discoveryCache = new Map<string, Promise<Discovered>>()

function discover(authority: string): Promise<Discovered> {
  const cached = discoveryCache.get(authority)
  if (cached) return cached

  const base = authority.replace(/\/+$/, '')
  const promise = (async (): Promise<Discovered> => {
    let discoveryURL: URL
    try {
      discoveryURL = new URL(`${base}/.well-known/openid-configuration`)
    } catch {
      throw new Error('OIDC authority is not a valid absolute URL')
    }
    let res: Response
    try {
      res = await fetch(discoveryURL)
    } catch (err) {
      throw new NetworkError('OIDC discovery network error', err)
    }
    if (!res.ok) {
      throw new Error(`OIDC discovery failed: HTTP ${res.status}`)
    }
    const doc = (await res.json()) as { issuer?: string; jwks_uri?: string }
    if (typeof doc.issuer !== 'string' || doc.issuer.length === 0) {
      throw new Error('OIDC discovery document is missing issuer')
    }
    if (doc.issuer !== authority) {
      throw new Error('OIDC discovery issuer does not match configured authority')
    }
    if (typeof doc.jwks_uri !== 'string' || doc.jwks_uri.length === 0) {
      throw new Error('OIDC discovery document is missing jwks_uri')
    }
    let jwksURL: URL
    try {
      jwksURL = new URL(doc.jwks_uri)
    } catch {
      throw new Error('OIDC discovery jwks_uri is not a valid absolute URL')
    }
    const remoteJWKS = createRemoteJWKSet(jwksURL)
    const jwks: JWTVerifyGetKey = async (...args) => {
      try {
        return await remoteJWKS(...args)
      } catch (err) {
        if (err instanceof TypeError || err instanceof errors.JWKSTimeout) {
          throw new NetworkError('OIDC JWKS network error', err)
        }
        throw err
      }
    }
    return { issuer: doc.issuer, jwks }
  })().catch((err) => {
    // Do not cache failures -- allow the next call to re-discover.
    discoveryCache.delete(authority)
    throw err
  })

  discoveryCache.set(authority, promise)
  return promise
}

/**
 * Verify an ID token's signature, issuer, audience, required OIDC claims,
 * and (when supplied) callback nonce against the IdP.
 * Resolves to the verified claims, or rejects when the token is forged,
 * expired, for a different issuer/audience, or carries no `sub`.
 *
 * `audience` is the OIDC `client_id` (the publishable key ID): an ID
 * token's `aud` is always the client it was issued for.
 */
export async function verifyIdToken(
  idToken: string,
  opts: { authority: string; clientId: string; nonce?: string },
): Promise<JWTPayload> {
  const { issuer, jwks } = await discover(opts.authority)
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer,
    audience: opts.clientId,
    requiredClaims: ['sub', 'exp', 'iat'],
  })
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new Error('verifyIdToken: token carries no usable sub claim')
  }
  if (opts.nonce !== undefined && payload.nonce !== opts.nonce) {
    throw new Error('verifyIdToken: nonce mismatch')
  }
  if (payload.azp !== undefined && payload.azp !== opts.clientId) {
    throw new Error('verifyIdToken: authorized party mismatch')
  }
  if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== opts.clientId) {
    throw new Error('verifyIdToken: multiple audiences require this client as azp')
  }
  return payload
}

/**
 * Verify an Atol JWT access token before any proof-binding, subject, or
 * organization claim is trusted. The audience is the protected resource,
 * not the OIDC client id used for an ID token.
 */
export async function verifyAccessToken(
  accessToken: string,
  opts: { authority: string; audience: string },
): Promise<JWTPayload> {
  const { issuer, jwks } = await discover(opts.authority)
  const { payload, protectedHeader } = await jwtVerify(accessToken, jwks, {
    issuer,
    audience: opts.audience,
    requiredClaims: ['sub', 'exp', 'iat'],
  })
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new Error('verifyAccessToken: token carries no usable sub claim')
  }
  if (protectedHeader.typ !== 'at+jwt') {
    throw new Error('verifyAccessToken: access token type must be at+jwt')
  }
  return payload
}

/** Test-only: drop the discovery cache so a test can re-stub the IdP. */
export function _resetDiscoveryCache(): void {
  discoveryCache.clear()
}
