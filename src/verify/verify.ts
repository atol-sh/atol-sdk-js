/**
 * JWT signature verification against the IdP's JWKS.
 *
 * Used to authenticate tokens that arrive over an UNTRUSTED in-browser
 * channel -- specifically the cross-tab `BroadcastChannel` (see the
 * browser auth client). BroadcastChannel is same-origin but not
 * same-trust: any script running on the origin (a third-party widget, an
 * XSS payload) can post to a channel whose name is derivable from the
 * public `authority` + `clientId`. Without verification a follower tab
 * would adopt attacker-supplied tokens and rebuild its identity from a
 * forged ID token.
 *
 * Verification is delegated to `jose` (RFC 7515/7517/7519). The JWKS is
 * fetched from the issuer's discovery document and cached with rotation
 * handling by `createRemoteJWKSet`.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'

interface Discovered {
  /** The issuer string the IdP advertises -- matched against the `iss` claim. */
  issuer: string
  /** Cached remote JWKS resolver (handles key rotation + cooldown internally). */
  jwks: ReturnType<typeof createRemoteJWKSet>
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
    const res = await fetch(`${base}/.well-known/openid-configuration`)
    if (!res.ok) {
      throw new Error(`OIDC discovery failed: HTTP ${res.status}`)
    }
    const doc = (await res.json()) as { issuer?: string; jwks_uri?: string }
    if (!doc.jwks_uri) {
      throw new Error('OIDC discovery document is missing jwks_uri')
    }
    return {
      issuer: doc.issuer ?? base,
      jwks: createRemoteJWKSet(new URL(doc.jwks_uri)),
    }
  })().catch((err) => {
    // Do not cache failures -- allow the next call to re-discover.
    discoveryCache.delete(authority)
    throw err
  })

  discoveryCache.set(authority, promise)
  return promise
}

/**
 * Verify an ID token's signature, issuer, and audience against the IdP.
 * Resolves to the verified claims, or rejects when the token is forged,
 * expired, for a different issuer/audience, or carries no `sub`.
 *
 * `audience` is the OIDC `client_id` (the publishable key ID): an ID
 * token's `aud` is always the client it was issued for.
 */
export async function verifyIdToken(
  idToken: string,
  opts: { authority: string; clientId: string },
): Promise<JWTPayload> {
  const { issuer, jwks } = await discover(opts.authority)
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer,
    audience: opts.clientId,
    requiredClaims: ['sub'],
  })
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new Error('verifyIdToken: token carries no usable sub claim')
  }
  return payload
}

/** Test-only: drop the discovery cache so a test can re-stub the IdP. */
export function _resetDiscoveryCache(): void {
  discoveryCache.clear()
}
