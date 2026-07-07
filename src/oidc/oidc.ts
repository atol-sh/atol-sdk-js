import {
  InMemoryWebStorage,
  User,
  UserManager,
  WebStorageStateStore,
  type IdTokenClaims,
  type UserManagerSettings,
} from 'oidc-client-ts'
import { decodeJWTPayload, getTokenExpiry } from '../claims/claims'
import type { TokenResponse } from './silent-renew'

/**
 * Create an oidc-client-ts UserManager configured for Atol.
 *
 * Storage policy:
 *   - `userStore` is IN-MEMORY. The full User object (access token, ID
 *     token, and -- when `useRefreshTokens` is on -- the refresh token)
 *     never touches sessionStorage or localStorage, so an XSS payload
 *     cannot read persisted credentials after the fact. The cost is that
 *     a page reload starts with an empty store; the provider recovers by
 *     attempting a silent renew against the IdP session cookie.
 *   - `stateStore` stays in sessionStorage. It only holds the OIDC
 *     state/PKCE verifier, which must survive the same-tab redirect to
 *     the Atol login page and back, and is worthless to an attacker
 *     after the code exchange completes.
 */
export function createUserManager(
  authority: string,
  clientId: string,
  redirectUri: string,
  scope: string,
  audience?: string,
): UserManager {
  // sessionStorage for PKCE state ONLY -- survives same-tab redirects to
  // the Atol login page and back. Guard for SSR: a "use client" component
  // is still rendered on the server for initial HTML, where `window` is
  // undefined. Fall back to in-memory there (the server never performs the
  // redirect dance, so the state store is unused until client hydration).
  const stateStorage =
    typeof window !== 'undefined' ? window.sessionStorage : new InMemoryWebStorage()

  const settings: UserManagerSettings = {
    authority,
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope,
    automaticSilentRenew: false,
    // In-memory only -- tokens must never persist to Web Storage.
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    stateStore: new WebStorageStateStore({ store: stateStorage }),
    extraQueryParams: audience ? { audience } : undefined,
  }

  return new UserManager(settings)
}

/** Extract the access token from an oidc-client-ts User. */
export function getAccessToken(user: User | null): string | undefined {
  return user?.access_token ?? undefined
}

/** Extract the ID token from an oidc-client-ts User. */
export function getIdToken(user: User | null): string | undefined {
  return user?.id_token ?? undefined
}

/**
 * Build an oidc-client-ts User from a raw /auth/token response. Used to
 * write renewed tokens back into the UserManager store so `mgr.getUser()`
 * and React state never disagree (e.g. a rotated-away refresh token
 * lingering in the store).
 *
 * `expires_at` prefers the access token's own `exp` claim; falls back to
 * `expires_in` relative to now when the token is opaque.
 */
export function userFromTokenResponse(tokens: TokenResponse): User {
  const expMs = getTokenExpiry(tokens.access_token)
  const expiresAt =
    expMs !== null
      ? Math.floor(expMs / 1000)
      : Math.floor(Date.now() / 1000) + (tokens.expires_in ?? 0)

  let profile: Record<string, unknown> = {}
  if (tokens.id_token) {
    try {
      profile = decodeJWTPayload(tokens.id_token)
    } catch {
      // Malformed ID token payload -- store the tokens anyway; claims
      // parsing errors surface separately via parseAtolUser.
    }
  }

  return new User({
    access_token: tokens.access_token,
    id_token: tokens.id_token,
    refresh_token: tokens.refresh_token,
    token_type: tokens.token_type,
    scope: tokens.scope,
    expires_at: expiresAt,
    profile: profile as IdTokenClaims,
  })
}
