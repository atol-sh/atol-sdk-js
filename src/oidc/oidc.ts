import {
  InMemoryWebStorage,
  OidcClient,
  User,
  UserManager,
  WebStorageStateStore,
  type IdTokenClaims,
  type UserManagerSettings,
} from 'oidc-client-ts'
import { decodeJWTPayload, getTokenExpiry } from '../claims/claims'
import type { TokenResponse } from './silent-renew'
import { LoginRequiredError, OAuthProtocolError } from './token-recovery'

/** Parsed, state-validated redirect result before the token exchange. */
export interface AuthorizationCodeCallback {
  code: string
  codeVerifier: string
  redirectUri: string
  nonce: string
}

/**
 * Public oidc-client-ts protocol readers paired with each UserManager. This
 * lets the SDK consume state + PKCE through supported APIs while retaining
 * control of the DPoP-aware token exchange.
 */
const protocolClients = new WeakMap<UserManager, OidcClient>()

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

  const manager = new UserManager(settings)
  protocolClients.set(manager, new OidcClient(settings))
  return manager
}

/**
 * Consume a redirect callback without letting oidc-client-ts exchange the
 * code. The matching state is removed exactly once, then the caller performs
 * the same DPoP-aware exchange used by silent authorization.
 */
export async function readAuthorizationCodeCallback(
  manager: UserManager,
  url: string,
): Promise<AuthorizationCodeCallback> {
  const protocol = protocolClients.get(manager)
  if (!protocol) {
    throw new Error('OIDC callback reader is unavailable for this UserManager')
  }

  let parsed: Awaited<ReturnType<OidcClient['readSigninResponseState']>>
  try {
    parsed = await protocol.readSigninResponseState(url, true)
  } catch (err) {
    if (err instanceof Error) throw err
    throw new Error('OIDC callback state could not be read')
  }
  const { state, response } = parsed
  if (state.id !== response.state) {
    throw new Error('OIDC callback state mismatch')
  }
  if (state.request_type !== 'si:r') {
    throw new Error('OIDC callback has an unexpected request type')
  }
  if (state.authority !== protocol.settings.authority) {
    throw new Error('OIDC callback authority mismatch')
  }
  if (state.client_id !== protocol.settings.client_id) {
    throw new Error('OIDC callback client mismatch')
  }
  if (response.error) {
    const message = response.error_description || response.error
    if (
      response.error === 'login_required' ||
      response.error === 'consent_required' ||
      response.error === 'interaction_required' ||
      response.error === 'account_selection_required'
    ) {
      throw new LoginRequiredError(message)
    }
    throw new OAuthProtocolError(response.error, message)
  }
  if (!response.code) {
    throw new Error('OIDC callback is missing an authorization code')
  }
  if (!state.code_verifier) {
    throw new Error('OIDC callback is missing the PKCE verifier')
  }
  if (typeof state.redirect_uri !== 'string' || state.redirect_uri.length === 0) {
    throw new Error('OIDC callback is missing the redirect URI')
  }
  if (typeof state.nonce !== 'string' || state.nonce.length === 0) {
    throw new Error('OIDC callback is missing the nonce')
  }

  return {
    code: response.code,
    codeVerifier: state.code_verifier,
    redirectUri: state.redirect_uri,
    nonce: state.nonce,
  }
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
