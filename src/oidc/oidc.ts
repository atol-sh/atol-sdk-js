import {
  InMemoryWebStorage,
  OidcClient,
  User,
  UserManager,
  WebStorageStateStore,
  type CreateSigninRequestArgs,
  type IdTokenClaims,
  type OidcMetadata,
  type UserManagerSettings,
} from 'oidc-client-ts'
import { decodeJWTPayload, getTokenExpiry } from '../claims/claims'
import type { TokenResponse } from './silent-renew'
import { LoginRequiredError, OAuthProtocolError } from './token-recovery'
import { normalizeSameOriginReturnTo } from './return-to'
import {
  isCredentialGeneration,
  type CredentialGenerationSnapshot,
} from './credential-generation'

/** Parsed, state-validated redirect result before the token exchange. */
export interface AuthorizationCodeCallback {
  code: string
  codeVerifier: string
  redirectUri: string
  nonce: string
  returnTo?: string
  credentialGeneration?: CredentialGenerationSnapshot
}

/**
 * The supported oidc-client-ts transaction produced before ordinary PAR
 * transport. `stateStorage` is the exact state/nonce/PKCE record already
 * persisted by oidc-client-ts.
 */
export interface CreatedAuthorizationRequest {
  authorizationURL: string
  stateId: string
  stateStorage: string
  stateCreatedAt: number
  codeVerifier: string
  codeChallenge: string
  nonce: string
  metadata: Partial<OidcMetadata>
}

/**
 * A non-consuming oidc-client-ts response-state read before OAuth response
 * handling. The browser client validates and claims the matching admitted
 * IndexedDB custody before it settles either storage surface.
 */
export interface AuthorizationCodeResponseState {
  stateId: string
  stateStorage: string
  stateCreatedAt: number
  codeVerifier: string
  codeChallenge: string
  redirectUri: string
  nonce: string
  code?: string
  error?: {
    code: string
  }
  returnTo?: string
  credentialGeneration?: CredentialGenerationSnapshot
}

const ATOL_AUTHORIZATION_STATE = 'atol_browser_auth'
const RETURN_TO_AUTHORIZATION_STATE = 'return_to'
const LOGOUT_GENERATION_STATE = 'logout_generation'
const TAB_OWNER_GENERATION_STATE = 'tab_owner_generation'
const AUTHORIZATION_STATE_VERSION = 1

/** Build transaction-bound application state that never changes redirect_uri. */
export function authorizationState(
  returnTo?: string,
  credentialGeneration?: CredentialGenerationSnapshot,
): Record<string, unknown> {
  if (!returnTo && !credentialGeneration) return {}
  const value: Record<string, unknown> = {
    version: AUTHORIZATION_STATE_VERSION,
  }
  if (returnTo) value[RETURN_TO_AUTHORIZATION_STATE] = returnTo
  if (credentialGeneration) {
    value[LOGOUT_GENERATION_STATE] = credentialGeneration.logout
    value[TAB_OWNER_GENERATION_STATE] = credentialGeneration.tabOwner
  }
  return { [ATOL_AUTHORIZATION_STATE]: value }
}

function parseAuthorizationState(
  value: unknown,
  redirectUri: string,
): {
  returnTo?: string
  credentialGeneration?: CredentialGenerationSnapshot
} {
  if (value === undefined) return {}
  // oidc-client-ts exposes arbitrary application state through this field.
  // Only the versioned SDK namespace belongs to us; unrelated consumer state
  // must remain compatible with the public low-level callback reader.
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  const outer = value as Record<string, unknown>
  if (!Object.prototype.hasOwnProperty.call(outer, ATOL_AUTHORIZATION_STATE)) {
    return {}
  }
  const rawAtolState = outer[ATOL_AUTHORIZATION_STATE]
  if (
    !rawAtolState ||
    typeof rawAtolState !== 'object' ||
    Array.isArray(rawAtolState)
  ) {
    throw new Error('OIDC callback has invalid Atol custom state')
  }
  const atolState = rawAtolState as Record<string, unknown>
  const keys = Object.keys(atolState)
  if (
    atolState.version !== AUTHORIZATION_STATE_VERSION ||
    keys.length < 1 ||
    keys.length > 4 ||
    keys.some(
      (key) =>
        key !== 'version' &&
        key !== RETURN_TO_AUTHORIZATION_STATE &&
        key !== LOGOUT_GENERATION_STATE &&
        key !== TAB_OWNER_GENERATION_STATE,
    )
  ) {
    throw new Error('OIDC callback has unexpected Atol custom state')
  }
  let returnTo: string | undefined
  if (Object.prototype.hasOwnProperty.call(atolState, RETURN_TO_AUTHORIZATION_STATE)) {
    const raw = atolState[RETURN_TO_AUTHORIZATION_STATE]
    if (typeof raw !== 'string') {
      throw new Error('OIDC callback has invalid returnTo state')
    }
    returnTo = normalizeSameOriginReturnTo(raw, redirectUri)
    if (returnTo !== raw) {
      throw new Error('OIDC callback has non-canonical returnTo state')
    }
  }
  const hasLogoutGeneration = Object.prototype.hasOwnProperty.call(
    atolState,
    LOGOUT_GENERATION_STATE,
  )
  const hasTabOwnerGeneration = Object.prototype.hasOwnProperty.call(
    atolState,
    TAB_OWNER_GENERATION_STATE,
  )
  if (hasLogoutGeneration !== hasTabOwnerGeneration) {
    throw new Error('OIDC callback has an incomplete credential generation')
  }
  let credentialGeneration: CredentialGenerationSnapshot | undefined
  if (hasLogoutGeneration) {
    const logout = atolState[LOGOUT_GENERATION_STATE]
    const tabOwner = atolState[TAB_OWNER_GENERATION_STATE]
    if (
      !isCredentialGeneration(logout) ||
      !isCredentialGeneration(tabOwner)
    ) {
      throw new Error('OIDC callback has an invalid credential generation')
    }
    credentialGeneration = { logout, tabOwner }
  }
  return {
    returnTo,
    credentialGeneration,
  }
}

/**
 * Public oidc-client-ts protocol readers paired with each UserManager. This
 * lets the SDK consume state + PKCE through supported APIs while retaining
 * control of the DPoP-aware token exchange.
 */
const protocolClients = new WeakMap<UserManager, OidcClient>()

function protocolClient(manager: UserManager): OidcClient {
  const protocol = protocolClients.get(manager)
  if (!protocol) {
    throw new Error('OIDC protocol client is unavailable for this UserManager')
  }
  return protocol
}

/**
 * Ask oidc-client-ts to generate and persist the protocol state, nonce, and
 * PKCE verifier through its supported API. The caller owns PAR transport and
 * browser navigation after it has durably staged the returned exact state.
 */
export async function createAuthorizationRequest(
  manager: UserManager,
  args: Omit<CreateSigninRequestArgs, 'response_mode'> & {
    response_mode?: CreateSigninRequestArgs['response_mode'] | 'web_message'
  },
): Promise<CreatedAuthorizationRequest> {
  const protocol = protocolClient(manager)
  const request = await protocol.createSigninRequest(
    args as CreateSigninRequestArgs,
  )
  const state = request.state
  try {
    if (
      typeof state.id !== 'string' ||
      state.id.length === 0 ||
      typeof state.created !== 'number' ||
      !Number.isSafeInteger(state.created) ||
      state.created < 0 ||
      typeof state.code_verifier !== 'string' ||
      state.code_verifier.length === 0 ||
      typeof state.code_challenge !== 'string' ||
      state.code_challenge.length === 0 ||
      typeof state.nonce !== 'string' ||
      state.nonce.length === 0
    ) {
      throw new Error('OIDC authorization request state is incomplete')
    }
    return {
      authorizationURL: request.url,
      stateId: state.id,
      stateStorage: state.toStorageString(),
      stateCreatedAt: state.created,
      codeVerifier: state.code_verifier,
      codeChallenge: state.code_challenge,
      nonce: state.nonce,
      metadata: await protocol.metadataService.getMetadata(),
    }
  } catch (error) {
    await removeAuthorizationRequestState(
      manager,
      state.id,
      state.toStorageString(),
    )
    throw error
  }
}

/**
 * Ensure an ambiguous PAR retry still has the exact oidc-client-ts state it
 * originally persisted. A missing entry is restored from IndexedDB custody;
 * a different entry is never overwritten.
 */
export async function ensureAuthorizationRequestState(
  manager: UserManager,
  stateId: string,
  stateStorage: string,
): Promise<void> {
  const store = protocolClient(manager).settings.stateStore
  const current = await store.get(stateId)
  if (current === null) {
    await store.set(stateId, stateStorage)
    return
  }
  if (current !== stateStorage) {
    throw new Error('OIDC authorization state storage mismatch')
  }
}

/**
 * Remove one exact oidc-client-ts state after definitive local settlement.
 * A missing value is an idempotent success; a substituted value is never
 * removed.
 */
export async function removeAuthorizationRequestState(
  manager: UserManager,
  stateId: string,
  expectedStorage: string,
): Promise<void> {
  const store = protocolClient(manager).settings.stateStore
  const current = await store.get(stateId)
  if (current === null) return
  if (current !== expectedStorage) {
    throw new Error('OIDC authorization state storage mismatch')
  }
  await store.remove(stateId)
  if ((await store.get(stateId)) !== null) {
    throw new Error('OIDC authorization state removal failed')
  }
}

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
 * Read a redirect callback without letting oidc-client-ts exchange the code.
 * The matching state remains present until the caller definitively settles
 * its code exchange.
 */
export async function readAuthorizationCodeCallback(
  manager: UserManager,
  url: string,
): Promise<AuthorizationCodeCallback> {
  return requireAuthorizationCodeCallback(
    await readAuthorizationCodeResponseState(manager, url),
  )
}

export async function readAuthorizationCodeResponseState(
  manager: UserManager,
  url: string,
): Promise<AuthorizationCodeResponseState> {
  const protocol = protocolClient(manager)
  let parsed: Awaited<ReturnType<OidcClient['readSigninResponseState']>>
  try {
    parsed = await protocol.readSigninResponseState(url, false)
  } catch {
    throw new Error('OIDC callback response could not be read')
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
  if (!state.code_verifier) {
    throw new Error('OIDC callback is missing the PKCE verifier')
  }
  if (!state.code_challenge) {
    throw new Error('OIDC callback is missing the PKCE challenge')
  }
  if (typeof state.redirect_uri !== 'string' || state.redirect_uri.length === 0) {
    throw new Error('OIDC callback is missing the redirect URI')
  }
  if (typeof state.nonce !== 'string' || state.nonce.length === 0) {
    throw new Error('OIDC callback is missing the nonce')
  }
  const clientState = parseAuthorizationState(state.data, state.redirect_uri)

  return {
    stateId: state.id,
    stateStorage: state.toStorageString(),
    stateCreatedAt: state.created,
    codeVerifier: state.code_verifier,
    codeChallenge: state.code_challenge,
    redirectUri: state.redirect_uri,
    nonce: state.nonce,
    ...(response.code ? { code: response.code } : {}),
    ...(response.error
      ? {
          error: {
            code: response.error,
          },
        }
      : {}),
    ...clientState,
  }
}

export function requireAuthorizationCodeCallback(
  state: AuthorizationCodeResponseState,
): AuthorizationCodeCallback {
  if (state.error) {
    if (
      state.error.code === 'login_required' ||
      state.error.code === 'consent_required' ||
      state.error.code === 'interaction_required' ||
      state.error.code === 'account_selection_required'
    ) {
      throw new LoginRequiredError()
    }
    throw new OAuthProtocolError(state.error.code)
  }
  if (!state.code) {
    throw new Error('OIDC callback is missing an authorization code')
  }
  return {
    code: state.code,
    codeVerifier: state.codeVerifier,
    redirectUri: state.redirectUri,
    nonce: state.nonce,
    returnTo: state.returnTo,
    credentialGeneration: state.credentialGeneration,
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
