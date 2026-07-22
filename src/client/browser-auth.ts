/**
 * createAtolBrowserAuth: the config-driven browser auth client.
 *
 * This is the keystone of @atol-sh/js. It wraps oidc-client-ts with the
 * proven Atol logic that previously lived only inside the React provider:
 * PKCE authorization-code login, in-memory token storage, DPoP-aware token
 * access, proactive + on-demand silent renewal with single-flight
 * coordination, signal-only cross-tab invalidation, organization-scoped
 * credential transactions, and RP-initiated logout with refresh-token
 * revocation.
 *
 * Framework bindings (React, Vue, ...) become thin wrappers over this: they
 * subscribe with `onSessionChange` and render, delegating every credential
 * decision here.
 *
 * Storage policy: tokens are MEMORY-ONLY. The oidc-client-ts user store is
 * `InMemoryWebStorage`; sessionStorage holds only the OIDC state/PKCE
 * verifier needed to survive the login redirect. A page reload starts with
 * an empty store, and the client recovers via a silent renew against the
 * IdP session cookie.
 */

import type { User, UserManager } from 'oidc-client-ts'
import {
  createUserManager,
  getAccessToken,
  getIdToken,
  readAuthorizationCodeCallback,
  userFromTokenResponse,
} from '../oidc/oidc'
import { getTokenExpiry, parseAtolUser } from '../claims/claims'
import {
  DEFAULT_SILENT_RENEW_RETRY_COUNT,
  LoginRequiredError,
  exchangeCode,
  generateAuthorizationNonce,
  refreshTokenGrant,
  revokeToken,
  silentAuthorizeWithRetry,
  type TokenResponse,
} from '../oidc/silent-renew'
import {
  RecoveryAction,
  backoffDelay,
  classifyRenewalError,
} from '../oidc/token-recovery'
import {
  createTokenBroadcast,
  type BroadcastMessage,
  type TokenBroadcast,
} from '../token/token-broadcast'
import { createDPoPKeyManager, type DPoPKeyManager } from '../dpop/dpop'
import { verifyAccessToken, verifyIdToken } from '../verify/verify'
import { decodeJWTPayload } from '../claims/claims'
import { KEKVault } from '../crypto/kek-vault'
import { extractKEKFromFragment, kekBase64ToBytes } from '../crypto/encryption'
import type { AtolUser, DPoPProofResult } from '../claims/types'

/** DPoP configuration: a boolean toggle or an object with `required`. */
export type DPoPConfig = boolean | { required?: boolean }

/** Configuration for {@link createAtolBrowserAuth}. */
export interface AtolBrowserAuthConfig {
  /** OIDC issuer URL (e.g. https://auth.atol.sh). */
  issuer: string
  /** Publishable OIDC client id / key id (atol_kid_...). Safe for the browser. */
  clientId: string
  /** API audience identifier. Optional. */
  audience?: string
  /** OIDC scopes. Default: "openid profile email". */
  scopes?: string
  /** URL to redirect to after login (and after logout). */
  redirectUri: string
  /**
   * Request DPoP-bound tokens (RFC 9449). `true` (or `{ required: true }`)
   * generates a per-tab non-exportable ES256 keypair on init and attaches a
   * proof to every token-endpoint call. `{ required: true }` also makes key
   * creation failure fatal; boolean `true` retains a Bearer fallback where
   * WebCrypto is unavailable. `false` (default) uses Bearer.
   */
  dpop?: DPoPConfig
  /**
   * Silent renewal strategy. Default (false): hidden-iframe silent
   * authentication against the IdP session cookie (prompt=none) - no
   * refresh token is requested or stored. The iframe path
   * relies on the IdP session cookie being sent from a third-party context,
   * which Safari ITP blocks and Chrome's third-party-cookie phase-out
   * removes, so it fails UNCONDITIONALLY for a cross-site app (one served on
   * a different registrable domain than the IdP). Cross-site apps MUST set
   * this true: it requests offline_access and renews via the refresh-token
   * grant (memory-only, rotated, DPoP-bound when dpop is on). Same-site apps
   * (e.g. an admin console on a subdomain of the IdP) reach the first-party
   * session cookie in the iframe and leave this false.
   */
  useRefreshTokens?: boolean
  /**
   * When useRefreshTokens is true, fall back to the hidden-iframe silent
   * authentication if a refresh-token grant fails transiently (network /
   * transient server error), instead of only backing off. No effect when
   * useRefreshTokens is false (iframe is already the path).
   */
  useRefreshTokensFallback?: boolean
  /**
   * Request the zero-knowledge encryption-key claim. When true, the client
   * appends `derive_encryption_key=true` to the login authorize request and
   * to every silent (iframe) renew, so the issuer emits the
   * `atol:wrapped_dek` claim on the ID token consistently across the
   * session. The client itself does no crypto with the claim; a framework
   * binding reads it from {@link AtolBrowserAuth.getIdToken} and derives the
   * data-encryption key. Defaults to false.
   */
  deriveEncryptionKey?: boolean
  /**
   * Token storage backend. Only `'memory'` is supported: tokens live in an
   * in-memory oidc-client-ts store and are never written to Web Storage.
   * Accepted as a config knob for forward-compat and to make the guarantee
   * explicit at the call site.
   */
  storage?: 'memory'
  /**
   * TEST ONLY. Enable {@link AtolBrowserAuth.seedTestSession}, which
   * establishes an authenticated session directly from a token response --
   * WITHOUT an OIDC redirect/callback, and without signature, state, nonce,
   * or DPoP-binding validation. Defaults to `false`; while `false`,
   * `seedTestSession` throws.
   *
   * This exists so browser end-to-end tests (Cypress, Playwright) can
   * bootstrap a logged-in session against the in-memory token store without a
   * live IdP round-trip -- the reason the old `sessionStorage` priming trick
   * stopped working once tokens moved in-memory. Skipping the OIDC checks is
   * safe ONLY because it is test-only and your API still validates the
   * presented token server-side; it must NEVER be enabled in a production
   * build, or an XSS payload could mint a session. The whole point of
   * in-memory storage is that persisted tokens are unreadable after an XSS,
   * and this flag must not reopen that surface. When enabled, the client logs
   * a one-time `console.warn` at construction as a guard against accidental
   * production enablement.
   */
  allowTestSessions?: boolean
  /**
   * TEST ONLY. A token response to adopt during {@link AtolBrowserAuth.init}
   * INSTEAD of the cold-load silent-renew restore. Requires
   * `allowTestSessions: true` (ignored otherwise). When set, `init()` skips the
   * redirect-callback and hidden-iframe restore paths entirely and settles
   * AUTHENTICATED from these tokens, deterministically -- so a browser e2e test
   * lands on a logged-in app at first paint with no IdP round-trip and no
   * restore iframe. That matters against a stubbed backend with no IdP at the
   * `issuer`, where the restore iframe would otherwise never receive a
   * `web_message` and block until it times out. Equivalent to calling
   * {@link AtolBrowserAuth.seedTestSession} the instant the client is ready,
   * but race-free because it happens inside `init()` before any restore.
   * Provide a token whose `exp` is in the future. Never set in production.
   */
  initialTestSession?: TokenResponse
}

/** The current auth session, delivered to `onSessionChange` subscribers. */
export interface AtolSession {
  /** Whether a user is currently authenticated. */
  isAuthenticated: boolean
  /** The authenticated user, or null. */
  user: AtolUser | null
  /** Organization to which the current credential pair is scoped. */
  organizationId?: string
  /**
   * The unwrapped zero-knowledge data-encryption key (DEK), when
   * `deriveEncryptionKey` is enabled and the KEK/wrapped-DEK derivation
   * succeeded for the current session. `undefined` when the feature is off,
   * when there is no session, or when derivation failed (see
   * {@link AtolSession.encryptionError}). Framework bindings consume this
   * instead of re-deriving the key themselves.
   */
  encryptionKey?: Uint8Array
  /**
   * Non-`undefined` when `deriveEncryptionKey` is enabled but the expected
   * DEK could not be unwrapped: a wrong KEK, a tampered wrapped-DEK
   * (AES-GCM auth-tag failure), or a vault error. Surfaced so the app can
   * deny encrypted operations instead of silently treating a failure as
   * "encryption off" -- an auth-tag failure must never present as a
   * silently-wrong key. Mutually exclusive with a present
   * {@link AtolSession.encryptionKey}.
   */
  encryptionError?: Error
}

/** Options for {@link AtolBrowserAuth.getAccessToken}. */
export interface GetAccessTokenOptions {
  /**
   * When present, and DPoP is active, the returned result carries a proof
   * JWT bound (via `ath`) to the returned access token for the given
   * (method, url). When DPoP is inactive the proof is omitted.
   */
  dpop?: { method: string; url: string }
}

/** Options for {@link AtolBrowserAuth.beginLogin}. */
export interface BeginLoginOptions {
  /** Same-origin path to return to after login (overrides the redirect URI). */
  returnTo?: string
  /**
   * OIDC `prompt` value (e.g. `'login'` to force re-authentication, `'none'`
   * for silent). Sent as an authorize-request parameter.
   */
  prompt?: string
  /**
   * OIDC `max_age` (seconds): the maximum acceptable age of the End-User's
   * authentication. `0` forces a fresh login.
   */
  maxAge?: number
  /** OIDC `acr_values`: requested authentication assurance level(s). */
  acrValues?: string
}

/** Options for {@link AtolBrowserAuth.stepUp}. */
export interface StepUpOptions {
  /** Same-origin path to return to after the step-up re-authentication. */
  returnTo?: string
  /**
   * OIDC `max_age` (seconds). Defaults to `0` (force a brand-new login). Set a
   * small positive value to accept a very recent existing authentication.
   */
  maxAge?: number
  /** OIDC `acr_values`. Defaults to `'mfa'`. */
  acrValues?: string
}

/** The browser auth client returned by {@link createAtolBrowserAuth}. */
export interface AtolBrowserAuth {
  /**
   * Initialize the client: install the DPoP key (if enabled), wire the
   * cross-tab broadcast, and attempt to restore a session (handling a
   * redirect callback if the current URL is one). Idempotent; safe to call
   * once at startup. Resolves once the initial session state is settled.
   */
  init(): Promise<AtolSession>
  /**
   * Begin an authorization-code + PKCE login by redirecting the browser to
   * the Atol authorize endpoint. `returnTo` (a same-origin path) overrides
   * the post-login redirect target for this call. `prompt` / `maxAge` /
   * `acrValues` are forwarded as OIDC authorize-request parameters (used by
   * {@link AtolBrowserAuth.stepUp} to force re-authentication).
   */
  beginLogin(options?: BeginLoginOptions): Promise<void>
  /**
   * Force a step-up re-authentication: redirect to the authorize endpoint with
   * `prompt=login` + `max_age=0` (and `acr_values=mfa` by default) so the
   * issuer mints a token with a fresh `auth_time` and a completed second
   * factor. Use this when a sensitive management operation returns a
   * "step_up_required" challenge; after the redirect completes, retry the
   * operation. Overridable via {@link StepUpOptions}.
   */
  stepUp(options?: StepUpOptions): Promise<void>
  /**
   * Complete a login redirect: exchange the authorization code for tokens,
   * verify the ID token, and establish the session. Call on the redirect
   * URI page. A no-op returning the current session when the URL is not a
   * callback. `init()` calls this automatically.
   */
  completeLogin(): Promise<AtolSession>
  /**
   * Mint a new credential pair scoped to `organizationId`. This is a
   * distinct prompt=none authorization transaction, never an alias for a
   * generic renewal. The previous credential pair remains active if the
   * selection fails.
   */
  selectOrganization(organizationId: string): Promise<AtolSession>
  /**
   * Return the current access token, renewing it when it is inside the 60s
   * expiry window. With `opts.dpop` and DPoP active, also returns a bound
   * proof. Resolves to `undefined` when there is no session.
   */
  getAccessToken(
    opts?: GetAccessTokenOptions,
  ): Promise<{ token: string; proof?: string } | undefined>
  /**
   * The current raw ID token (the JWT), or `undefined` when there is no
   * session. Exposed so framework bindings can read issuer-specific ID
   * token claims the parsed {@link AtolUser} does not carry (e.g. an
   * app-specific encryption-key claim) without re-implementing token
   * storage. Read-only; the client owns renewal and rotation.
   */
  getIdToken(): string | undefined
  /**
   * The current unwrapped zero-knowledge data-encryption key (DEK), or
   * `undefined`. Only ever non-`undefined` when `deriveEncryptionKey` is
   * enabled and derivation succeeded for the active session. Framework
   * bindings read this (or the {@link AtolSession.encryptionKey} field on
   * the session-change payload) instead of re-deriving the key. The
   * returned array is the client's live buffer; do not mutate it.
   */
  getEncryptionKey(): Uint8Array | undefined
  /**
   * The last zero-knowledge key-derivation error, or `undefined`. Set when
   * `deriveEncryptionKey` is enabled but the DEK could not be unwrapped
   * (wrong KEK, tampered wrapped-DEK auth-tag failure, or vault error), so
   * the caller can fail loud rather than treat a tamper as "encryption
   * off". Cleared on the next successful derivation and on logout/destroy.
   */
  getEncryptionError(): Error | undefined
  /**
   * Sign out via OIDC RP-Initiated Logout: revoke the refresh token
   * (best-effort), clear local state, then redirect to the end_session
   * endpoint with `id_token_hint` + `post_logout_redirect_uri`.
   */
  logout(): Promise<void>
  /**
   * Force an immediate silent renew, bypassing the freshness check.
   * Resolves to the new access token, or undefined on failure.
   */
  forceRenew(): Promise<string | undefined>
  /**
   * Sign a DPoP resource-server proof (RFC 9449 §7) for a request to your
   * own protected resource. Fetches a fresh token first so `ath` binds to
   * the token actually presented. Resolves undefined when there is no
   * session; `proof` is undefined when DPoP is inactive.
   */
  signDPoPProof(method: string, url: string): Promise<DPoPProofResult | undefined>
  /** Whether DPoP is active (enabled AND WebCrypto produced a key manager). */
  isDPoPActive(): boolean
  /**
   * Subscribe to session changes (login, logout, renewal, organization
   * selection, or a cross-tab lifecycle signal). The callback fires
   * immediately with the current session, and
   * again on every subsequent change. Returns an unsubscribe function.
   */
  onSessionChange(cb: (session: AtolSession) => void): () => void
  /**
   * TEST ONLY. Establish an authenticated session directly from a raw token
   * response, bypassing the OIDC redirect/callback and all signature, state,
   * nonce, and DPoP-binding checks. Throws unless the client was created with
   * `allowTestSessions: true` (see {@link AtolBrowserAuthConfig.allowTestSessions}).
   *
   * The tokens are adopted through the same path a real login/renewal uses:
   * the user is stored in the (in-memory) token store, `getAccessToken`
   * resolves the seeded token, proactive renewal is scheduled from its
   * `exp`, and `onSessionChange` subscribers are notified -- so a framework
   * binding flips to authenticated exactly as it would after a real login.
   * Provide a token whose `exp` is in the future; an already-expired access
   * token schedules an immediate renewal the hermetic test environment
   * cannot satisfy. Never call this in production; the presented tokens are
   * still validated server-side by your API.
   */
  seedTestSession(tokens: TokenResponse): Promise<AtolSession>
  /** Tear down timers, the broadcast channel, and subscriptions. */
  destroy(): void
}

const DEFAULT_SCOPES = 'openid profile email'
/** Renew when the access token is within this window of expiry. */
const RENEW_WINDOW_MS = 60_000
const CANONICAL_ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/

function dpopEnabled(cfg: DPoPConfig | undefined): boolean {
  if (typeof cfg === 'boolean') return cfg
  return cfg?.required === true
}

function dpopRequired(cfg: DPoPConfig | undefined): boolean {
  return typeof cfg === 'object' && cfg.required === true
}

class StaleCredentialTransactionError extends Error {
  constructor() {
    super('credential transaction was superseded')
    this.name = 'StaleCredentialTransactionError'
  }
}

/**
 * Warn when a seeded test-session access token has no FUTURE `exp`. Such a
 * token schedules an immediate renewal against an issuer a hermetic test
 * cannot reach, which can flip the just-seeded session back to unauthenticated.
 * Shared by `seedTestSession` and the `initialTestSession` init path.
 */
function warnIfSeedTokenNotFresh(accessToken: string): void {
  const exp = getTokenExpiry(accessToken)
  if ((exp === null || exp <= Date.now()) && typeof console !== 'undefined') {
    console.warn(
      '[Atol] test session: the access token has no future `exp` claim; the ' +
        'seeded session may immediately attempt renewal and drop. Seed a token ' +
        'whose exp is in the future.',
    )
  }
}

/**
 * Create a framework-agnostic Atol browser auth client. See
 * {@link AtolBrowserAuthConfig} for options. Call {@link AtolBrowserAuth.init}
 * once at startup.
 */
export function createAtolBrowserAuth(config: AtolBrowserAuthConfig): AtolBrowserAuth {
  const issuer = config.issuer
  const clientId = config.clientId
  const audience = config.audience
  const redirectUri = config.redirectUri
  const useDPoP = dpopEnabled(config.dpop)
  const requireDPoP = dpopRequired(config.dpop)
  const useRefreshTokens = config.useRefreshTokens ?? false
  const useRefreshTokensFallback = config.useRefreshTokensFallback ?? false
  const deriveEncryptionKey = config.deriveEncryptionKey ?? false
  const allowTestSessions = config.allowTestSessions ?? false
  // Only honored under allowTestSessions; ignored otherwise so a stray value
  // can never establish a session in a production build.
  const initialTestSession = allowTestSessions ? config.initialTestSession : undefined

  // Loud, one-time guard: seedTestSession bypasses OIDC validation, so a
  // build that reaches this branch in production is a security defect. The
  // warning makes an accidental enablement visible in the console.
  if (allowTestSessions && typeof console !== 'undefined') {
    console.warn(
      '[Atol] allowTestSessions is ENABLED: seedTestSession can establish a ' +
        'session without OIDC validation. This is for tests only and must ' +
        'never be enabled in production.',
    )
  }

  // Renewal model: by default (useRefreshTokens=false) renewal is a
  // hidden-iframe silent authorize against the IdP session cookie
  // (prompt=none), so no refresh token is requested or stored. DPoP still
  // works in this path: the iframe code exchange sends a proof. Only when
  // useRefreshTokens=true do we append `offline_access` so the server mints
  // a refresh token and renew via the refresh-token grant.
  const requestedScopes = config.scopes ?? DEFAULT_SCOPES
  const scope =
    useRefreshTokens && !requestedScopes.split(' ').includes('offline_access')
      ? `${requestedScopes} offline_access`
      : requestedScopes

  const manager: UserManager = createUserManager(issuer, clientId, redirectUri, scope, audience)

  // Session state.
  let currentUser: AtolUser | null = null
  let currentIdToken: string | undefined
  let currentOrganizationId: string | undefined
  let accessToken: string | undefined
  let refreshToken: string | undefined

  // Zero-knowledge encryption state (only touched when deriveEncryptionKey
  // is set -- when off, these stay undefined and no crypto/vault/fragment
  // work ever runs). `encKey` is the unwrapped DEK for the active session;
  // `encError` is the last derivation failure (tamper / vault error),
  // surfaced so a binding can fail loud instead of treating it as
  // "encryption off". `fragmentKEK` is the base64 KEK captured from the URL
  // fragment on init (before the callback strips the URL) and consumed once
  // to provision the vault. `vault` is created lazily on first use.
  let encKey: Uint8Array | undefined
  let encError: Error | undefined
  let fragmentKEK: string | null = null
  let vault: KEKVault | null = null

  // DPoP + broadcast + renewal machinery.
  let dpop: DPoPKeyManager | null = null
  let broadcast: TokenBroadcast | null = null
  let renewTimer: ReturnType<typeof setTimeout> | null = null
  let renewInFlight: {
    epoch: number
    promise: Promise<string | undefined>
  } | null = null
  let renewBackoff = 0
  let restoreInFlight: Promise<SilentCredentialGrant> | null = null
  let runtimeInitPromise: Promise<void> | null = null
  let credentialEpoch = 0
  let destroyed = false

  const subscribers = new Set<(session: AtolSession) => void>()

  function session(): AtolSession {
    return {
      isAuthenticated: currentUser !== null,
      user: currentUser,
      organizationId: currentOrganizationId,
      encryptionKey: encKey,
      encryptionError: encError,
    }
  }

  function emit(): void {
    const snap = session()
    for (const cb of subscribers) {
      try {
        cb(snap)
      } catch {
        // Subscribers must not throw -- swallow to keep the notifier healthy.
      }
    }
  }

  function toUser(idToken: string | undefined): AtolUser | null {
    if (!idToken) return null
    const u = parseAtolUser(idToken)
    return u.id ? u : null
  }

  // ---- Zero-knowledge encryption-key orchestration ----
  //
  // All of the following is inert unless `deriveEncryptionKey` is set: the
  // early `if (!deriveEncryptionKey) return` guards ensure zero crypto,
  // vault, or fragment work when the option is off. The DEK derivation runs
  // on every session (login callback + every silent renew) so the key is
  // available consistently: on a fresh login-callback the KEK is still in
  // the URL fragment (captured in init before the callback strips the URL)
  // and provisions the device-bound vault; on a restore/renew there is no
  // fragment, so we rehydrate the KEK from the vault. Either way the wrapped
  // DEK rides the ID token's `atol:wrapped_dek` claim and is unwrapped
  // locally. Never log key material.

  function getVault(): KEKVault {
    return (vault ??= new KEKVault())
  }

  /** Read the base64 wrapped-DEK claim from the current ID token, if any. */
  function wrappedDEKFromIdToken(): string | undefined {
    if (!currentIdToken) return undefined
    try {
      const claim = decodeJWTPayload(currentIdToken)['atol:wrapped_dek']
      return typeof claim === 'string' && claim !== '' ? claim : undefined
    } catch {
      // A malformed ID token is not a tamper signal for the DEK path -- the
      // OIDC layer already validated the token to establish the session.
      // Treat an unreadable claim as absent (graceful: no key, no crash).
      return undefined
    }
  }

  /** Best-effort zero the current DEK buffer and drop the reference. */
  function zeroEncKey(): void {
    if (encKey) {
      for (let i = 0; i < encKey.length; i++) encKey[i] = 0
    }
    encKey = undefined
  }

  /**
   * Provision the vault from the URL-fragment KEK + the wrapped-DEK claim on
   * a fresh login-callback. A wrapped-DEK auth-tag failure is a TAMPER
   * signal, not a benign branch: surface it as encError (never a silently
   * wrong key) and clear the vault so the next explicit login re-provisions.
   */
  async function provisionDEK(kek: string): Promise<void> {
    const wrappedDEK = wrappedDEKFromIdToken()
    if (!wrappedDEK) return
    try {
      const dek = await getVault().provision(kekBase64ToBytes(kek), wrappedDEK)
      encKey = dek
      encError = undefined
    } catch (err) {
      zeroEncKey()
      encError = err instanceof Error ? err : new Error(String(err))
      await getVault().clear().catch(() => undefined)
    }
  }

  /**
   * Rehydrate the DEK from the device-bound vault on a restored/renewed
   * session (no URL fragment). A corrupted vault or KEK/DEK mismatch
   * (possible tamper) surfaces as encError and clears the vault. A missing
   * vault record (rehydrate resolves null) is a normal branch -- leave the
   * key absent without an error.
   */
  async function rehydrateDEK(): Promise<void> {
    const wrappedDEK = wrappedDEKFromIdToken()
    if (!wrappedDEK) return
    try {
      const dek = await getVault().rehydrate(wrappedDEK)
      if (dek) {
        encKey = dek
        encError = undefined
      }
    } catch (err) {
      zeroEncKey()
      encError = err instanceof Error ? err : new Error(String(err))
      await getVault().clear().catch(() => undefined)
    }
  }

  /**
   * Derive the encryption key for the current session. Provisions from the
   * one-shot fragment KEK when present (fresh callback), otherwise
   * rehydrates from the vault (restore/renew). No-op when the feature is off
   * or the key is already derived. Emits nothing itself -- the caller
   * emits after the session settles.
   */
  async function deriveEncKey(): Promise<void> {
    if (!deriveEncryptionKey) return
    if (encKey) return
    if (fragmentKEK) {
      const kek = fragmentKEK
      fragmentKEK = null
      await provisionDEK(kek)
    } else {
      await rehydrateDEK()
    }
  }

  function clearRenewTimer(): void {
    if (renewTimer) {
      clearTimeout(renewTimer)
      renewTimer = null
    }
  }

  /**
   * Schedule the proactive renew for (exp - 60s), plus a backoff term when
   * recent renews have been failing transiently. Re-armed whenever the
   * access token changes.
   */
  function scheduleRenew(): void {
    clearRenewTimer()
    if (!accessToken) return
    const exp = getTokenExpiry(accessToken)
    if (exp === null) return
    const baseDelay = Math.max(0, exp - RENEW_WINDOW_MS - Date.now())
    const delay = baseDelay + backoffDelay(renewBackoff)
    renewTimer = setTimeout(() => {
      void renewSingleFlight(false, true).catch(() => undefined)
    }, delay)
  }

  interface ApplyTokenOptions {
    /** Skip signature and proof-binding checks only for the explicit test seam. */
    testSession?: boolean
    /** Organization requested by a selectOrganization transaction. */
    expectedOrganizationId?: string
    /** Compare against expectedOrganizationId even when it is undefined. */
    enforceExpectedOrganization?: boolean
    /** Existing ID/refresh tokens may be retained only for an ordinary renewal. */
    preserveExistingTokens?: boolean
    /** Reject the commit when a newer credential transaction has started. */
    epoch?: number
    /** OIDC nonce read from the matching redirect state. */
    expectedNonce?: string
    /** Invalidate same-epoch background work at an exclusive commit. */
    advanceEpochOnCommit?: boolean
  }

  interface PreparedCredentials {
    accessToken: string
    idToken: string
    refreshToken?: string
    tokenType: string
    organizationId?: string
    user: AtolUser
  }

  interface SilentCredentialGrant {
    tokens: TokenResponse
    nonce: string
  }

  function organizationClaim(
    claims: Record<string, unknown>,
    tokenName: string,
    requireCanonical: boolean,
  ): string | undefined {
    const value = claims['atol:org_id']
    if (value === undefined) return undefined
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`${tokenName} has an invalid organization claim`)
    }
    if (requireCanonical && !CANONICAL_ULID.test(value)) {
      throw new Error(`${tokenName} organization claim is not a canonical ULID`)
    }
    return value
  }

  /**
   * Validate a complete candidate before touching live credential state.
   * Access-token proof binding is checked only on the access token; the ID
   * token is verified as OIDC identity evidence and must agree on subject
   * and organization.
   */
  async function prepareCredentials(
    tokens: TokenResponse,
    options: ApplyTokenOptions,
  ): Promise<PreparedCredentials> {
    let accessClaims: Record<string, unknown>
    if (options.testSession) {
      try {
        accessClaims = decodeJWTPayload(tokens.access_token)
      } catch {
        throw new Error('token response contains an invalid access token')
      }
    } else {
      accessClaims = (await verifyAccessToken(tokens.access_token, {
        authority: issuer,
        audience: audience ?? issuer,
      })) as Record<string, unknown>
    }

    if (!options.testSession) {
      if (typeof tokens.token_type !== 'string' || tokens.token_type.length === 0) {
        throw new Error('token response is missing token_type')
      }
      const tokenType = tokens.token_type.toLowerCase()
      if (dpop) {
        if (tokenType !== 'dpop') {
          throw new Error('DPoP token exchange returned a non-DPoP access token')
        }
        const cnf = accessClaims.cnf
        const jkt =
          cnf && typeof cnf === 'object'
            ? (cnf as Record<string, unknown>).jkt
            : undefined
        if (typeof jkt !== 'string' || jkt !== (await dpop.thumbprint())) {
          throw new Error('DPoP access token is not bound to this tab key')
        }
      } else if (tokenType === 'dpop') {
        throw new Error('received a DPoP access token without a local DPoP key')
      }
    }

    const idToken =
      tokens.id_token ?? (options.preserveExistingTokens ? currentIdToken : undefined)
    if (!idToken) {
      throw new Error('token response is missing an ID token')
    }

    let idClaims: Record<string, unknown>
    if (options.testSession) {
      try {
        idClaims = decodeJWTPayload(idToken)
      } catch {
        throw new Error('token response contains an invalid ID token')
      }
    } else if (!tokens.id_token && options.preserveExistingTokens && currentIdToken === idToken) {
      // The existing ID token was verified before it entered live state.
      idClaims = decodeJWTPayload(idToken)
    } else {
      idClaims = (await verifyIdToken(idToken, {
        authority: issuer,
        clientId,
        nonce: options.expectedNonce,
      })) as Record<string, unknown>
    }

    const accessSubject = accessClaims.sub
    const idSubject = idClaims.sub
    if (
      typeof accessSubject !== 'string' ||
      accessSubject.length === 0 ||
      typeof idSubject !== 'string' ||
      idSubject.length === 0 ||
      accessSubject !== idSubject
    ) {
      throw new Error('access and ID token subjects do not match')
    }
    if (currentUser && currentUser.id !== idSubject) {
      throw new Error('new credentials changed the authenticated subject')
    }

    const accessOrganizationId = organizationClaim(
      accessClaims,
      'access token',
      !options.testSession,
    )
    const idOrganizationId = organizationClaim(idClaims, 'ID token', !options.testSession)
    if (accessOrganizationId !== idOrganizationId) {
      throw new Error('access and ID token organization mismatch')
    }
    if (
      options.enforceExpectedOrganization &&
      accessOrganizationId !== options.expectedOrganizationId
    ) {
      throw new Error('token organization does not match the requested organization')
    }

    const user = toUser(idToken)
    if (!user) throw new Error('ID token has no usable subject')

    return {
      accessToken: tokens.access_token,
      idToken,
      refreshToken: useRefreshTokens
        ? (tokens.refresh_token ??
          (options.preserveExistingTokens ? refreshToken : undefined))
        : undefined,
      tokenType: tokens.token_type,
      organizationId: accessOrganizationId,
      user,
    }
  }

  /**
   * Validate, then atomically replace the live credential pair. Validation
   * and all asynchronous proof/JWKS work happens before any assignment, so a
   * failed or superseded organization grant cannot leave mixed credentials.
   */
  async function applyTokens(
    tokens: TokenResponse,
    options: ApplyTokenOptions = {},
  ): Promise<void> {
    if (destroyed) {
      throw new Error('auth client has been destroyed')
    }
    if (options.epoch !== undefined && options.epoch !== credentialEpoch) {
      throw new StaleCredentialTransactionError()
    }
    const prepared = await prepareCredentials(tokens, options)
    if (destroyed) {
      throw new Error('auth client has been destroyed')
    }
    if (options.epoch !== undefined && options.epoch !== credentialEpoch) {
      throw new StaleCredentialTransactionError()
    }
    if (options.advanceEpochOnCommit) credentialEpoch++

    accessToken = prepared.accessToken
    currentIdToken = prepared.idToken
    refreshToken = prepared.refreshToken
    currentOrganizationId = prepared.organizationId
    currentUser = prepared.user

    const stored: TokenResponse = {
      ...tokens,
      access_token: prepared.accessToken,
      id_token: prepared.idToken,
      refresh_token: prepared.refreshToken,
      token_type: prepared.tokenType,
    }
    void manager
      .storeUser(userFromTokenResponse(stored))
      .then(() => (destroyed ? manager.removeUser() : undefined))
      .catch(() => undefined)
    scheduleRenew()
    await deriveEncKey()
    if (destroyed) {
      zeroEncKey()
      throw new Error('auth client has been destroyed')
    }
    emit()
  }

  /** Clear all local session state (terminal auth failure / logout). */
  function clearSession(): void {
    credentialEpoch++
    clearRenewTimer()
    accessToken = undefined
    refreshToken = undefined
    currentUser = null
    currentIdToken = undefined
    currentOrganizationId = undefined
    // Drop the derived encryption key + error and best-effort zero the DEK
    // buffer. The vault record is wiped on logout (see logout()); a terminal
    // renewal failure keeps the vault so a subsequent silent restore can
    // rehydrate.
    zeroEncKey()
    encError = undefined
    void manager.removeUser().catch(() => undefined)
    emit()
  }

  /** Silent renew via iframe, preserving the transaction nonce with its tokens. */
  async function renewViaIframe(organizationId?: string): Promise<SilentCredentialGrant> {
    const result = await silentAuthorizeWithRetry(
      {
        authority: issuer,
        clientId,
        redirectUri,
        scope,
        audience,
        organizationId,
        deriveEncryptionKey,
      },
      DEFAULT_SILENT_RENEW_RETRY_COUNT,
    )
    const tokens = await exchangeCode(
        issuer,
        clientId,
        result.code,
        redirectUri,
        result.codeVerifier,
        dpop ?? undefined,
      )
    return { tokens, nonce: result.nonce }
  }

  /**
   * Run one tab-local renewal. Proof-bound credentials cannot be shared
   * across tabs, so coordination is signal-only and each tab renews with its
   * own DPoP key. The epoch guard prevents an older generic renewal from
   * overwriting a newer organization selection.
   */
  async function renewOnce(
    force: boolean,
    startEpoch: number,
    publishSignal: boolean,
  ): Promise<string | undefined> {
    const startingAccessToken = accessToken
    const startingRefreshToken = refreshToken
    const startingOrganizationId = currentOrganizationId

    if (!force && startingAccessToken) {
      const exp = getTokenExpiry(startingAccessToken)
      if (exp !== null && Date.now() < exp - RENEW_WINDOW_MS) {
        return startingAccessToken
      }
    }

    try {
      let tokens: TokenResponse
      let expectedNonce: string | undefined
      if (useRefreshTokens && startingRefreshToken) {
        try {
          tokens = await refreshTokenGrant(
            issuer,
            clientId,
            startingRefreshToken,
            scope,
            audience,
            dpop ?? undefined,
          )
        } catch (grantErr) {
          if (
            !useRefreshTokensFallback ||
            classifyRenewalError(grantErr) !== RecoveryAction.Retry
          ) {
            throw grantErr
          }
          const grant = await renewViaIframe(startingOrganizationId)
          tokens = grant.tokens
          expectedNonce = grant.nonce
        }
      } else {
        const grant = await renewViaIframe(startingOrganizationId)
        tokens = grant.tokens
        expectedNonce = grant.nonce
      }

      if (startEpoch !== credentialEpoch) return accessToken
      await applyTokens(tokens, {
        epoch: startEpoch,
        expectedOrganizationId: startingOrganizationId,
        enforceExpectedOrganization: true,
        preserveExistingTokens: true,
        expectedNonce,
      })

      if (publishSignal && broadcast) {
        broadcast.publish({ type: 'credentials-invalidated', sentAt: Date.now() })
      }
      renewBackoff = 0
      return tokens.access_token
    } catch (err) {
      if (err instanceof StaleCredentialTransactionError || startEpoch !== credentialEpoch) {
        return accessToken
      }
      switch (classifyRenewalError(err)) {
        case RecoveryAction.ForceReauth: {
          clearSession()
          if (publishSignal && broadcast) {
            broadcast.publish({ type: 'session-ended', sentAt: Date.now() })
          }
          return undefined
        }
        case RecoveryAction.Retry: {
          renewBackoff = Math.min(10, renewBackoff + 1)
          throw err
        }
        case RecoveryAction.Surface:
        default:
          throw err
      }
    }
  }

  function renewSingleFlight(
    force: boolean,
    publishSignal: boolean,
  ): Promise<string | undefined> {
    const epoch = credentialEpoch
    if (renewInFlight?.epoch === epoch) return renewInFlight.promise

    const promise = renewOnce(force, epoch, publishSignal).finally(() => {
      if (renewInFlight?.promise === promise) renewInFlight = null
    })
    renewInFlight = { epoch, promise }
    return promise
  }

  /** Return the current token, renewing when stale. Dedupes concurrent calls. */
  async function getToken(): Promise<string | undefined> {
    if (!accessToken) return undefined
    const exp = getTokenExpiry(accessToken)
    if (exp !== null && Date.now() < exp - RENEW_WINDOW_MS) {
      return accessToken
    }
    return renewSingleFlight(false, true)
  }

  /** Receive lifecycle signals only; credentials never cross the channel. */
  async function onBroadcast(message: BroadcastMessage): Promise<void> {
    if (message.type === 'session-ended') {
      clearSession()
      return
    }
    if (!currentUser) return
    await renewSingleFlight(true, false).catch(() => undefined)
  }

  async function forceRenew(): Promise<string | undefined> {
    return renewSingleFlight(true, true)
  }

  function isCallbackUrl(): boolean {
    if (typeof window === 'undefined') return false
    const params = new URLSearchParams(window.location.search)
    return params.has('code') || params.has('error')
  }

  /**
   * Install all tab-local credential machinery exactly once. Public callback
   * completion and init share this gate so neither can exchange a code before
   * required DPoP state exists.
   */
  function ensureRuntimeInitialized(): Promise<void> {
    if (runtimeInitPromise) return runtimeInitPromise
    runtimeInitPromise = (async () => {
      if (destroyed) throw new Error('auth client has been destroyed')

      // Capture the one-shot fragment before callback cleanup can remove it.
      if (deriveEncryptionKey) {
        fragmentKEK = extractKEKFromFragment()
      }
      if (useDPoP) {
        const initializedDPoP = await createDPoPKeyManager()
        if (destroyed) throw new Error('auth client has been destroyed')
        dpop = initializedDPoP
        if (!initializedDPoP && requireDPoP) {
          throw new Error('DPoP is required but WebCrypto could not create a key')
        }
      }
      if (destroyed) throw new Error('auth client has been destroyed')
      broadcast = createTokenBroadcast(`atol:tokens:${issuer}:${clientId}`)
      broadcast.subscribe((message) => {
        void onBroadcast(message)
      })
    })()
    return runtimeInitPromise
  }

  let completeLoginPromise: Promise<AtolSession> | null = null

  function completeLogin(): Promise<AtolSession> {
    if (!isCallbackUrl()) return Promise.resolve(session())
    if (completeLoginPromise) return completeLoginPromise

    const completion = (async (): Promise<AtolSession> => {
      try {
        await ensureRuntimeInitialized()
        const callback = await readAuthorizationCodeCallback(manager, window.location.href)
        const tokens = await exchangeCode(
          issuer,
          clientId,
          callback.code,
          callback.redirectUri,
          callback.codeVerifier,
          dpop ?? undefined,
        )
        await applyTokens(tokens, { expectedNonce: callback.nonce })
        return session()
      } catch {
        clearSession()
        throw new Error('OIDC callback failed. Please sign in again.')
      } finally {
        if (typeof window !== 'undefined') {
          window.history.replaceState({}, document.title, window.location.pathname)
        }
      }
    })().finally(() => {
      if (completeLoginPromise === completion) completeLoginPromise = null
    })
    completeLoginPromise = completion
    return completion
  }

  /** Adopt an oidc-client-ts User into session state. */
  async function adoptOidcUser(oidcUser: User): Promise<void> {
    const storedAccessToken = getAccessToken(oidcUser)
    if (!storedAccessToken) throw new Error('stored OIDC user has no access token')
    await applyTokens({
      access_token: storedAccessToken,
      id_token: getIdToken(oidcUser),
      refresh_token: oidcUser.refresh_token,
      token_type: oidcUser.token_type,
      expires_in: oidcUser.expires_in ?? 0,
      scope: oidcUser.scope,
    })
  }

  async function restoreSession(): Promise<void> {
    let oidcUser: User | null = await manager.getUser()
    if (oidcUser?.expired) oidcUser = null
    if (!oidcUser) {
      try {
        if (!restoreInFlight) {
          restoreInFlight = renewViaIframe()
        }
        const grant = await restoreInFlight
        await applyTokens(grant.tokens, { expectedNonce: grant.nonce })
        return
      } catch (err) {
        // login_required is the normal "no IdP session" answer.
        if (err instanceof LoginRequiredError) {
          oidcUser = null
        } else {
          // A discovery, CORS, network, or validation failure is not evidence
          // that the user signed out. Surface it so the host can render a
          // retryable error instead of silently changing session state.
          throw err
        }
      } finally {
        restoreInFlight = null
      }
    }
    if (oidcUser) {
      await adoptOidcUser(oidcUser)
    } else {
      emit()
    }
  }

  let initPromise: Promise<AtolSession> | null = null

  async function init(): Promise<AtolSession> {
    if (initPromise) return initPromise
    initPromise = (async () => {
      await ensureRuntimeInitialized()
      // TEST ONLY: adopt a pre-supplied session deterministically and skip the
      // restore entirely -- no redirect-callback handling, no silent-renew
      // iframe. Gated on allowTestSessions (initialTestSession is undefined
      // otherwise). This is why it is race-free where seedTestSession-after-mount
      // is not: init never launches the restore iframe that would otherwise
      // block against a stubbed backend with no IdP.
      if (initialTestSession) {
        warnIfSeedTokenNotFresh(initialTestSession.access_token)
        await applyTokens(initialTestSession, { testSession: true })
        return session()
      }
      // Restore or complete-login.
      if (isCallbackUrl()) {
        await completeLogin()
      } else {
        await restoreSession()
      }
      return session()
    })()
    return initPromise
  }

  async function beginLogin(options?: BeginLoginOptions): Promise<void> {
    const extraQueryParams: Record<string, string> = {}
    if (audience) extraQueryParams.audience = audience
    // Ask the issuer to mint the zero-knowledge encryption-key claim on the
    // ID token so a framework binding can derive the data-encryption key.
    if (deriveEncryptionKey) extraQueryParams.derive_encryption_key = 'true'
    // Step-up / forced-reauth parameters (OIDC Core). `prompt=login` re-prompts
    // for authentication; `max_age` caps the acceptable authentication age
    // (`max_age=0` forces a brand-new login); `acr_values` requests a specific
    // assurance level (e.g. "mfa"). Passed straight through to the authorize URL.
    if (options?.prompt) extraQueryParams.prompt = options.prompt
    if (options?.maxAge !== undefined) extraQueryParams.max_age = String(options.maxAge)
    if (options?.acrValues) extraQueryParams.acr_values = options.acrValues
    await manager.signinRedirect({
      redirect_uri:
        options?.returnTo && typeof window !== 'undefined'
          ? `${window.location.origin}${options.returnTo}`
          : redirectUri,
      extraQueryParams,
      nonce: generateAuthorizationNonce(),
    })
  }

  async function stepUp(options?: StepUpOptions): Promise<void> {
    // A step-up is a forced re-authentication: prompt=login + max_age=0 so the
    // issuer mints a token with a fresh auth_time (and a completed second
    // factor), which the management API's step-up gate requires for sensitive
    // operations. Defaults request the "mfa" assurance level; callers may
    // override acrValues or set a non-zero maxAge.
    await beginLogin({
      returnTo: options?.returnTo,
      prompt: 'login',
      maxAge: options?.maxAge ?? 0,
      acrValues: options?.acrValues ?? 'mfa',
    })
  }

  async function selectOrganization(organizationId: string): Promise<AtolSession> {
    if (!CANONICAL_ULID.test(organizationId)) {
      throw new Error('organizationId must be a canonical ULID')
    }
    if (!currentUser) {
      throw new Error('cannot select an organization without an authenticated session')
    }

    // A selection is its own credential transaction. Advancing the epoch
    // immediately makes any older generic renewal result ineligible to
    // commit, while leaving the current pair live until the new pair has
    // passed every validation check.
    const selectionEpoch = ++credentialEpoch
    clearRenewTimer()
    try {
      const grant = await renewViaIframe(organizationId)
      await applyTokens(grant.tokens, {
        epoch: selectionEpoch,
        expectedOrganizationId: organizationId,
        enforceExpectedOrganization: true,
        preserveExistingTokens: false,
        expectedNonce: grant.nonce,
        advanceEpochOnCommit: true,
      })
      if (broadcast) {
        broadcast.publish({ type: 'credentials-invalidated', sentAt: Date.now() })
      }
      return session()
    } catch (err) {
      // The previous credential pair was never mutated, so it remains safe
      // to use. Re-arm its timer before surfacing the failed selection.
      if (selectionEpoch === credentialEpoch) scheduleRenew()
      throw err
    }
  }

  async function logout(): Promise<void> {
    // Best-effort refresh-token revocation (RFC 7009) before we drop it.
    if (refreshToken) {
      await revokeToken(issuer, clientId, refreshToken).catch(() => undefined)
    }
    const idTokenHint = currentIdToken
    if (broadcast) {
      broadcast.publish({ type: 'session-ended', sentAt: Date.now() })
    }
    clearSession()
    // Wipe the device-bound KEK vault so the next visit to this origin does
    // not silently rehydrate this user's DEK. Best-effort and non-blocking:
    // the logout redirect must not wait on IndexedDB, and a missing record
    // is fine (clear is idempotent). Only when the feature is on.
    if (deriveEncryptionKey) {
      void getVault().clear().catch(() => undefined)
    }
    await manager.signoutRedirect({
      post_logout_redirect_uri: redirectUri,
      ...(idTokenHint ? { id_token_hint: idTokenHint } : {}),
    })
  }

  async function getAccessTokenPublic(
    opts?: GetAccessTokenOptions,
  ): Promise<{ token: string; proof?: string } | undefined> {
    const token = await getToken()
    if (!token) return undefined
    if (opts?.dpop && dpop) {
      const proof = await dpop.signProof(opts.dpop.method, opts.dpop.url, {
        accessToken: token,
      })
      return { token, proof }
    }
    return { token }
  }

  async function signDPoPProof(
    method: string,
    url: string,
  ): Promise<DPoPProofResult | undefined> {
    const token = await getToken()
    if (!token) return undefined
    const proof = dpop ? await dpop.signProof(method, url, { accessToken: token }) : undefined
    return { token, proof }
  }

  async function seedTestSession(tokens: TokenResponse): Promise<AtolSession> {
    if (!allowTestSessions) {
      // Deny by default. Without the opt-in this method is inert, so an XSS
      // payload in a production build cannot use it to forge a session.
      throw new Error(
          'seedTestSession is disabled: pass allowTestSessions:true to ' +
          'createAtolBrowserAuth to enable it. It bypasses OIDC signature, ' +
          'state, nonce, and DPoP-binding validation and must never be enabled ' +
          'in production.',
      )
    }
    // A seeded access token needs a FUTURE `exp`: applyTokens schedules
    // proactive renewal from it, and a missing/past exp makes the client renew
    // immediately (and possibly drop the session). Warn loudly rather than let
    // it become a silent "authenticated then instantly signed out" flake.
    warnIfSeedTokenNotFresh(tokens.access_token)
    // Adopt the tokens through the same routine a real login/renewal uses:
    // store the user in-memory, set the current user/id token from the id
    // token, honor the refresh-token retention policy, schedule renewal, and
    // emit so subscribers (a framework binding) flip to authenticated.
    await applyTokens(tokens, { testSession: true })
    return session()
  }

  function onSessionChange(cb: (s: AtolSession) => void): () => void {
    subscribers.add(cb)
    // Fire immediately with the current snapshot.
    try {
      cb(session())
    } catch {
      // ignore subscriber errors on initial fire
    }
    return () => {
      subscribers.delete(cb)
    }
  }

  function destroy(): void {
    if (destroyed) return
    destroyed = true
    credentialEpoch++
    clearRenewTimer()
    if (broadcast) {
      broadcast.close()
      broadcast = null
    }
    subscribers.clear()
    dpop = null
    accessToken = undefined
    refreshToken = undefined
    currentUser = null
    currentIdToken = undefined
    currentOrganizationId = undefined
    void manager.removeUser().catch(() => undefined)
    // Best-effort zero the DEK buffer and drop derived encryption state.
    zeroEncKey()
    encError = undefined
  }

  return {
    init,
    beginLogin,
    stepUp,
    completeLogin,
    selectOrganization,
    getAccessToken: getAccessTokenPublic,
    getIdToken: () => currentIdToken,
    getEncryptionKey: () => encKey,
    getEncryptionError: () => encError,
    logout,
    forceRenew,
    signDPoPProof,
    isDPoPActive: () => dpop !== null,
    onSessionChange,
    seedTestSession,
    destroy,
  }
}
