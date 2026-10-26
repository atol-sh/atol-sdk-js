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

import type { AtolUser, DPoPProofResult } from '../claims/types'
import type { TokenResponse } from '../oidc/silent-renew'

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
  /** Exact registered OIDC callback URL used only for authorization responses. */
  redirectUri: string
  /**
   * Exact registered same-origin landing URL used after RP-initiated logout.
   * Ordinary clients default to `redirectUri` for compatibility.
   * Response-vault clients require an explicit, distinct value.
   */
  postLogoutRedirectUri?: string
  /**
   * Enable the public response-vault v1 browser authorization protocol. Every
   * interactive, silent, organization-selection, and step-up authorization
   * uses PAR plus a parameter-free navigation and same-origin token relay.
   * The client registration must support the protocol. A non-empty audience
   * and mandatory DPoP are required.
   */
  responseVault?: boolean
  /**
   * Request DPoP-bound tokens (RFC 9449). `true` (or `{ required: true }`)
   * generates a per-tab non-exportable ES256 keypair on init and attaches a
   * proof to every token-endpoint call. `{ required: true }` also makes key
   * creation failure fatal; boolean `true` retains a Bearer fallback where
   * WebCrypto is unavailable. `false` (default) uses Bearer for ordinary
   * clients. Response-vault mode always requires DPoP and rejects `false`.
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
  /**
   * Same-origin application route to restore only after the authorization
   * response has been verified and committed. This is transaction-bound
   * application state and never changes the registered OIDC redirect URI.
   */
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
  /**
   * Same-origin application route to restore after the verified step-up
   * response commits. It never changes the registered OIDC redirect URI.
   */
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
   * the Atol authorize endpoint. The registered redirect URI is immutable;
   * host applications keep any post-login route separately in same-tab state.
   * `prompt` / `maxAge` / `acrValues` are forwarded as OIDC
   * authorize-request parameters (used by {@link AtolBrowserAuth.stepUp} to
   * force re-authentication).
   */
  beginLogin(options?: BeginLoginOptions): Promise<void>
  /**
   * Force a step-up re-authentication: redirect to the authorize endpoint with
   * `prompt=login` + `max_age=0` (and `acr_values=mfa` by default) so the
   * issuer mints a token with a fresh `auth_time` and a completed second
   * factor. Use this when a sensitive operation returns a
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
   * Cancel the response-vault interactive login owned by the current browser
   * generation without ending an established session or navigating to the
   * issuer. Resolves only after exact server rejection and local custody
   * release. Unsupported auth modes and initialized/session states reject.
   */
  cancelLogin(): Promise<void>
  /**
   * Whether this runtime holds the exact hidden failed-initialization
   * authority required by {@link AtolBrowserAuth.restartLogin}. This is a
   * read-only lifecycle capability, not a probe of arbitrary durable custody.
   */
  canRestartLogin(): boolean
  /**
   * Recover from a rejected, signed-out response-vault initialization caused
   * by an authorization abandoned in another tab. The SDK first invalidates
   * the abandoned origin-wide generation, then rejects only the exact durable
   * reference, binding, mode, generation, and active slot captured by
   * `init()`. A fresh authorization starts only after authenticated server
   * settlement and local custody release complete.
   *
   * Concurrent callers share one operation. Ordinary `cancelLogin()` remains
   * same-tab only and will not adopt custody merely because a tab owner differs.
   */
  restartLogin(options?: BeginLoginOptions): Promise<void>
  /**
   * Persist durable signed-out authority, clear local state, attempt refresh
   * revocation, then redirect to the end_session endpoint with a one-use
   * callback state. Any observable teardown or navigation failure rejects
   * while the tombstone continues to suppress silent restoration.
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
  /**
   * Tear down timers, the broadcast channel, and subscriptions. A failed
   * browser-resource close throws `AtolBrowserAuthCleanupError`; call again
   * to retry only the retained cleanup ownership.
   */
  destroy(): void
}

export { AtolBrowserAuthCleanupError } from './browser-auth-diagnostics'
export { createAtolBrowserAuth } from './browser-auth-runtime'
