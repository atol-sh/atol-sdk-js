/**
 * createAtolBrowserAuth: the config-driven browser auth client.
 *
 * This is the keystone of @atol-sh/js. It wraps oidc-client-ts with the
 * proven Atol logic that previously lived only inside the React provider:
 * PKCE authorization-code login, in-memory token storage, DPoP-aware token
 * access, proactive + on-demand silent renewal with single-flight
 * coordination, cross-tab rotation broadcast (authenticated via JWKS), and
 * RP-initiated logout with refresh-token revocation.
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
  userFromTokenResponse,
} from '../oidc/oidc'
import { getTokenExpiry, parseAtolUser } from '../claims/claims'
import {
  DEFAULT_SILENT_RENEW_RETRY_COUNT,
  LoginRequiredError,
  exchangeCode,
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
import { withTabLock } from '../oidc/cross-tab-lock'
import {
  createTokenBroadcast,
  type BroadcastMessage,
  type TokenBroadcast,
} from '../token/token-broadcast'
import { createDPoPKeyManager, type DPoPKeyManager } from '../dpop/dpop'
import { verifyIdToken } from '../verify/verify'
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
   * proof to every token-endpoint call. `false` (default) uses Bearer.
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
}

/** The current auth session, delivered to `onSessionChange` subscribers. */
export interface AtolSession {
  /** Whether a user is currently authenticated. */
  isAuthenticated: boolean
  /** The authenticated user, or null. */
  user: AtolUser | null
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
   * Subscribe to session changes (login, logout, renewal, cross-tab
   * rotation). The callback fires immediately with the current session, and
   * again on every subsequent change. Returns an unsubscribe function.
   */
  onSessionChange(cb: (session: AtolSession) => void): () => void
  /** Tear down timers, the broadcast channel, and subscriptions. */
  destroy(): void
}

const DEFAULT_SCOPES = 'openid profile email'
/** Renew when the access token is within this window of expiry. */
const RENEW_WINDOW_MS = 60_000

function dpopEnabled(cfg: DPoPConfig | undefined): boolean {
  if (typeof cfg === 'boolean') return cfg
  return cfg?.required === true
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
  const useRefreshTokens = config.useRefreshTokens ?? false
  const useRefreshTokensFallback = config.useRefreshTokensFallback ?? false
  const deriveEncryptionKey = config.deriveEncryptionKey ?? false

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
  let renewInFlight: Promise<string | undefined> | null = null
  let renewBackoff = 0
  let restoreInFlight: Promise<TokenResponse> | null = null
  let destroyed = false

  const subscribers = new Set<(session: AtolSession) => void>()

  function session(): AtolSession {
    return {
      isAuthenticated: currentUser !== null,
      user: currentUser,
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
      if (!renewInFlight) {
        renewInFlight = renewOnce()
          .catch(() => undefined)
          .finally(() => {
            renewInFlight = null
          })
      }
    }, delay)
  }

  /**
   * Apply a token response to session state + the oidc-client-ts store,
   * derive the encryption key (when enabled), then emit. Async because DEK
   * derivation is async and must complete before we emit so subscribers see
   * the key in the same session payload.
   */
  async function applyTokens(tokens: TokenResponse): Promise<void> {
    accessToken = tokens.access_token
    // Only retain a refresh token when the caller opted into the
    // refresh-token renewal strategy. In the default iframe model a stray
    // server-issued RT is dropped -- neither kept in memory nor persisted to
    // the oidc-client-ts store -- so renewal stays on the iframe path.
    const stored = useRefreshTokens ? tokens : { ...tokens, refresh_token: undefined }
    if (useRefreshTokens && tokens.refresh_token) {
      refreshToken = tokens.refresh_token
    }
    void manager.storeUser(userFromTokenResponse(stored)).catch(() => undefined)
    if (tokens.id_token) {
      currentIdToken = tokens.id_token
      currentUser = toUser(tokens.id_token)
    }
    scheduleRenew()
    await deriveEncKey()
    emit()
  }

  /** Clear all local session state (terminal auth failure / logout). */
  function clearSession(): void {
    clearRenewTimer()
    accessToken = undefined
    refreshToken = undefined
    currentUser = null
    currentIdToken = undefined
    // Drop the derived encryption key + error and best-effort zero the DEK
    // buffer. The vault record is wiped on logout (see logout()); a terminal
    // renewal failure keeps the vault so a subsequent silent restore can
    // rehydrate.
    zeroEncKey()
    encError = undefined
    void manager.removeUser().catch(() => undefined)
    emit()
  }

  /** Silent renew via the iframe + web_message flow (raw tokens). */
  async function renewViaIframe(): Promise<TokenResponse> {
    const result = await silentAuthorizeWithRetry(
      { authority: issuer, clientId, redirectUri, scope, audience, deriveEncryptionKey },
      DEFAULT_SILENT_RENEW_RETRY_COUNT,
    )
    return exchangeCode(
      issuer,
      clientId,
      result.code,
      redirectUri,
      result.codeVerifier,
      dpop ?? undefined,
    )
  }

  /**
   * Run the renew once, under a cross-tab lock so simultaneous tabs collapse
   * to a single /auth/token POST. Broadcasts the rotated tokens. Terminal
   * auth errors clear the session; transient errors re-throw for backoff.
   */
  async function renewOnce(force = false): Promise<string | undefined> {
    const lockName = `atol:renew:${issuer}:${clientId}`
    return withTabLock(lockName, 30_000, async () => {
      if (!force && accessToken) {
        const exp = getTokenExpiry(accessToken)
        if (exp !== null && Date.now() < exp - RENEW_WINDOW_MS) {
          return accessToken
        }
      }

      try {
        let tokens: TokenResponse
        if (useRefreshTokens && refreshToken) {
          try {
            tokens = await refreshTokenGrant(
              issuer,
              clientId,
              refreshToken,
              scope,
              audience,
              dpop ?? undefined,
            )
          } catch (grantErr) {
            // A TRANSIENT refresh-token grant failure (network blip, 5xx,
            // 429) can fall back to the hidden-iframe path once when the
            // caller opted in via useRefreshTokensFallback. Terminal auth
            // failures (invalid_grant / login_required -> ForceReauth) and
            // programmer errors (Surface) are re-thrown to the outer catch,
            // which clears the session, so a dead refresh token never
            // silently degrades into an iframe renew.
            if (
              !useRefreshTokensFallback ||
              classifyRenewalError(grantErr) !== RecoveryAction.Retry
            ) {
              throw grantErr
            }
            tokens = await renewViaIframe()
          }
        } else {
          tokens = await renewViaIframe()
        }
        await applyTokens(tokens)

        if (broadcast) {
          const exp =
            getTokenExpiry(tokens.access_token) ??
            Date.now() + (tokens.expires_in ?? 3600) * 1000
          broadcast.publish({
            type: 'token-rotated',
            accessToken: tokens.access_token,
            idToken: tokens.id_token,
            // Only carry a refresh token cross-tab in the refresh-token
            // model; in the iframe model each tab renews on its own.
            refreshToken: useRefreshTokens ? tokens.refresh_token : undefined,
            expiresAt: exp,
            sentAt: Date.now(),
          })
        }

        renewBackoff = 0
        return tokens.access_token
      } catch (err) {
        switch (classifyRenewalError(err)) {
          case RecoveryAction.ForceReauth: {
            clearSession()
            if (broadcast) {
              broadcast.publish({ type: 'session-expired', sentAt: Date.now() })
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
    })
  }

  /** Return the current token, renewing when stale. Dedupes concurrent calls. */
  async function getToken(): Promise<string | undefined> {
    if (accessToken) {
      const exp = getTokenExpiry(accessToken)
      if (exp !== null && Date.now() < exp - RENEW_WINDOW_MS) {
        return accessToken
      }
    } else {
      const stored = getAccessToken((await manager.getUser()) ?? null)
      if (stored) {
        const exp = getTokenExpiry(stored)
        if (exp !== null && Date.now() < exp - RENEW_WINDOW_MS) {
          return stored
        }
      } else {
        return undefined
      }
    }
    if (!renewInFlight) {
      renewInFlight = renewOnce().finally(() => {
        renewInFlight = null
      })
    }
    return renewInFlight
  }

  /**
   * Cross-tab broadcast handler: adopt rotated tokens only after
   * authenticating the ID token (signature, issuer, audience) against the
   * IdP JWKS and pinning the subject. Never trust a raw channel message.
   */
  async function onBroadcast(message: BroadcastMessage): Promise<void> {
    if (message.type === 'session-expired') {
      // Re-verify with the server rather than trusting the message: a forged
      // session-expired is a no-op because forceRenew only clears when the
      // refresh token is actually dead.
      void forceRenew()
      return
    }
    const rotated = message
    // Forward-progress only.
    if (accessToken) {
      const existingExp = getTokenExpiry(accessToken)
      if (existingExp !== null && existingExp >= rotated.expiresAt) return
    }
    if (!rotated.idToken) return
    let claims
    try {
      claims = await verifyIdToken(rotated.idToken, { authority: issuer, clientId })
    } catch {
      return // Unverifiable -> never adopt.
    }
    // Identity pinning: a broadcast must not switch the active user.
    if (currentUser && claims.sub !== currentUser.id) return

    // Under DPoP each tab owns its own key, so the leader's refresh token is
    // bound to a different cnf.jkt. Adopting it would poison the family on
    // the next renew. Drop the RT under DPoP; keep it otherwise.
    const dpopActive = dpop !== null
    await applyTokens({
      access_token: rotated.accessToken,
      id_token: rotated.idToken,
      refresh_token: dpopActive ? undefined : rotated.refreshToken,
      token_type: 'bearer',
      expires_in: Math.max(0, Math.floor((rotated.expiresAt - Date.now()) / 1000)),
    })
  }

  async function forceRenew(): Promise<string | undefined> {
    if (!renewInFlight) {
      renewInFlight = renewOnce(true).finally(() => {
        renewInFlight = null
      })
    }
    return renewInFlight
  }

  function isCallbackUrl(): boolean {
    if (typeof window === 'undefined') return false
    const s = window.location.search
    return s.includes('code=') || s.includes('error=')
  }

  async function completeLogin(): Promise<AtolSession> {
    if (!isCallbackUrl()) return session()
    const oidcUser = await manager.signinRedirectCallback()
    await adoptOidcUser(oidcUser)
    // Clean the code/state out of the address bar.
    if (typeof window !== 'undefined') {
      window.history.replaceState({}, document.title, window.location.pathname)
    }
    return session()
  }

  /** Adopt an oidc-client-ts User into session state. */
  async function adoptOidcUser(oidcUser: User): Promise<void> {
    accessToken = getAccessToken(oidcUser)
    // Only adopt a refresh token under the refresh-token strategy; the
    // default iframe model never renews from a stored RT.
    if (useRefreshTokens && oidcUser.refresh_token) {
      refreshToken = oidcUser.refresh_token
    }
    currentIdToken = getIdToken(oidcUser)
    currentUser = toUser(currentIdToken)
    scheduleRenew()
    await deriveEncKey()
    emit()
  }

  async function restoreSession(): Promise<void> {
    let oidcUser: User | null = await manager.getUser()
    if (oidcUser?.expired) oidcUser = null
    if (!oidcUser) {
      try {
        if (!restoreInFlight) {
          restoreInFlight = renewViaIframe()
        }
        const tokens = await restoreInFlight
        // In the iframe model, drop any stray RT before it reaches the store.
        oidcUser = userFromTokenResponse(
          useRefreshTokens ? tokens : { ...tokens, refresh_token: undefined },
        )
        await manager.storeUser(oidcUser)
      } catch (err) {
        // login_required is the normal "no IdP session" answer.
        if (!(err instanceof LoginRequiredError)) {
          // Non-terminal restore failures are swallowed: the on-demand path
          // retries on the next getAccessToken. Never log token material.
        }
        oidcUser = null
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
      // Capture the zero-knowledge KEK from the URL fragment FIRST, before
      // anything touches the URL. On a fresh login-callback the Atol
      // authorize endpoint delivers the KEK in the fragment
      // (`#atol_enc_key=...`) alongside the `?code=` query; completeLogin
      // strips the query below and extractKEKFromFragment strips the
      // fragment here, so this must run before either. Gated on the option:
      // when off, the fragment is never read. The captured KEK is consumed
      // once by deriveEncKey() to provision the vault.
      if (deriveEncryptionKey) {
        fragmentKEK = extractKEKFromFragment()
      }
      // DPoP key install (best-effort; null => Bearer).
      if (useDPoP) {
        dpop = await createDPoPKeyManager()
      }
      // Cross-tab broadcast wiring.
      broadcast = createTokenBroadcast(`atol:tokens:${issuer}:${clientId}`)
      broadcast.subscribe((message) => {
        void onBroadcast(message)
      })
      // Restore or complete-login.
      if (isCallbackUrl()) {
        try {
          await completeLogin()
        } catch {
          // A stale/failed callback settles unauthenticated; the caller can
          // retry beginLogin. Never surface token material in the error.
          clearSession()
        }
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

  async function logout(): Promise<void> {
    // Best-effort refresh-token revocation (RFC 7009) before we drop it.
    if (refreshToken) {
      await revokeToken(issuer, clientId, refreshToken).catch(() => undefined)
    }
    // Look up the id_token_hint for RP-initiated logout validation.
    let idTokenHint: string | undefined
    try {
      const u = await manager.getUser()
      idTokenHint = u?.id_token ?? undefined
    } catch {
      // getUser failure must not block logout.
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
    clearRenewTimer()
    if (broadcast) {
      broadcast.close()
      broadcast = null
    }
    subscribers.clear()
    dpop = null
    // Best-effort zero the DEK buffer and drop derived encryption state.
    zeroEncKey()
    encError = undefined
  }

  return {
    init,
    beginLogin,
    stepUp,
    completeLogin,
    getAccessToken: getAccessTokenPublic,
    getIdToken: () => currentIdToken,
    getEncryptionKey: () => encKey,
    getEncryptionError: () => encError,
    logout,
    forceRenew,
    signDPoPProof,
    isDPoPActive: () => dpop !== null,
    onSessionChange,
    destroy,
  }
}
