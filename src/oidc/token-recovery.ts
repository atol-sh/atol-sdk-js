/**
 * Token renewal error classification.
 *
 * The provider's `renewOnce` has three possible reactions to a failed
 * renewal: retry (transient), force re-auth (terminal auth failure,
 * local state is out of sync with the server), or surface (programmer
 * error the caller should see). Spreading those decisions across every
 * catch block drifts; centralizing them here keeps the contract auditable.
 *
 * The classification is deliberately conservative: anything we don't
 * recognize surfaces, rather than silently forcing re-auth or looping.
 */

/**
 * OAuth 2.0 / OIDC protocol error surfaced by the authorization server.
 * Carries only a closed machine-readable code. Provider descriptions and
 * unknown error names are untrusted diagnostic input and are never retained
 * on a public Error object.
 */
const OAUTH_PROTOCOL_ERROR_CODES = [
  "access_denied",
  "account_selection_required",
  "authorization_pending",
  "authorization_nonterminal",
  "authorization_terminal",
  "consent_required",
  "expired_token",
  "insufficient_scope",
  "interaction_required",
  "invalid_client",
  "invalid_dpop_proof",
  "invalid_grant",
  "invalid_request",
  "invalid_response",
  "invalid_scope",
  "invalid_token",
  "login_required",
  "server_error",
  "slow_down",
  "temporarily_unavailable",
  "unauthorized_client",
  "unsupported_grant_type",
  "unsupported_response_type",
  "use_dpop_nonce",
] as const

export type OAuthProtocolErrorCode =
  (typeof OAUTH_PROTOCOL_ERROR_CODES)[number]

export function closedOAuthProtocolErrorCode(
  value: unknown,
): OAuthProtocolErrorCode {
  switch (value) {
    case "access_denied":
    case "account_selection_required":
    case "authorization_pending":
    case "authorization_nonterminal":
    case "authorization_terminal":
    case "consent_required":
    case "expired_token":
    case "insufficient_scope":
    case "interaction_required":
    case "invalid_client":
    case "invalid_dpop_proof":
    case "invalid_grant":
    case "invalid_request":
    case "invalid_response":
    case "invalid_scope":
    case "invalid_token":
    case "login_required":
    case "server_error":
    case "slow_down":
    case "temporarily_unavailable":
    case "unauthorized_client":
    case "unsupported_grant_type":
    case "unsupported_response_type":
    case "use_dpop_nonce":
      return value
    default:
      return "invalid_response"
  }
}

export class OAuthProtocolError extends Error {
  readonly code: OAuthProtocolErrorCode

  constructor(code: unknown, _description?: unknown) {
    const safeCode = closedOAuthProtocolErrorCode(code)
    super(`OAuth protocol error: ${safeCode}`)
    this.code = safeCode
    this.name = "OAuthProtocolError"
  }
}

/**
 * Re-auth-class protocol errors -- login_required, consent_required,
 * interaction_required. Subclass of OAuthProtocolError so existing
 * `instanceof LoginRequiredError` checks keep working AND `instanceof
 * OAuthProtocolError` matches the broader classification.
 */
export class LoginRequiredError extends OAuthProtocolError {
  constructor(_description?: unknown) {
    super("login_required")
    this.name = "LoginRequiredError"
  }
}

/**
 * Transport / network layer failure -- `fetch` rejected, DNS miss, TLS
 * error, CORS block. Surfaced as retry because the authorization server
 * never saw the request.
 */
export class NetworkError extends Error {
  constructor(message: string, _cause?: unknown) {
    super(message)
    this.name = "NetworkError"
  }
}

/**
 * The token request may have consumed an authorization code, but the browser
 * did not obtain a complete usable response. Exact code replay is required so
 * the authorization server can revoke any first family before local cleanup.
 */
export class AuthorizationCodeExchangeUncertainError extends NetworkError {
  readonly code = 'authorization_code_exchange_uncertain'

  constructor(message: string, _cause?: unknown) {
    super(message)
    this.name = 'AuthorizationCodeExchangeUncertainError'
  }
}

/**
 * What the caller should do when a renewal throws.
 *
 *   Retry       -- transient (network blip, 5xx). Backoff and try again.
 *   ForceReauth -- terminal (stale refresh token, revoked client, session
 *                  gone). Wipe local state and return the user to the
 *                  signed-out screen. Don't loop.
 *   Surface     -- programmer error (invalid_scope, unsupported_grant_type).
 *                  Throw to the caller so they can see it during dev.
 */
export enum RecoveryAction {
  Retry = "retry",
  ForceReauth = "force_reauth",
  Surface = "surface",
}

/**
 * Classify a renewal error into a recovery action. The full mapping,
 * grouped by cause:
 *
 *   Terminal auth (ForceReauth):
 *     invalid_grant           refresh token expired / revoked / rotated-reused
 *     invalid_request         stale or malformed token at /auth/token
 *                             (also what the server returns after a lost HMAC secret)
 *     invalid_client          client was deleted / secret changed server-side
 *     unauthorized_client     client no longer permitted this grant
 *     login_required          prompt=none could not silently re-auth
 *     consent_required        user consent missing
 *     interaction_required    user action required
 *
 *   Transient (Retry):
 *     server_error            500-class error on the authz server
 *     temporarily_unavailable documented OAuth retry signal
 *     NetworkError            fetch rejection, DNS, TLS, CORS
 *
 *   Programmer error (Surface):
 *     invalid_scope           misconfigured scope list
 *     unsupported_grant_type  wrong grant wiring
 *     unsupported_response_type
 *     Unknown OAuth codes     -- conservative default
 *     Unknown Error subclass  -- ditto
 */
export function classifyRenewalError(err: unknown): RecoveryAction {
  if (err instanceof OAuthProtocolError) {
    switch (err.code) {
      case "invalid_grant":
      case "invalid_request":
      case "invalid_client":
      case "unauthorized_client":
      case "login_required":
      case "consent_required":
      case "interaction_required":
        return RecoveryAction.ForceReauth

      case "server_error":
      case "temporarily_unavailable":
        return RecoveryAction.Retry

      case "invalid_scope":
      case "unsupported_grant_type":
      case "unsupported_response_type":
        return RecoveryAction.Surface

      default:
        return RecoveryAction.Surface
    }
  }

  if (err instanceof NetworkError) return RecoveryAction.Retry

  return RecoveryAction.Surface
}

/**
 * Exponential backoff with full jitter. Cheap, deterministic test
 * surface -- callers can swap out `Math.random` via the seed arg.
 *
 *   attempt 0 -> [0, 500)      ms
 *   attempt 1 -> [0, 1000)     ms
 *   attempt 2 -> [0, 2000)     ms
 *   attempt 3 -> [0, 4000)     ms
 *   attempt N -> [0, 30_000)   ms   (capped)
 *
 * The cap matters: without it an always-failing transient error fires a
 * renewal an hour later and the user thinks the app is frozen.
 */
export function backoffDelay(attempt: number, rand: () => number = Math.random): number {
  const base = 500 // ms
  const cap = 30_000 // ms
  const exp = Math.min(cap, base * Math.pow(2, Math.max(0, attempt)))
  return Math.floor(rand() * exp)
}
