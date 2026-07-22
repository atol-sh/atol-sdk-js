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
 * Carries the machine-readable `error` code from the token / authorize
 * endpoint response so the recovery layer can act on it precisely.
 */
export class OAuthProtocolError extends Error {
  code: string
  description?: string
  constructor(code: string, description?: string) {
    super(description ? `${code}: ${description}` : code)
    this.code = code
    this.description = description
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
  constructor(description?: string) {
    super("login_required", description)
    this.name = "LoginRequiredError"
  }
}

/**
 * Transport / network layer failure -- `fetch` rejected, DNS miss, TLS
 * error, CORS block. Surfaced as retry because the authorization server
 * never saw the request.
 */
export class NetworkError extends Error {
  cause?: unknown
  constructor(message: string, cause?: unknown) {
    super(message)
    this.cause = cause
    this.name = "NetworkError"
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
