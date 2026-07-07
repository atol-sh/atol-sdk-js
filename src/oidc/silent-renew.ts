/**
 * Silent token renewal via web_message response mode.
 *
 * Opens a hidden iframe to the authorization endpoint with response_mode=web_message
 * and prompt=none. The server validates the session cookie and returns an HTML page
 * that sends the authorization response via postMessage. No SPA loading in the iframe.
 *
 * Spec: draft-sakimura-oauth-wmrm-01
 */

import { bytesToBase64Url } from '../crypto/base64url'
import type { DPoPProofOptions } from '../dpop/dpop'
import {
  LoginRequiredError,
  NetworkError,
  OAuthProtocolError,
} from './token-recovery'

// Re-export for backward compatibility -- the browser auth client and the
// React provider import LoginRequiredError directly from this module.
export { LoginRequiredError } from './token-recovery'

interface AuthorizationResponse {
  type: 'authorization_response'
  response: {
    code?: string
    state?: string
    error?: string
    error_description?: string
  }
}

interface SilentRenewOptions {
  authority: string
  clientId: string
  redirectUri: string
  scope: string
  audience?: string
  /**
   * When true, asks the server to include `atol:wrapped_dek` on the renewed
   * ID token. The KEK is NOT re-delivered (the password isn't available
   * during silent renew), but carrying the wrapped DEK claim keeps it
   * consistently present across every token in the session, so app code
   * that re-reads it after a renewal (tab rehydrate, multi-tab sync) finds
   * the same DEK material it saw at login.
   */
  deriveEncryptionKey?: boolean
  /**
   * Milliseconds to wait for the iframe's postMessage before rejecting.
   * Defaults to 60s. An earlier 10s value was too tight on
   * slow networks and caused the "return stale token" fallback to fire
   * unnecessarily, producing `token is expired (exp)` errors on the server.
   */
  timeoutMs?: number
}

/** Default iframe timeout for silent authorization. */
export const DEFAULT_AUTHORIZE_TIMEOUT_MS = 60_000

/** Default retry count for silent authorize on transient errors. */
export const DEFAULT_SILENT_RENEW_RETRY_COUNT = 3


/**
 * Perform a silent authorization request via web_message.
 * Returns the authorization code + state, or throws on error.
 */
export async function silentAuthorize(
  opts: SilentRenewOptions,
): Promise<{ code: string; state: string; codeVerifier: string }> {
  const timeout = opts.timeoutMs ?? DEFAULT_AUTHORIZE_TIMEOUT_MS

  // Generate PKCE challenge.
  const verifier = generateCodeVerifier()
  const challenge = await generateCodeChallenge(verifier)

  // Generate state for CSRF.
  const state = generateRandomString(32)

  // Build the authorize URL with response_mode=web_message.
  const params = new URLSearchParams({
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    response_type: 'code',
    response_mode: 'web_message',
    scope: opts.scope,
    state,
    prompt: 'none',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })
  if (opts.audience) {
    params.set('audience', opts.audience)
  }
  if (opts.deriveEncryptionKey) {
    // The server re-emits the stored wrapped DEK on silent renew when this
    // flag is set, without re-deriving the KEK (no password is available).
    // Keeps the `atol:wrapped_dek` claim stable across every token.
    params.set('derive_encryption_key', 'true')
  }

  const authorizeUrl = `${opts.authority}/auth/authorize?${params.toString()}`
  const expectedOrigin = new URL(opts.authority).origin

  return new Promise<{ code: string; state: string; codeVerifier: string }>((resolve, reject) => {
    let iframe: HTMLIFrameElement | null = null
    let timer: ReturnType<typeof setTimeout> | null = null

    function cleanup() {
      if (timer) clearTimeout(timer)
      window.removeEventListener('message', onMessage)
      if (iframe && iframe.parentNode) {
        iframe.parentNode.removeChild(iframe)
      }
    }

    function onMessage(event: MessageEvent) {
      // Verify origin matches the authorization server.
      if (event.origin !== expectedOrigin) return

      const data = event.data as AuthorizationResponse
      if (!data || data.type !== 'authorization_response') return

      cleanup()

      const resp = data.response
      if (resp.error) {
        // Map the authorize-endpoint error code to a typed exception so
        // the recovery layer can classify it. login_required /
        // consent_required / interaction_required all mean "session is
        // gone", which is a subclass of OAuthProtocolError -- see
        // token-recovery.ts.
        const code = resp.error
        if (
          code === "login_required" ||
          code === "consent_required" ||
          code === "interaction_required"
        ) {
          reject(new LoginRequiredError(resp.error_description || code))
        } else {
          reject(new OAuthProtocolError(code, resp.error_description))
        }
        return
      }

      if (!resp.code || !resp.state) {
        reject(new Error('missing code or state in authorization response'))
        return
      }

      if (resp.state !== state) {
        reject(new Error('state mismatch'))
        return
      }

      resolve({ code: resp.code, state: resp.state, codeVerifier: verifier })
    }

    window.addEventListener('message', onMessage)

    // Timeout.
    timer = setTimeout(() => {
      cleanup()
      reject(new Error('silent renew timed out'))
    }, timeout)

    // Create hidden iframe.
    iframe = document.createElement('iframe')
    iframe.style.display = 'none'
    iframe.setAttribute('aria-hidden', 'true')
    iframe.src = authorizeUrl
    document.body.appendChild(iframe)
  })
}

/**
 * silentAuthorize with bounded retry on transient errors (default 3
 * attempts). `login_required` and similar
 * re-auth errors are fatal and bypass the retry loop.
 */
export async function silentAuthorizeWithRetry(
  opts: SilentRenewOptions,
  retries: number = DEFAULT_SILENT_RENEW_RETRY_COUNT,
): Promise<{ code: string; state: string; codeVerifier: string }> {
  let lastErr: unknown
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      return await silentAuthorize(opts)
    } catch (err) {
      lastErr = err
      if (err instanceof LoginRequiredError) throw err
      // Exponential-ish backoff: 200ms, 400ms, 800ms. Cheap to wait; prevents
      // hammering the authorize endpoint when the network is flapping.
      if (attempt < retries - 1) {
        await new Promise((r) => setTimeout(r, 200 * 2 ** attempt))
      }
    }
  }
  throw lastErr instanceof Error
    ? lastErr
    : new Error("silent renew failed after retries")
}

/** Shape of a successful /auth/token response. */
export interface TokenResponse {
  access_token: string
  id_token?: string
  refresh_token?: string
  token_type: string
  expires_in: number
  scope?: string
}

/**
 * Optional per-request DPoP signer. When provided, token-endpoint calls
 * attach a signed proof header (RFC 9449). When omitted, calls run Bearer-
 * only and the server issues un-bound tokens. The provider wires this
 * through from its DPoPKeyManager when `useDPoP: true`.
 */
export interface DPoPSigner {
  signProof(method: string, url: string, options?: DPoPProofOptions): Promise<string>
}

/**
 * POST to the token endpoint with an optional DPoP proof, transparently
 * handling the RFC 9449 §8 server-nonce challenge: if the server replies
 * `use_dpop_nonce` with a `DPoP-Nonce` header, re-sign the proof with the
 * nonce and retry once. Fetch rejections are wrapped as NetworkError.
 */
async function tokenEndpointPost(
  url: string,
  body: string,
  op: string,
  dpop?: DPoPSigner,
): Promise<Response> {
  const send = async (nonce?: string): Promise<Response> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }
    if (dpop) {
      headers['DPoP'] = await dpop.signProof('POST', url, nonce ? { nonce } : undefined)
    }
    try {
      return await fetch(url, { method: 'POST', headers, body })
    } catch (err) {
      throw new NetworkError(`${op} network error`, err)
    }
  }

  let resp = await send()
  if (dpop && (resp.status === 400 || resp.status === 401)) {
    const nonce = resp.headers.get('DPoP-Nonce')
    if (nonce && (await isUseDpopNonce(resp))) {
      resp = await send(nonce)
    }
  }
  return resp
}

/** Whether a non-2xx token response is the RFC 9449 nonce challenge. */
async function isUseDpopNonce(resp: Response): Promise<boolean> {
  const text = await resp.clone().text().catch(() => '')
  if (!text) return false
  try {
    return (JSON.parse(text) as { error?: string }).error === 'use_dpop_nonce'
  } catch {
    return false
  }
}

/**
 * Exchange an authorization code for tokens via the token endpoint.
 */
export async function exchangeCode(
  authority: string,
  clientId: string,
  code: string,
  redirectUri: string,
  codeVerifier: string,
  dpop?: DPoPSigner,
): Promise<TokenResponse> {
  const url = `${authority}/auth/token`
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  }).toString()

  const resp = await tokenEndpointPost(url, body, 'token exchange', dpop)
  if (!resp.ok) {
    throw await oauthErrorFromResponse(resp, 'token exchange')
  }

  return resp.json()
}

/**
 * Renew tokens using a refresh token grant (RFC 6749 §6). This is the
 * `useRefreshTokens: true` path -- a direct POST to the token
 * endpoint, no iframe, no cross-site cookies. Works under Chrome's third-
 * party cookie phaseout, Safari ITP, and Firefox ETP without the user
 * needing to grant Storage Access.
 *
 * The server may rotate the refresh token on each use (RFC 6749 §10.4);
 * callers must read `refresh_token` from the response and replace their
 * stored copy before the next renew.
 *
 * An expired or revoked refresh token surfaces as `LoginRequiredError` so
 * the caller can force a re-auth, matching the semantics of the iframe
 * path for login_required.
 */
export async function refreshTokenGrant(
  authority: string,
  clientId: string,
  refreshToken: string,
  scope?: string,
  audience?: string,
  dpop?: DPoPSigner,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: clientId,
    refresh_token: refreshToken,
  })
  if (scope) body.set('scope', scope)
  if (audience) body.set('audience', audience)

  const url = `${authority}/auth/token`
  const resp = await tokenEndpointPost(url, body.toString(), 'refresh token grant', dpop)
  if (!resp.ok) {
    throw await oauthErrorFromResponse(resp, 'refresh token grant')
  }

  return resp.json()
}

/**
 * Revoke a token via the RFC 7009 revocation endpoint. Used on logout to
 * proactively invalidate the refresh token server-side rather than waiting
 * for it to expire. A best-effort call: revocation failures are surfaced
 * to the caller, which typically swallows them (the RP-initiated logout
 * still kills the session cookie).
 *
 * `tokenTypeHint` defaults to `refresh_token` -- the token most worth
 * revoking, since it can mint new access tokens.
 */
export async function revokeToken(
  authority: string,
  clientId: string,
  token: string,
  tokenTypeHint: 'refresh_token' | 'access_token' = 'refresh_token',
): Promise<void> {
  const url = `${authority}/auth/revoke`
  const body = new URLSearchParams({
    client_id: clientId,
    token,
    token_type_hint: tokenTypeHint,
  }).toString()

  let resp: Response
  try {
    resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
  } catch (err) {
    throw new NetworkError('token revocation network error', err)
  }
  // RFC 7009 §2.2: the server responds 200 even for an unknown token. A
  // non-2xx is a real server-side failure worth surfacing.
  if (!resp.ok) {
    throw new Error(`token revocation failed: HTTP ${resp.status}`)
  }
}

/**
 * Turn a non-2xx /auth/token response into the typed exception the
 * recovery layer expects. The OAuth error body is parsed; if the code
 * falls into the re-auth bucket we surface a LoginRequiredError so both
 * old and new classification paths agree. 5xx with no parseable body
 * becomes an OAuthProtocolError("server_error", ...) so backoff kicks
 * in instead of forcing a sign-out.
 */
async function oauthErrorFromResponse(resp: Response, op: string): Promise<Error> {
  const text = await resp.text().catch(() => '')
  let code = ''
  let description: string | undefined
  if (text) {
    try {
      const parsed = JSON.parse(text) as { error?: string; error_description?: string }
      code = parsed.error ?? ''
      description = parsed.error_description
    } catch {
      // Non-JSON body; leave code blank so the status-based fallback fires.
    }
  }
  // 429 Too Many Requests -- the endpoint is throttling us, not refusing
  // the credential. Treat as transient so the backoff path retries rather
  // than forcing an unnecessary sign-out under load.
  if (resp.status === 429) {
    return new OAuthProtocolError(
      'temporarily_unavailable',
      `${op} rate limited (429)`,
    )
  }
  if (!code) {
    // 5xx without a structured body -- treat as transient.
    if (resp.status >= 500) {
      return new OAuthProtocolError(
        'server_error',
        `${op} failed: ${resp.status} ${text.slice(0, 200)}`,
      )
    }
    // Other non-2xx without a code -- surface the raw response.
    return new Error(`${op} failed: ${resp.status} ${text.slice(0, 200)}`)
  }
  if (
    code === 'login_required' ||
    code === 'consent_required' ||
    code === 'interaction_required'
  ) {
    return new LoginRequiredError(description ?? code)
  }
  return new OAuthProtocolError(code, description)
}

// --- PKCE helpers ---

function generateRandomString(length: number): string {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('')
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return bytesToBase64Url(array)
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return bytesToBase64Url(new Uint8Array(digest))
}
