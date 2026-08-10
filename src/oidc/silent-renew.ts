/**
 * Silent token renewal transport for a PAR-admitted web_message URL.
 *
 * The caller owns PAR admission and callback custody. This module validates
 * and navigates only the resulting client_id + request_uri envelope.
 *
 * Spec: draft-sakimura-oauth-wmrm-01
 */

import { NetworkError } from './token-recovery'
import {
  potentiallyTrustworthyEndpoint,
  REQUEST_URI_PREFIX,
  validCanonicalSHA256,
} from './ordinary-authorization-model'

export { LoginRequiredError } from './token-recovery'
export {
  exchangeCode,
  parseDPoPNonceHeader,
  refreshTokenGrant,
  rememberTokenEndpointDPoPNonce,
  revokeToken,
} from './token-endpoint'
export type {
  DPoPSigner,
  TokenResponse,
} from './token-endpoint'

interface AuthorizationResponse {
  type: 'authorization_response'
  response: {
    code?: string
    state?: string
    error?: string
  }
}

export interface SilentAuthorizeURLOptions {
  authority: string
  clientId: string
  admittedAuthorizationUrl: string
  expectedState?: string
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

export interface SilentAuthorizationResponse {
  code?: string
  state: string
  error?: string
  codeVerifier?: string
  nonce?: string
}

/** Generate one cryptographically random nonce for an OIDC authorization. */
export function generateAuthorizationNonce(): string {
  return generateRandomString(32)
}

/**
 * Navigate one already-admitted authorization URL in a hidden iframe and
 * receive its web_message response. Admission, PKCE state, and callback
 * custody remain the caller's responsibility.
 */
export function silentAuthorizeURL(
  opts: SilentAuthorizeURLOptions,
): Promise<SilentAuthorizationResponse> {
  const authorizationUrl = admittedSilentAuthorizationURL(opts)
  const expectedOrigin = new URL(opts.authority).origin
  const timeout =
    opts.timeoutMs ?? DEFAULT_AUTHORIZE_TIMEOUT_MS
  return new Promise<SilentAuthorizationResponse>((resolve, reject) => {
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
      if (event.origin !== expectedOrigin) return
      if (!iframe || event.source !== iframe.contentWindow) return

      const data = event.data as AuthorizationResponse
      if (!data || data.type !== 'authorization_response') return
      const response = data.response
      if (!response?.state) {
        cleanup()
        reject(new Error('missing state in authorization response'))
        return
      }
      if (
        opts.expectedState !== undefined &&
        response.state !== opts.expectedState
      ) {
        cleanup()
        reject(new Error('state mismatch'))
        return
      }

      cleanup()
      resolve({
        state: response.state,
        ...(response.code ? { code: response.code } : {}),
        ...(response.error ? { error: response.error } : {}),
      })
    }

    window.addEventListener('message', onMessage)
    timer = setTimeout(() => {
      cleanup()
      reject(new NetworkError('silent renew timed out'))
    }, timeout)

    iframe = document.createElement('iframe')
    iframe.style.display = 'none'
    iframe.setAttribute('aria-hidden', 'true')
    iframe.referrerPolicy = 'no-referrer'
    iframe.src = authorizationUrl
    document.body.appendChild(iframe)
  })
}

function admittedSilentAuthorizationURL(
  opts: SilentAuthorizeURLOptions,
): string {
  let authority: URL
  let authorization: URL
  try {
    authority = new URL(opts.authority)
    authorization = new URL(opts.admittedAuthorizationUrl)
    potentiallyTrustworthyEndpoint(
      authority.origin,
      authority.origin,
      'issuer',
    )
  } catch {
    throw new Error(
      'silent authorization: admitted PAR navigation URL is invalid',
    )
  }
  if (
    (authority.protocol !== 'https:' &&
      authority.protocol !== 'http:') ||
    authority.username !== '' ||
    authority.password !== '' ||
    authority.pathname !== '/' ||
    authority.search !== '' ||
    authority.hash !== '' ||
    authorization.origin !== authority.origin ||
    authorization.pathname !== '/auth/authorize' ||
    authorization.username !== '' ||
    authorization.password !== '' ||
    authorization.hash !== ''
  ) {
    throw new Error(
      'silent authorization: admitted PAR navigation URL is invalid',
    )
  }
  const entries = Array.from(authorization.searchParams)
  if (
    entries.length !== 2 ||
    authorization.searchParams.getAll('client_id').length !== 1 ||
    authorization.searchParams.get('client_id') !== opts.clientId ||
    authorization.searchParams.getAll('request_uri').length !== 1
  ) {
    throw new Error(
      'silent authorization: admitted PAR navigation URL is invalid',
    )
  }
  const names = new Set(entries.map(([name]) => name))
  const requestUri = authorization.searchParams.get('request_uri')
  if (
    names.size !== 2 ||
    !names.has('client_id') ||
    !names.has('request_uri') ||
    requestUri === null ||
    !requestUri.startsWith(REQUEST_URI_PREFIX) ||
    !validCanonicalSHA256(
      requestUri.slice(REQUEST_URI_PREFIX.length),
    )
  ) {
    throw new Error(
      'silent authorization: admitted PAR navigation URL is invalid',
    )
  }
  return authorization.href
}

function generateRandomString(length: number): string {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('')
}
