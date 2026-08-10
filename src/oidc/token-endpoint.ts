import type { DPoPProofOptions } from '../dpop/dpop'
import {
  MAX_OAUTH_ERROR_RESPONSE_BYTES,
  oauthErrorCodeFromText,
  readBoundedResponseBody,
  validatedTokenResponse,
  waitForTokenTransport,
  type TokenResponse,
} from './token-endpoint-response'
import {
  AuthorizationCodeExchangeUncertainError,
  LoginRequiredError,
  NetworkError,
  OAuthProtocolError,
} from './token-recovery'

export type { TokenResponse } from './token-endpoint-response'

export interface DPoPSigner {
  signProof(
    method: string,
    url: string,
    options?: DPoPProofOptions,
  ): Promise<string>
}

const dpopServerNonces = new WeakMap<
  DPoPSigner,
  Map<string, string>
>()
const DPOP_NONCE_MAX_LENGTH = 512
const CANONICAL_DPOP_NONCE =
  /^[\x21\x23-\x2B\x2D-\x5B\x5D-\x7E]+$/

function rememberedDPoPNonce(
  dpop: DPoPSigner,
  url: string,
): string | undefined {
  return dpopServerNonces.get(dpop)?.get(url)
}

function canonicalDPoPNonce(value: string): string {
  if (
    value.length === 0 ||
    value.length > DPOP_NONCE_MAX_LENGTH ||
    !CANONICAL_DPOP_NONCE.test(value)
  ) {
    throw new Error('DPoP: server nonce header is invalid')
  }
  return value
}

export function parseDPoPNonceHeader(
  headers: Pick<Headers, 'get'>,
): string | undefined {
  const value = headers.get('DPoP-Nonce')
  return value === null
    ? undefined
    : canonicalDPoPNonce(value)
}

function storeDPoPNonce(
  dpop: DPoPSigner,
  url: string,
  nonce: string,
): void {
  let byURL = dpopServerNonces.get(dpop)
  if (!byURL) {
    byURL = new Map()
    dpopServerNonces.set(dpop, byURL)
  }
  byURL.set(url, nonce)
}

export function rememberTokenEndpointDPoPNonce(
  dpop: DPoPSigner,
  url: string,
  nonce: string,
): void {
  storeDPoPNonce(dpop, url, canonicalDPoPNonce(nonce))
}

async function tokenEndpointPost(
  url: string,
  body: string,
  op: string,
  dpop?: DPoPSigner,
  signal?: AbortSignal,
  authorizationCodeDispatched = false,
): Promise<Response> {
  const send = async (
    nonce?: string,
  ): Promise<{
    response: Response
    responseNonce?: string
  }> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }
    if (dpop) {
      const effectiveNonce =
        nonce ?? rememberedDPoPNonce(dpop, url)
      try {
        headers.DPoP = await waitForTokenTransport(
          dpop.signProof(
            'POST',
            url,
            effectiveNonce
              ? { nonce: effectiveNonce }
              : undefined,
          ),
          signal,
          `${op} DPoP proof`,
        )
      } catch {
        throw new Error(`${op} DPoP proof could not be created`)
      }
    }
    let response: Response
    try {
      response = await waitForTokenTransport(
        fetch(url, {
          method: 'POST',
          headers,
          body,
          signal,
        }),
        signal,
        op,
      )
    } catch {
      if (authorizationCodeDispatched) {
        throw new AuthorizationCodeExchangeUncertainError(
          `${op} response is incomplete`,
        )
      }
      throw new NetworkError(`${op} network error`)
    }
    let responseNonce: string | undefined
    try {
      responseNonce = dpop
        ? parseDPoPNonceHeader(response.headers)
        : undefined
    } catch {
      if (authorizationCodeDispatched) {
        throw new AuthorizationCodeExchangeUncertainError(
          `${op} response is incomplete`,
        )
      }
      throw new OAuthProtocolError('invalid_response')
    }
    if (dpop && responseNonce !== undefined) {
      storeDPoPNonce(dpop, url, responseNonce)
    }
    return { response, responseNonce }
  }

  let result = await send()
  if (
    dpop &&
    result.responseNonce !== undefined &&
    (result.response.status === 400 ||
      result.response.status === 401) &&
    (await isUseDpopNonce(result.response, signal))
  ) {
    result = await send(result.responseNonce)
  }
  return result.response
}

async function isUseDpopNonce(
  response: Response,
  signal?: AbortSignal,
): Promise<boolean> {
  let text = ''
  try {
    text = await readBoundedResponseBody(
      response.clone(),
      MAX_OAUTH_ERROR_RESPONSE_BYTES,
      signal,
      'DPoP nonce response',
    )
    return (
      oauthErrorCodeFromText(text) === 'use_dpop_nonce'
    )
  } catch {
    return false
  } finally {
    text = ''
  }
}

export async function exchangeCode(
  authority: string,
  clientId: string,
  code: string,
  redirectUri: string,
  codeVerifier: string,
  dpop?: DPoPSigner,
  options?: { signal?: AbortSignal },
): Promise<TokenResponse> {
  const url = `${authority}/auth/token`
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  }).toString()

  const response = await tokenEndpointPost(
    url,
    body,
    'token exchange',
    dpop,
    options?.signal,
    true,
  )
  if (!response.ok) {
    throw await oauthErrorFromResponse(
      response,
      'token exchange',
      options?.signal,
      true,
    )
  }

  try {
    return await validatedTokenResponse(
      response,
      dpop !== undefined,
      options?.signal,
    )
  } catch (error) {
    if (
      error instanceof
      AuthorizationCodeExchangeUncertainError
    ) {
      throw error
    }
    throw new AuthorizationCodeExchangeUncertainError(
      'token exchange response is incomplete',
    )
  }
}

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
  const response = await tokenEndpointPost(
    url,
    body.toString(),
    'refresh token grant',
    dpop,
  )
  if (!response.ok) {
    throw await oauthErrorFromResponse(
      response,
      'refresh token grant',
    )
  }
  try {
    return await validatedTokenResponse(
      response,
      dpop !== undefined,
    )
  } catch {
    throw new OAuthProtocolError('invalid_response')
  }
}

export async function revokeToken(
  authority: string,
  clientId: string,
  token: string,
  tokenTypeHint: 'refresh_token' | 'access_token' =
    'refresh_token',
): Promise<void> {
  const url = `${authority}/auth/revoke`
  const body = new URLSearchParams({
    client_id: clientId,
    token,
    token_type_hint: tokenTypeHint,
  }).toString()

  let response: Response
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    })
  } catch {
    throw new NetworkError('token revocation network error')
  }
  if (!response.ok) {
    throw new Error(
      `token revocation failed: HTTP ${response.status}`,
    )
  }
}

async function oauthErrorFromResponse(
  response: Response,
  op: string,
  signal?: AbortSignal,
  authorizationCodeDispatched = false,
): Promise<Error> {
  let text = ''
  try {
    text = await readBoundedResponseBody(
      response,
      MAX_OAUTH_ERROR_RESPONSE_BYTES,
      signal,
      `${op} response`,
    )
  } catch {
    if (authorizationCodeDispatched) {
      throw new AuthorizationCodeExchangeUncertainError(
        `${op} response is incomplete`,
      )
    }
  }
  try {
    if (response.status === 429) {
      return new OAuthProtocolError('temporarily_unavailable')
    }
    const code = text
      ? oauthErrorCodeFromText(text)
      : undefined
    if (code === undefined) {
      return new OAuthProtocolError(
        response.status >= 500
          ? 'server_error'
          : 'invalid_response',
      )
    }
    if (
      code === 'login_required' ||
      code === 'consent_required' ||
      code === 'interaction_required' ||
      code === 'account_selection_required'
    ) {
      return new LoginRequiredError()
    }
    return new OAuthProtocolError(code)
  } finally {
    text = ''
  }
}
