import {
  hasExactMembers,
  parseUniqueFlatJSONObject,
} from './strict-json'
import {
  AuthorizationCodeExchangeUncertainError,
  closedOAuthProtocolErrorCode,
  type OAuthProtocolErrorCode,
} from './token-recovery'

export interface TokenResponse {
  access_token: string
  id_token?: string
  refresh_token?: string
  token_type: string
  expires_in: number
  scope?: string
}

const MAX_TOKEN_RESPONSE_BYTES = 32 * 1024
export const MAX_OAUTH_ERROR_RESPONSE_BYTES = 4 * 1024
const MAX_TOKEN_VALUE_LENGTH = 32 * 1024
const MAX_TOKEN_SCOPE_LENGTH = 512
const MAX_TOKEN_LIFETIME_SECONDS = 86_400
const MAX_ERROR_DESCRIPTION_LENGTH = 512
const MAX_ERROR_URI_LENGTH = 2_048

class MalformedTokenResponseError extends Error {
  constructor() {
    super('token endpoint returned an invalid success response')
    this.name = 'MalformedTokenResponseError'
  }
}

function forgetRecord(
  value: Record<string, unknown> | undefined,
): void {
  if (!value) return
  for (const name of Object.keys(value)) {
    value[name] = undefined
    delete value[name]
  }
}

export async function readBoundedResponseBody(
  response: Response,
  maximumBytes: number,
  signal: AbortSignal | undefined,
  label: string,
): Promise<string> {
  const declaredLength = response.headers.get('Content-Length')
  if (
    declaredLength !== null &&
    (!/^(?:0|[1-9][0-9]*)$/.test(declaredLength) ||
      !Number.isSafeInteger(Number(declaredLength)) ||
      Number(declaredLength) > maximumBytes)
  ) {
    throw new Error('token endpoint response body exceeds the limit')
  }

  if (!response.body) {
    const text = await waitForTokenTransport(
      response.text(),
      signal,
      label,
    )
    const encoded = new TextEncoder().encode(text)
    try {
      if (encoded.byteLength > maximumBytes) {
        throw new Error(
          'token endpoint response body exceeds the limit',
        )
      }
      return text
    } finally {
      encoded.fill(0)
    }
  }

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  let combined: Uint8Array | undefined
  try {
    for (;;) {
      let chunk: ReadableStreamReadResult<Uint8Array>
      try {
        chunk = await waitForTokenTransport(
          reader.read(),
          signal,
          label,
        )
      } catch (error) {
        void reader.cancel().catch(() => undefined)
        throw error
      }
      if (chunk.done) break
      total += chunk.value.byteLength
      if (total > maximumBytes) {
        void reader.cancel().catch(() => undefined)
        throw new Error(
          'token endpoint response body exceeds the limit',
        )
      }
      // Keep ownership of the memory we later clear. A stream producer, or
      // the sibling branch created by Response.clone(), may retain its chunk.
      chunks.push(chunk.value.slice())
    }

    combined = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
      combined.set(chunk, offset)
      offset += chunk.byteLength
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(
      combined,
    )
  } finally {
    combined?.fill(0)
    for (const chunk of chunks) chunk.fill(0)
    try {
      reader.releaseLock()
    } catch {
      // A cancelled pending read releases its lock asynchronously.
    }
  }
}

function validTokenString(
  value: unknown,
  maximumLength = MAX_TOKEN_VALUE_LENGTH,
): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maximumLength
  )
}

function validatedTokenResponseText(
  text: string,
  expectDPoP: boolean,
): TokenResponse {
  let response: Record<string, unknown> | undefined
  try {
    response = parseUniqueFlatJSONObject(
      text,
      MAX_TOKEN_RESPONSE_BYTES,
    )
    const accessToken = response.access_token
    const tokenType = response.token_type
    const expiresIn = response.expires_in
    const idToken = response.id_token
    const refreshToken = response.refresh_token
    const scope = response.scope
    if (
      !hasExactMembers(
        response,
        ['access_token', 'token_type', 'expires_in'],
        ['id_token', 'refresh_token', 'scope'],
      ) ||
      !validTokenString(accessToken) ||
      typeof tokenType !== 'string' ||
      (expectDPoP
        ? tokenType !== 'DPoP'
        : tokenType !== 'Bearer' &&
          tokenType !== 'bearer') ||
      typeof expiresIn !== 'number' ||
      !Number.isSafeInteger(expiresIn) ||
      expiresIn < 1 ||
      expiresIn > MAX_TOKEN_LIFETIME_SECONDS
    ) {
      throw new MalformedTokenResponseError()
    }
    if (
      idToken !== undefined &&
      !validTokenString(idToken)
    ) {
      throw new MalformedTokenResponseError()
    }
    if (
      refreshToken !== undefined &&
      !validTokenString(refreshToken)
    ) {
      throw new MalformedTokenResponseError()
    }
    if (
      scope !== undefined &&
      !validTokenString(scope, MAX_TOKEN_SCOPE_LENGTH)
    ) {
      throw new MalformedTokenResponseError()
    }

    const tokens: TokenResponse = {
      access_token: accessToken,
      token_type: tokenType,
      expires_in: expiresIn,
    }
    if (idToken !== undefined) {
      tokens.id_token = idToken
    }
    if (refreshToken !== undefined) {
      tokens.refresh_token = refreshToken
    }
    if (scope !== undefined) {
      tokens.scope = scope
    }
    return tokens
  } catch (error) {
    if (error instanceof MalformedTokenResponseError) {
      throw error
    }
    throw new MalformedTokenResponseError()
  } finally {
    forgetRecord(response)
  }
}

export async function validatedTokenResponse(
  response: Response,
  expectDPoP: boolean,
  signal?: AbortSignal,
): Promise<TokenResponse> {
  let text = ''
  try {
    text = await readBoundedResponseBody(
      response,
      MAX_TOKEN_RESPONSE_BYTES,
      signal,
      'token endpoint success response',
    )
    return validatedTokenResponseText(text, expectDPoP)
  } finally {
    text = ''
  }
}

export function oauthErrorCodeFromText(
  text: string,
): OAuthProtocolErrorCode | undefined {
  let response: Record<string, unknown> | undefined
  try {
    response = parseUniqueFlatJSONObject(
      text,
      MAX_OAUTH_ERROR_RESPONSE_BYTES,
    )
    if (
      !hasExactMembers(
        response,
        ['error'],
        ['error_description', 'error_uri'],
      ) ||
      typeof response.error !== 'string' ||
      response.error.length === 0 ||
      response.error.length > 64 ||
      (response.error_description !== undefined &&
        (typeof response.error_description !== 'string' ||
          response.error_description.length >
            MAX_ERROR_DESCRIPTION_LENGTH)) ||
      (response.error_uri !== undefined &&
        (typeof response.error_uri !== 'string' ||
          response.error_uri.length === 0 ||
          response.error_uri.length > MAX_ERROR_URI_LENGTH))
    ) {
      return undefined
    }
    return closedOAuthProtocolErrorCode(response.error)
  } catch {
    return undefined
  } finally {
    forgetRecord(response)
  }
}

export function waitForTokenTransport<T>(
  operation: Promise<T>,
  signal: AbortSignal | undefined,
  label: string,
): Promise<T> {
  if (!signal) return operation
  if (signal.aborted) {
    return Promise.reject(
      new AuthorizationCodeExchangeUncertainError(
        `${label} deadline expired`,
      ),
    )
  }
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (
      result:
        | { ok: true; value: T }
        | { ok: false; error: unknown },
    ): void => {
      if (settled) return
      settled = true
      signal.removeEventListener('abort', onAbort)
      if (result.ok) resolve(result.value)
      else reject(result.error)
    }
    const onAbort = (): void =>
      finish({
        ok: false,
        error: new AuthorizationCodeExchangeUncertainError(
          `${label} deadline expired`,
        ),
      })
    signal.addEventListener('abort', onAbort, { once: true })
    void operation.then(
      (value) => finish({ ok: true, value }),
      (error) => finish({ ok: false, error }),
    )
  })
}
