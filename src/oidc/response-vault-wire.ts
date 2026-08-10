import {
  LoginRequiredError,
  NetworkError,
  OAuthProtocolError,
} from './token-recovery'
import type { TokenResponse } from './silent-renew'
import {
  base64ToBytes,
  bytesToBase64Url,
} from '../crypto/base64url'
import {
  hasExactMembers,
  parseUniqueFlatJSONObject,
  parseUniqueJSONObject,
} from './strict-json'
import {
  BOOTSTRAP_MAX_LIFETIME_SECONDS,
  CANONICAL_OPAQUE,
  REQUEST_URI_MAX_LIFETIME_SECONDS,
  RESPONSE_VAULT_PROTOCOL_VERSION,
  TRANSACTION_MAX_LIFETIME_SECONDS,
  type BootstrapAttemptChallenge,
  type BootstrapResponse,
  type IssuerBootstrapResponse,
  type PushedAuthorizationResponse,
  type RelaySuccess,
} from './response-vault-contract'
import { validResponseVaultTerminalProof } from './response-vault-storage'
import { rfc3339NanoNanoseconds } from './rfc3339-nano'

function jsonContentType(response: Response): boolean {
  const value = response.headers.get('Content-Type')
  return (
    value === 'application/json' ||
    value === 'application/json; charset=utf-8'
  )
}

async function parseResponseEnvelope(
  response: Response,
  parser: (input: string) => Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!jsonContentType(response)) {
    throw new Error('response vault: response content type is invalid')
  }
  let body: string
  try {
    body = await response.text()
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === 'response vault: response body exceeds the limit'
    ) {
      throw error
    }
    throw new NetworkError(
      'response vault: response body transport failed',
      error,
    )
  }
  return parser(body)
}

export async function responseEnvelope(
  response: Response,
): Promise<Record<string, unknown>> {
  return parseResponseEnvelope(response, parseUniqueFlatJSONObject)
}

export async function discoveryEnvelope(
  response: Response,
): Promise<Record<string, unknown>> {
  return parseResponseEnvelope(response, parseUniqueJSONObject)
}

function expectInteger(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new Error(`response vault: ${name} is invalid`)
  }
  return value
}

function expectString(
  value: unknown,
  name: string,
  maximum: number,
): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximum
  ) {
    throw new Error(`response vault: ${name} is invalid`)
  }
  return value
}

function expectTerminalProof(value: unknown, name: string): string {
  if (!validResponseVaultTerminalProof(value)) {
    throw new Error(`response vault: ${name} is invalid`)
  }
  return value
}

export function protocolError(
  status: number,
  envelope: Record<string, unknown>,
  operation: string,
): Error {
  if (!hasExactMembers(envelope, ['error'])) {
    return new Error(`response vault: ${operation} returned a malformed error`)
  }
  const code = envelope.error
  if (typeof code !== 'string' || code.length === 0 || code.length > 64) {
    return new Error(`response vault: ${operation} returned a malformed error`)
  }
  if (status === 503 && code === 'unavailable') {
    return new OAuthProtocolError(
      'temporarily_unavailable',
      `response vault: ${operation} is unavailable`,
    )
  }
  if (status === 409 && code === 'busy') {
    return new OAuthProtocolError(
      'temporarily_unavailable',
      'response vault: another browser authorization is active',
    )
  }
  return new OAuthProtocolError(code, `response vault: ${operation} failed`)
}

export function isAuthenticatedTerminalResponse(
  response: Response,
  envelope: Record<string, unknown>,
): boolean {
  return (
    response.status === 410 &&
    response.headers.get('Cache-Control') === 'no-store' &&
    hasExactMembers(envelope, ['error']) &&
    envelope.error === 'authorization_terminal'
  )
}

export function isAuthenticatedNonterminalResponse(
  response: Response,
  envelope: Record<string, unknown>,
): boolean {
  return (
    response.status === 409 &&
    response.headers.get('Cache-Control') === 'no-store' &&
    hasExactMembers(envelope, ['error']) &&
    envelope.error === 'authorization_nonterminal'
  )
}

export async function expectProtocolResponse(
  response: Response,
  status: number,
  operation: string,
): Promise<Record<string, unknown>> {
  const envelope = await responseEnvelope(response)
  if (response.status !== status) {
    throw protocolError(response.status, envelope, operation)
  }
  return envelope
}

function responseDeadline(
  requestStartedAt: number,
  expiresIn: number,
  operation: string,
): number {
  const deadline = requestStartedAt + expiresIn * 1000
  if (
    !Number.isSafeInteger(requestStartedAt) ||
    requestStartedAt < 0 ||
    !Number.isSafeInteger(deadline)
  ) {
    throw new Error(`response vault: ${operation} deadline is invalid`)
  }
  return deadline
}

export function bootstrapResponse(
  envelope: Record<string, unknown>,
  requestStartedAt: number,
): BootstrapResponse {
  if (
    !hasExactMembers(envelope, [
      'version',
      'csrf_token',
      'bootstrap_terminal_proof',
      'expires_in',
    ]) ||
    envelope.version !== RESPONSE_VAULT_PROTOCOL_VERSION ||
    typeof envelope.csrf_token !== 'string' ||
    !CANONICAL_OPAQUE.test(envelope.csrf_token)
  ) {
    throw new Error('response vault: bootstrap response is invalid')
  }
  const expiresIn = expectInteger(
    envelope.expires_in,
    'bootstrap expiry',
    1,
    BOOTSTRAP_MAX_LIFETIME_SECONDS,
  )
  const bootstrapExpiresAt = responseDeadline(
    requestStartedAt,
    expiresIn,
    'bootstrap',
  )
  if (bootstrapExpiresAt <= Date.now()) {
    throw new Error('response vault: invalid bootstrap response')
  }
  return {
    csrfToken: envelope.csrf_token,
    bootstrapTerminalProof: expectTerminalProof(
      envelope.bootstrap_terminal_proof,
      'bootstrap terminal proof',
    ),
    bootstrapExpiresAt,
  }
}

export function bootstrapAttemptChallenge(
  envelope: Record<string, unknown>,
  requestStartedAt: number,
): BootstrapAttemptChallenge {
  if (
    !hasExactMembers(envelope, [
      'error',
      'attempt_capability',
      'expires_in',
      'attempt_expires_at',
    ]) ||
    envelope.error !== 'attempt_capability_required' ||
    typeof envelope.attempt_expires_at !== 'string'
  ) {
    throw new Error(
      'response vault: bootstrap attempt challenge is invalid',
    )
  }
  const capability = expectTerminalProof(
    envelope.attempt_capability,
    'bootstrap attempt capability',
  )
  const expiresIn = expectInteger(
    envelope.expires_in,
    'bootstrap attempt expiry',
    2,
    BOOTSTRAP_MAX_LIFETIME_SECONDS,
  )
  try {
    const raw = base64ToBytes(capability)
    if (
      bytesToBase64Url(raw) !== capability ||
      raw[0] !== 1 ||
      raw[1] !== 3
    ) {
      throw new Error()
    }
    let proofDeadline = 0n
    for (let index = 18; index < 26; index++) {
      proofDeadline = (proofDeadline << 8n) | BigInt(raw[index])
    }
    if (
      proofDeadline <= 0n ||
      proofDeadline !==
        rfc3339NanoNanoseconds(envelope.attempt_expires_at)
    ) {
      throw new Error()
    }
  } catch {
    throw new Error(
      'response vault: bootstrap attempt capability is invalid',
    )
  }
  const attemptExpiresAt =
    requestStartedAt + (expiresIn - 1) * 1000
  if (
    !Number.isSafeInteger(requestStartedAt) ||
    requestStartedAt < 0 ||
    !Number.isSafeInteger(attemptExpiresAt)
  ) {
    throw new Error(
      'response vault: bootstrap attempt deadline is invalid',
    )
  }
  return { attemptCapability: capability, attemptExpiresAt }
}

export function issuerBootstrapResponse(
  envelope: Record<string, unknown>,
  requestStartedAt: number,
): IssuerBootstrapResponse {
  if (
    !hasExactMembers(envelope, ['version', 'csrf_token', 'expires_in']) ||
    envelope.version !== RESPONSE_VAULT_PROTOCOL_VERSION ||
    typeof envelope.csrf_token !== 'string' ||
    !CANONICAL_OPAQUE.test(envelope.csrf_token)
  ) {
    throw new Error('response vault: issuer bootstrap response is invalid')
  }
  const expiresIn = expectInteger(
    envelope.expires_in,
    'issuer bootstrap expiry',
    1,
    BOOTSTRAP_MAX_LIFETIME_SECONDS,
  )
  const bootstrapExpiresAt = responseDeadline(
    requestStartedAt,
    expiresIn,
    'issuer bootstrap',
  )
  if (bootstrapExpiresAt <= Date.now()) {
    throw new Error('response vault: invalid issuer bootstrap response')
  }
  return {
    csrfToken: envelope.csrf_token,
    bootstrapExpiresAt,
  }
}

export function pushedResponse(
  envelope: Record<string, unknown>,
  requestStartedAt: number,
): PushedAuthorizationResponse {
  if (
    !hasExactMembers(envelope, [
      'version',
      'transaction_id',
      'request_uri',
      'expires_in',
      'transaction_expires_in',
      'csrf_token',
      'terminal_proof',
    ]) ||
    envelope.version !== RESPONSE_VAULT_PROTOCOL_VERSION ||
    typeof envelope.transaction_id !== 'string' ||
    !CANONICAL_OPAQUE.test(envelope.transaction_id) ||
    typeof envelope.request_uri !== 'string' ||
    !envelope.request_uri.startsWith(
      'urn:ietf:params:oauth:request_uri:',
    ) ||
    !CANONICAL_OPAQUE.test(
      envelope.request_uri.slice(
        'urn:ietf:params:oauth:request_uri:'.length,
      ),
    ) ||
    typeof envelope.csrf_token !== 'string' ||
    !CANONICAL_OPAQUE.test(envelope.csrf_token)
  ) {
    throw new Error('response vault: pushed authorization response is invalid')
  }
  const requestUriExpiresIn = expectInteger(
    envelope.expires_in,
    'pushed authorization expiry',
    0,
    REQUEST_URI_MAX_LIFETIME_SECONDS,
  )
  const transactionExpiresIn = expectInteger(
    envelope.transaction_expires_in,
    'pushed authorization transaction expiry',
    1,
    TRANSACTION_MAX_LIFETIME_SECONDS,
  )
  return {
    transactionId: envelope.transaction_id,
    requestUri: envelope.request_uri,
    csrfToken: envelope.csrf_token,
    terminalProof: expectTerminalProof(
      envelope.terminal_proof,
      'terminal proof',
    ),
    requestUriExpiresAt: responseDeadline(
      requestStartedAt,
      requestUriExpiresIn,
      'pushed authorization request URI',
    ),
    transactionExpiresAt: responseDeadline(
      requestStartedAt,
      transactionExpiresIn,
      'pushed authorization transaction',
    ),
  }
}

export function relaySuccess(
  envelope: Record<string, unknown>,
): RelaySuccess {
  if (
    !hasExactMembers(
      envelope,
      [
        'version',
        'access_token',
        'token_type',
        'expires_in',
        'scope',
        'csrf_token',
      ],
      ['refresh_token', 'id_token'],
    ) ||
    envelope.version !== RESPONSE_VAULT_PROTOCOL_VERSION ||
    envelope.token_type !== 'DPoP' ||
    typeof envelope.csrf_token !== 'string' ||
    !CANONICAL_OPAQUE.test(envelope.csrf_token)
  ) {
    throw new Error('response vault: relay token response is invalid')
  }
  const tokens: TokenResponse = {
    access_token: expectString(
      envelope.access_token,
      'access token',
      32 * 1024,
    ),
    token_type: 'DPoP',
    expires_in: expectInteger(
      envelope.expires_in,
      'token expiry',
      1,
      86_400,
    ),
    scope: expectString(envelope.scope, 'token scope', 512),
  }
  if (envelope.refresh_token !== undefined) {
    tokens.refresh_token = expectString(
      envelope.refresh_token,
      'refresh token',
      32 * 1024,
    )
  }
  if (envelope.id_token !== undefined) {
    tokens.id_token = expectString(
      envelope.id_token,
      'ID token',
      32 * 1024,
    )
  }
  return { tokens, csrfToken: envelope.csrf_token }
}

export function terminalRelayError(
  envelope: Record<string, unknown>,
): { code: string; csrfToken: string } | null {
  if (!hasExactMembers(envelope, ['version', 'error', 'csrf_token'])) {
    return null
  }
  const allowed = new Set([
    'invalid_request',
    'access_denied',
    'login_required',
    'temporarily_unavailable',
    'server_error',
  ])
  if (
    envelope.version !== RESPONSE_VAULT_PROTOCOL_VERSION ||
    typeof envelope.error !== 'string' ||
    !allowed.has(envelope.error) ||
    typeof envelope.csrf_token !== 'string' ||
    !CANONICAL_OPAQUE.test(envelope.csrf_token)
  ) {
    throw new Error('response vault: terminal relay error is invalid')
  }
  return { code: envelope.error, csrfToken: envelope.csrf_token }
}

export function relayOAuthError(code: string): Error {
  if (code === 'login_required') {
    return new LoginRequiredError('response vault: login is required')
  }
  return new OAuthProtocolError(code, `response vault: authorization ${code}`)
}
