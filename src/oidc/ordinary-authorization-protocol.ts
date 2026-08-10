import {
  base64ToBytes,
  bytesToBase64Url,
} from '../crypto/base64url'
import {
  AUTHORIZATION_CODE_LIFETIME_SECONDS,
  MAX_CEREMONY_LIFETIME_SECONDS,
  MAX_PAR_RESPONSE_BYTES,
  ORDINARY_AUTHORIZATION_PROTOCOL_VERSION,
  REQUEST_URI_PREFIX,
  TERMINAL_PROOF_BYTES,
  TERMINAL_PROOF_LENGTH,
  potentiallyTrustworthyEndpoint,
  validCanonicalAttemptCapability,
  validCanonicalSHA256,
  type OrdinaryAuthorizationBinding,
  type OrdinaryAuthorizationDiscoveryContract,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import {
  hasExactMembers,
  parseUniqueFlatJSONObject,
} from './strict-json'
import {
  rfc3339NanoMilliseconds,
  rfc3339NanoNanoseconds,
} from './rfc3339-nano'

export function ordinaryAuthorizationDiscoveryContract(
  metadata: Record<string, unknown>,
  binding: OrdinaryAuthorizationBinding,
): OrdinaryAuthorizationDiscoveryContract {
  if (metadata.issuer !== binding.issuer) {
    throw new Error(
      'ordinary browser authorization: discovered issuer is invalid',
    )
  }
  if (metadata.require_pushed_authorization_requests !== true) {
    throw new Error(
      'ordinary browser authorization: pushed authorization is not required',
    )
  }
  const browser = metadata.atol_browser_authorization
  if (
    browser === null ||
    typeof browser !== 'object' ||
    Array.isArray(browser) ||
    !hasExactMembers(
      browser as Record<string, unknown>,
      [
        'version',
        'ceremony_lifetime_seconds',
        'authorization_code_lifetime_seconds',
        'pre_navigation_cancellation_endpoint',
        'settlement_endpoint',
      ],
    )
  ) {
    throw new Error(
      'ordinary browser authorization: discovery contract is invalid',
    )
  }
  const contract = browser as Record<string, unknown>
  if (
    contract.version !== ORDINARY_AUTHORIZATION_PROTOCOL_VERSION ||
    !Number.isInteger(contract.ceremony_lifetime_seconds) ||
    (contract.ceremony_lifetime_seconds as number) <= 0 ||
    (contract.ceremony_lifetime_seconds as number) >
      MAX_CEREMONY_LIFETIME_SECONDS ||
    contract.authorization_code_lifetime_seconds !==
      AUTHORIZATION_CODE_LIFETIME_SECONDS
  ) {
    throw new Error(
      'ordinary browser authorization: discovery lifetimes are invalid',
    )
  }
  return {
    authorizationEndpoint: potentiallyTrustworthyEndpoint(
      metadata.authorization_endpoint,
      `${binding.issuer}/auth/authorize`,
      'authorization endpoint',
    ),
    pushedAuthorizationRequestEndpoint: potentiallyTrustworthyEndpoint(
      metadata.pushed_authorization_request_endpoint,
      `${binding.issuer}/auth/par`,
      'PAR endpoint',
    ),
    preNavigationCancellationEndpoint:
      potentiallyTrustworthyEndpoint(
        contract.pre_navigation_cancellation_endpoint,
        `${binding.issuer}/auth/par/pre-navigation-cancellation`,
        'pre-navigation cancellation endpoint',
      ),
    settlementEndpoint: potentiallyTrustworthyEndpoint(
      contract.settlement_endpoint,
      `${binding.issuer}/auth/par/settlement`,
      'settlement endpoint',
    ),
    protocolVersion: ORDINARY_AUTHORIZATION_PROTOCOL_VERSION,
    ceremonyLifetimeSeconds:
      contract.ceremony_lifetime_seconds as number,
    authorizationCodeLifetimeSeconds:
      AUTHORIZATION_CODE_LIFETIME_SECONDS,
  }
}

export function validOrdinaryAuthorizationTerminalProof(
  value: unknown,
  rootExpiresAt: string,
): value is string {
  if (
    typeof value !== 'string' ||
    value.length !== TERMINAL_PROOF_LENGTH
  ) {
    return false
  }
  try {
    const raw = base64ToBytes(value)
    if (
      raw.length !== TERMINAL_PROOF_BYTES ||
      bytesToBase64Url(raw) !== value ||
      raw[0] !== 1 ||
      raw[1] !== 1
    ) {
      return false
    }
    let deadline = 0n
    for (let index = 18; index < 26; index++) {
      deadline = (deadline << 8n) | BigInt(raw[index])
    }
    return (
      deadline > 0n &&
      deadline === rfc3339NanoNanoseconds(rootExpiresAt)
    )
  } catch {
    return false
  }
}

export interface OrdinaryAuthorizationAttemptChallenge {
  attemptCapability: string
  attemptExpiresAt: number
}

export function ordinaryAuthorizationAttemptCapabilityDeadline(
  value: unknown,
): bigint {
  if (!validCanonicalAttemptCapability(value)) {
    throw new Error(
      'ordinary browser authorization: attempt capability is invalid',
    )
  }
  const raw = base64ToBytes(value)
  let deadline = 0n
  for (let index = 18; index < 26; index++) {
    deadline = (deadline << 8n) | BigInt(raw[index])
  }
  if (deadline <= 0n) {
    throw new Error(
      'ordinary browser authorization: attempt capability is invalid',
    )
  }
  return deadline
}

export function ordinaryAuthorizationAttemptChallenge(
  record: OrdinaryAuthorizationRecord,
  responseText: string,
  requestStartedAt: number,
): OrdinaryAuthorizationAttemptChallenge {
  const response = parseUniqueFlatJSONObject(
    responseText,
    MAX_PAR_RESPONSE_BYTES,
  )
  if (
    !hasExactMembers(response, [
      'error',
      'attempt_capability',
      'expires_in',
      'attempt_expires_at',
    ]) ||
    response.error !== 'attempt_capability_required' ||
    !Number.isInteger(response.expires_in) ||
    (response.expires_in as number) <= 1 ||
    (response.expires_in as number) >
      record.ceremonyLifetimeSeconds ||
    typeof response.attempt_expires_at !== 'string' ||
    typeof response.attempt_capability !== 'string'
  ) {
    throw new Error(
      'ordinary browser authorization: attempt challenge is invalid',
    )
  }
  const expiresIn = response.expires_in as number
  if (
    !Number.isSafeInteger(requestStartedAt) ||
    requestStartedAt < 0
  ) {
    throw new Error(
      'ordinary browser authorization: attempt deadline is invalid',
    )
  }
  const capability = response.attempt_capability
  try {
    const deadline =
      ordinaryAuthorizationAttemptCapabilityDeadline(capability)
    if (
      deadline !==
        rfc3339NanoNanoseconds(response.attempt_expires_at)
    ) {
      throw new Error()
    }
  } catch {
    throw new Error(
      'ordinary browser authorization: attempt capability is invalid',
    )
  }
  const attemptExpiresAt =
    requestStartedAt + (expiresIn - 1) * 1000
  if (!Number.isSafeInteger(attemptExpiresAt)) {
    throw new Error(
      'ordinary browser authorization: attempt deadline is invalid',
    )
  }
  return { attemptCapability: capability, attemptExpiresAt }
}

export function admittedOrdinaryAuthorizationRecord(
  record: OrdinaryAuthorizationRecord,
  responseText: string,
): OrdinaryAuthorizationRecord {
  const response = parseUniqueFlatJSONObject(
    responseText,
    MAX_PAR_RESPONSE_BYTES,
  )
  if (
    !hasExactMembers(response, [
      'request_uri',
      'expires_in',
      'authorization_code_expires_in',
      'atol_browser_authorization_version',
      'atol_browser_authorization_expires_at',
      'terminal_proof',
    ]) ||
    record.parPhase !== 'submitted' ||
    typeof response.request_uri !== 'string' ||
    !response.request_uri.startsWith(REQUEST_URI_PREFIX) ||
    !validCanonicalSHA256(
      response.request_uri.slice(REQUEST_URI_PREFIX.length),
    ) ||
    !Number.isInteger(response.expires_in) ||
    (response.expires_in as number) <= 0 ||
    (response.expires_in as number) >
      record.ceremonyLifetimeSeconds ||
    response.authorization_code_expires_in !==
      record.authorizationCodeLifetimeSeconds ||
    response.atol_browser_authorization_version !==
      record.protocolVersion ||
    typeof response.atol_browser_authorization_expires_at !== 'string' ||
    record.attemptExpiresAtMs === null ||
    !new URLSearchParams(record.form).has(
      'atol_attempt_capability',
    )
  ) {
    throw new Error(
      'ordinary browser authorization: PAR response is invalid',
    )
  }
  const rootExpiresAt =
    response.atol_browser_authorization_expires_at
  if (
    !validOrdinaryAuthorizationTerminalProof(
      response.terminal_proof,
      rootExpiresAt,
    ) ||
    ordinaryAuthorizationAttemptCapabilityDeadline(
      new URLSearchParams(record.form).get(
        'atol_attempt_capability',
      ),
    ) !== rfc3339NanoNanoseconds(rootExpiresAt)
  ) {
    throw new Error(
      'ordinary browser authorization: PAR deadline binding is invalid',
    )
  }
  const rootExpiresAtMs = rfc3339NanoMilliseconds(rootExpiresAt)
  const localCustodyExpiresAtMs =
    record.attemptExpiresAtMs +
    record.authorizationCodeLifetimeSeconds * 1000
  const custodyExpiresAtMs = Math.min(
    localCustodyExpiresAtMs,
    record.provisionalExpiresAt,
  )
  if (
    !Number.isSafeInteger(localCustodyExpiresAtMs) ||
    !Number.isSafeInteger(custodyExpiresAtMs) ||
    custodyExpiresAtMs <= record.createdAt
  ) {
    throw new Error(
      'ordinary browser authorization: PAR deadline is invalid',
    )
  }
  return {
    ...record,
    parPhase: 'admitted',
    requestUri: response.request_uri,
    terminalProof: response.terminal_proof,
    rootExpiresAt,
    rootExpiresAtMs,
    custodyExpiresAtMs,
  }
}

export function ordinaryAuthorizationPARBody(
  record: OrdinaryAuthorizationRecord,
): string {
  const parameters = new URLSearchParams(record.form)
  parameters.set(
    'atol_cancellation_secret',
    record.cancellationSecret,
  )
  parameters.sort()
  return parameters.toString()
}

async function readResponseChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
  description: string,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  if (signal.aborted) {
    throw new Error(
      `ordinary browser authorization: ${description} timed out`,
    )
  }
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (
      result:
        | {
            ok: true
            value: ReadableStreamReadResult<Uint8Array>
          }
        | { ok: false; error: unknown },
    ): void => {
      if (settled) return
      settled = true
      signal.removeEventListener('abort', onAbort)
      if (result.ok) resolve(result.value)
      else reject(result.error)
    }
    const onAbort = (): void => {
      finish({
        ok: false,
        error: new Error(
          `ordinary browser authorization: ${description} timed out`,
        ),
      })
      void reader.cancel()
    }
    signal.addEventListener('abort', onAbort, { once: true })
    void reader.read().then(
      (value) => finish({ ok: true, value }),
      (error) => finish({ ok: false, error }),
    )
  })
}

export async function readBoundedOrdinaryAuthorizationResponse(
  response: Response,
  signal: AbortSignal,
  maxBytes: number,
  description: string,
): Promise<string> {
  const contentLength = response.headers.get('content-length')
  if (contentLength !== null) {
    const parsed = Number(contentLength)
    if (
      !Number.isSafeInteger(parsed) ||
      parsed < 0 ||
      parsed > maxBytes
    ) {
      throw new Error(
        `ordinary browser authorization: ${description} is too large`,
      )
    }
  }
  if (!response.body) {
    throw new Error(
      `ordinary browser authorization: ${description} body is missing`,
    )
  }
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const result = await readResponseChunk(
        reader,
        signal,
        description,
      )
      if (result.done) break
      total += result.value.byteLength
      if (total > maxBytes) {
        await reader.cancel()
        throw new Error(
          `ordinary browser authorization: ${description} is too large`,
        )
      }
      chunks.push(result.value)
    }
  } catch (error) {
    await reader.cancel()
    throw error
  } finally {
    reader.releaseLock()
  }
  const body = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(body)
}

export function readBoundedParResponse(
  response: Response,
  signal: AbortSignal,
): Promise<string> {
  return readBoundedOrdinaryAuthorizationResponse(
    response,
    signal,
    MAX_PAR_RESPONSE_BYTES,
    'PAR response',
  )
}

export function ordinaryAuthorizationNavigationURL(
  record: OrdinaryAuthorizationRecord,
): string {
  if (
    record.parPhase !== 'admitted' ||
    record.requestUri === null ||
    record.terminalProof === null ||
    record.attemptExpiresAtMs === null ||
    Date.now() >= record.attemptExpiresAtMs
  ) {
    throw new Error(
      'ordinary browser authorization: admitted root is expired',
    )
  }
  const target = new URL(record.authorizationEndpoint)
  target.searchParams.set('client_id', record.clientId)
  target.searchParams.set('request_uri', record.requestUri)
  return target.href
}
