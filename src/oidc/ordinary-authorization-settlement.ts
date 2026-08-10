import {
  MAX_SETTLEMENT_RESPONSE_BYTES,
  ORDINARY_AUTHORIZATION_PROTOCOL_VERSION,
  REQUEST_URI_PREFIX,
  SETTLEMENT_TIMEOUT_MS,
  OrdinaryAuthorizationPendingError,
  validCanonicalSHA256,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import {
  readBoundedOrdinaryAuthorizationResponse,
  validOrdinaryAuthorizationTerminalProof,
} from './ordinary-authorization-protocol'
import {
  hasExactMembers,
  parseUniqueFlatJSONObject,
} from './strict-json'

export type OrdinaryAuthorizationSettlementMode =
  | 'reject'
  | 'terminal_only'

export type OrdinaryAuthorizationSettlementAuthority = Pick<
  OrdinaryAuthorizationRecord,
  | 'issuer'
  | 'clientId'
  | 'settlementEndpoint'
  | 'requestUri'
  | 'cancellationSecret'
  | 'terminalProof'
  | 'rootExpiresAt'
>

export class OrdinaryAuthorizationSettlementInvalidError extends Error {
  constructor() {
    super(
      'ordinary browser authorization: settlement authority was rejected',
    )
    this.name = 'OrdinaryAuthorizationSettlementInvalidError'
  }
}

function assertSettlementAuthority(
  authority: OrdinaryAuthorizationSettlementAuthority,
  mode: OrdinaryAuthorizationSettlementMode,
): asserts authority is OrdinaryAuthorizationSettlementAuthority & {
  requestUri: string
} {
  if (
    authority.settlementEndpoint !==
      `${authority.issuer}/auth/par/settlement` ||
    authority.requestUri === null ||
    !authority.requestUri.startsWith(REQUEST_URI_PREFIX) ||
    !validCanonicalSHA256(
      authority.requestUri.slice(REQUEST_URI_PREFIX.length),
    ) ||
    !validCanonicalSHA256(authority.cancellationSecret) ||
    (authority.terminalProof !== null &&
      (authority.rootExpiresAt === null ||
        !validOrdinaryAuthorizationTerminalProof(
          authority.terminalProof,
          authority.rootExpiresAt,
        ))) ||
    (mode === 'terminal_only' &&
      authority.terminalProof === null)
  ) {
    throw new Error(
      'ordinary browser authorization: settlement authority is invalid',
    )
  }
}

export function hasAuthenticatedOrdinaryAuthorizationSignal(
  response: Response,
): boolean {
  return (
    response.headers.get('atol-browser-authorization') === 'v2'
  )
}

function hasNoStore(response: Response): boolean {
  return response.headers.get('cache-control') === 'no-store'
}

async function exactSettlementError(
  response: Response,
  signal: AbortSignal,
  expected: string,
): Promise<boolean> {
  if (response.headers.get('content-type') !== 'application/json') {
    return false
  }
  try {
    const parsed = parseUniqueFlatJSONObject(
      await readBoundedOrdinaryAuthorizationResponse(
        response,
        signal,
        MAX_SETTLEMENT_RESPONSE_BYTES,
        'settlement response',
      ),
      MAX_SETTLEMENT_RESPONSE_BYTES,
    )
    return (
      hasExactMembers(parsed, ['error']) &&
      parsed.error === expected
    )
  } catch {
    return false
  }
}

function settlementBody(
  authority: OrdinaryAuthorizationSettlementAuthority & {
    requestUri: string
  },
  mode: OrdinaryAuthorizationSettlementMode,
): string {
  return JSON.stringify({
    version: ORDINARY_AUTHORIZATION_PROTOCOL_VERSION,
    mode,
    client_id: authority.clientId,
    request_uri: authority.requestUri,
    cancellation_secret: authority.cancellationSecret,
    ...(authority.terminalProof === null
      ? {}
      : { terminal_proof: authority.terminalProof }),
  })
}

/**
 * Proves an ordinary authorization terminal before local custody is deleted.
 */
export async function settleOrdinaryAuthorization(
  authority: OrdinaryAuthorizationSettlementAuthority,
  mode: OrdinaryAuthorizationSettlementMode,
): Promise<void> {
  assertSettlementAuthority(authority, mode)
  const controller = new AbortController()
  const timeout = setTimeout(
    () => controller.abort(),
    SETTLEMENT_TIMEOUT_MS,
  )
  try {
    let response: Response
    try {
      response = await fetch(authority.settlementEndpoint, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: settlementBody(authority, mode),
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      })
    } catch {
      throw new OrdinaryAuthorizationPendingError()
    }
    if (!hasNoStore(response)) {
      throw new OrdinaryAuthorizationPendingError()
    }
    if (response.status === 204 && mode === 'reject') {
      if (
        !hasAuthenticatedOrdinaryAuthorizationSignal(response) ||
        response.headers.get('content-type') !== null ||
        response.body !== null
      ) {
        throw new OrdinaryAuthorizationPendingError()
      }
      return
    }
    if (
      response.status === 410 &&
      mode === 'terminal_only' &&
      hasAuthenticatedOrdinaryAuthorizationSignal(response) &&
      await exactSettlementError(
        response,
        controller.signal,
        'authorization_terminal',
      )
    ) {
      return
    }
    if (
      response.status === 409 &&
      mode === 'terminal_only' &&
      hasAuthenticatedOrdinaryAuthorizationSignal(response)
    ) {
      await exactSettlementError(
        response,
        controller.signal,
        'authorization_nonterminal',
      )
      throw new OrdinaryAuthorizationPendingError()
    }
    if (
      response.status === 503 &&
      hasAuthenticatedOrdinaryAuthorizationSignal(response)
    ) {
      await exactSettlementError(
        response,
        controller.signal,
        'unavailable',
      )
      throw new OrdinaryAuthorizationPendingError()
    }
    if (
      response.status === 400 &&
      hasAuthenticatedOrdinaryAuthorizationSignal(response) &&
      await exactSettlementError(
        response,
        controller.signal,
        'invalid_request',
      )
    ) {
      throw new OrdinaryAuthorizationSettlementInvalidError()
    }
    throw new OrdinaryAuthorizationPendingError()
  } finally {
    clearTimeout(timeout)
  }
}
