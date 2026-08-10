import {
  SETTLEMENT_TIMEOUT_MS,
  OrdinaryAuthorizationPendingError,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import { ordinaryAuthorizationPARBody } from './ordinary-authorization-protocol'
import { hasAuthenticatedOrdinaryAuthorizationSignal } from './ordinary-authorization-settlement'

function assertSubmittedCancellation(
  record: OrdinaryAuthorizationRecord,
): void {
  if (
    record.preNavigationCancellationEndpoint !==
      `${record.issuer}/auth/par/pre-navigation-cancellation` ||
    record.parPhase !== 'submitted' ||
    record.requestUri !== null ||
    record.terminalProof !== null ||
    record.rootExpiresAt !== null ||
    record.rootExpiresAtMs !== null ||
    record.custodyExpiresAtMs !== null ||
    record.rejectionRequired ||
    record.cleanupStarted
  ) {
    throw new Error(
      'ordinary browser authorization: pre-navigation cancellation authority is invalid',
    )
  }
}

/**
 * Fences a submitted PAR before local custody may be removed.
 */
export async function cancelSubmittedOrdinaryAuthorization(
  record: OrdinaryAuthorizationRecord,
): Promise<void> {
  assertSubmittedCancellation(record)
  const controller = new AbortController()
  const timeout = setTimeout(
    () => controller.abort(),
    SETTLEMENT_TIMEOUT_MS,
  )
  try {
    let response: Response
    try {
      response = await fetch(
        record.preNavigationCancellationEndpoint,
        {
          method: 'POST',
          headers: {
            Accept: 'application/json',
            'Content-Type':
              'application/x-www-form-urlencoded',
          },
          body: ordinaryAuthorizationPARBody(record),
          cache: 'no-store',
          credentials: 'omit',
          redirect: 'error',
          referrerPolicy: 'no-referrer',
          signal: controller.signal,
        },
      )
    } catch {
      throw new OrdinaryAuthorizationPendingError()
    }
    if (
      response.status !== 204 ||
      response.headers.get('cache-control') !== 'no-store' ||
      !hasAuthenticatedOrdinaryAuthorizationSignal(response) ||
      response.headers.get('content-type') !== null ||
      response.body !== null
    ) {
      throw new OrdinaryAuthorizationPendingError()
    }
  } finally {
    clearTimeout(timeout)
  }
}
