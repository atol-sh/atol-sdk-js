import {
  SETTLEMENT_TIMEOUT_MS,
  OrdinaryAuthorizationPendingError,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import { ordinaryAuthorizationPARBody } from './ordinary-authorization-protocol'
import { hasAuthenticatedOrdinaryAuthorizationSignal } from './ordinary-authorization-settlement'
import {
  bindOrdinaryPARChallenge,
  postOrdinaryPAR,
} from './ordinary-authorization-transport'

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
): Promise<OrdinaryAuthorizationRecord> {
  assertSubmittedCancellation(record)
  const controller = new AbortController()
  const timeout = setTimeout(
    () => controller.abort(),
    SETTLEMENT_TIMEOUT_MS,
  )
  try {
    let submitted = record
    if (record.attemptExpiresAtMs === null) {
      // A capability-free PAR can only obtain a challenge. The exact
      // capability is required for authenticated cancellation.
      const challenge = await postOrdinaryPAR(record, controller.signal)
      submitted = await bindOrdinaryPARChallenge(
        record,
        challenge.response,
        challenge.startedAt,
        controller.signal,
      )
    }
    let response: Response
    try {
      response = await fetch(
        submitted.preNavigationCancellationEndpoint,
        {
          method: 'POST',
          headers: {
            Accept: 'application/json',
            'Content-Type':
              'application/x-www-form-urlencoded',
          },
          body: ordinaryAuthorizationPARBody(submitted),
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
    return submitted
  } finally {
    clearTimeout(timeout)
  }
}
