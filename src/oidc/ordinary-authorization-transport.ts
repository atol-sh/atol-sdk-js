import {
  OrdinaryAuthorizationPendingError,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import {
  ordinaryAuthorizationAttemptChallenge,
  ordinaryAuthorizationPARBody,
  readBoundedParResponse,
} from './ordinary-authorization-protocol'
import { bindOrdinaryAuthorizationAttemptCapability } from './ordinary-authorization-storage'
import {
  assertOrdinaryAuthorizationRecord,
  assertOrdinaryAuthorizationRecordState,
} from './ordinary-authorization-validation'

export function validOrdinaryPARResponseHeaders(response: Response): boolean {
  return (
    response.headers.get('cache-control') === 'no-store' &&
    response.headers.get('content-type') === 'application/json' &&
    response.headers.get('atol-browser-authorization') === 'v2'
  )
}

export async function postOrdinaryPAR(
  record: OrdinaryAuthorizationRecord,
  signal: AbortSignal,
): Promise<{ response: Response; startedAt: number }> {
  const startedAt = Date.now()
  try {
    const response = await fetch(record.pushedAuthorizationRequestEndpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: ordinaryAuthorizationPARBody(record),
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal,
    })
    return { response, startedAt }
  } catch {
    throw new OrdinaryAuthorizationPendingError()
  }
}

export async function bindOrdinaryPARChallenge(
  record: OrdinaryAuthorizationRecord,
  response: Response,
  startedAt: number,
  signal: AbortSignal,
): Promise<OrdinaryAuthorizationRecord> {
  if (response.status !== 428 || !validOrdinaryPARResponseHeaders(response)) {
    throw new OrdinaryAuthorizationPendingError()
  }
  let challengeText: string
  try {
    challengeText = await readBoundedParResponse(response, signal)
  } catch {
    throw new OrdinaryAuthorizationPendingError()
  }
  const challenge = ordinaryAuthorizationAttemptChallenge(
    record,
    challengeText,
    startedAt,
  )
  const bound = await bindOrdinaryAuthorizationAttemptCapability(
    record,
    challenge.attemptCapability,
    challenge.attemptExpiresAt,
  )
  assertOrdinaryAuthorizationRecord(
    bound,
    record,
    record.credentialGeneration,
    record.intent,
  )
  await assertOrdinaryAuthorizationRecordState(bound)
  return bound
}
