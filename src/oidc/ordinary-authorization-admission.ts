import {
  PAR_TIMEOUT_MS,
  OrdinaryAuthorizationPendingError,
  ordinaryAuthorizationRecordExpired,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import {
  admittedOrdinaryAuthorizationRecord,
  ordinaryAuthorizationAttemptChallenge,
  ordinaryAuthorizationPARBody,
  readBoundedParResponse,
} from './ordinary-authorization-protocol'
import { cancelSubmittedOrdinaryAuthorization } from './ordinary-authorization-pre-navigation'
import {
  markOrdinaryAuthorizationPARSubmitted,
  bindOrdinaryAuthorizationAttemptCapability,
  replaceOrdinaryAuthorizationRecord,
  startOrdinaryAuthorizationCleanup,
} from './ordinary-authorization-storage'
import {
  assertOrdinaryAuthorizationRecord,
  assertOrdinaryAuthorizationRecordState,
} from './ordinary-authorization-validation'

export class OrdinaryAuthorizationAdmissionTerminalError extends Error {
  constructor(
    readonly cleaning: OrdinaryAuthorizationRecord,
  ) {
    super(
      'ordinary browser authorization: invalid admission was rejected',
    )
    this.name = 'OrdinaryAuthorizationAdmissionTerminalError'
  }
}

async function rejectUncommittedAdmission(
  submitted: OrdinaryAuthorizationRecord,
): Promise<OrdinaryAuthorizationRecord | null> {
  try {
    await cancelSubmittedOrdinaryAuthorization(submitted)
  } catch {
    return null
  }
  return startOrdinaryAuthorizationCleanup(submitted)
}

async function rejectOrRetainInvalidAdmission(
  submitted: OrdinaryAuthorizationRecord,
): Promise<never> {
  const cleaning = await rejectUncommittedAdmission(submitted)
  if (cleaning !== null) {
    throw new OrdinaryAuthorizationAdmissionTerminalError(cleaning)
  }
  throw new OrdinaryAuthorizationPendingError()
}

function validPARResponseHeaders(response: Response): boolean {
  return (
    response.headers.get('cache-control') === 'no-store' &&
    response.headers.get('content-type') === 'application/json' &&
    response.headers.get('atol-browser-authorization') === 'v2'
  )
}

/**
 * Durably crosses prepared -> submitted -> admitted before navigation.
 */
export async function admitOrdinaryAuthorization(
  record: OrdinaryAuthorizationRecord,
): Promise<OrdinaryAuthorizationRecord> {
  if (ordinaryAuthorizationRecordExpired(record)) {
    if (record.parPhase === 'submitted') {
      return rejectOrRetainInvalidAdmission(record)
    }
    throw new OrdinaryAuthorizationPendingError()
  }
  let submitted =
    await markOrdinaryAuthorizationPARSubmitted(record)
  assertOrdinaryAuthorizationRecord(
    submitted,
    {
      issuer: record.issuer,
      clientId: record.clientId,
      redirectUri: record.redirectUri,
      scope: record.scope,
    },
    record.credentialGeneration,
    record.intent,
  )
  await assertOrdinaryAuthorizationRecordState(submitted)
  if (submitted.parPhase === 'admitted') return submitted

  const controller = new AbortController()
  const timeout = setTimeout(
    () => controller.abort(),
    PAR_TIMEOUT_MS,
  )
  try {
    let response: Response
    let requestStartedAt = Date.now()
    try {
      response = await fetch(
        submitted.pushedAuthorizationRequestEndpoint,
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
    if (response.status === 428) {
      if (!validPARResponseHeaders(response)) {
        throw new OrdinaryAuthorizationPendingError()
      }
      let challengeText: string
      try {
        challengeText = await readBoundedParResponse(
          response,
          controller.signal,
        )
      } catch {
        throw new OrdinaryAuthorizationPendingError()
      }
      const challenge = ordinaryAuthorizationAttemptChallenge(
        submitted,
        challengeText,
        requestStartedAt,
      )
      submitted = await bindOrdinaryAuthorizationAttemptCapability(
        submitted,
        challenge.attemptCapability,
        challenge.attemptExpiresAt,
      )
      assertOrdinaryAuthorizationRecord(
        submitted,
        {
          issuer: record.issuer,
          clientId: record.clientId,
          redirectUri: record.redirectUri,
          scope: record.scope,
        },
        record.credentialGeneration,
        record.intent,
      )
      await assertOrdinaryAuthorizationRecordState(submitted)
      requestStartedAt = Date.now()
      try {
        response = await fetch(
          submitted.pushedAuthorizationRequestEndpoint,
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
    }
    if (response.status !== 201) {
      throw new OrdinaryAuthorizationPendingError()
    }
    if (!validPARResponseHeaders(response)) {
      return rejectOrRetainInvalidAdmission(submitted)
    }

    let responseText: string
    try {
      responseText = await readBoundedParResponse(
        response,
        controller.signal,
      )
    } catch {
      return rejectOrRetainInvalidAdmission(submitted)
    }
    let admitted: OrdinaryAuthorizationRecord
    try {
      admitted = admittedOrdinaryAuthorizationRecord(
        submitted,
        responseText,
      )
    } catch {
      return rejectOrRetainInvalidAdmission(submitted)
    }
    try {
      return await replaceOrdinaryAuthorizationRecord(
        submitted,
        admitted,
      )
    } catch {
      return rejectOrRetainInvalidAdmission(submitted)
    }
  } finally {
    clearTimeout(timeout)
  }
}
