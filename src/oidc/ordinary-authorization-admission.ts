import {
  PAR_TIMEOUT_MS,
  OrdinaryAuthorizationPendingError,
  ordinaryAuthorizationRecordExpired,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import {
  admittedOrdinaryAuthorizationRecord,
  readBoundedParResponse,
} from './ordinary-authorization-protocol'
import { cancelSubmittedOrdinaryAuthorization } from './ordinary-authorization-pre-navigation'
import {
  markOrdinaryAuthorizationPARSubmitted,
  replaceOrdinaryAuthorizationRecord,
  startOrdinaryAuthorizationCleanup,
} from './ordinary-authorization-storage'
import {
  assertOrdinaryAuthorizationRecord,
  assertOrdinaryAuthorizationRecordState,
} from './ordinary-authorization-validation'
import {
  bindOrdinaryPARChallenge,
  postOrdinaryPAR,
  validOrdinaryPARResponseHeaders,
} from './ordinary-authorization-transport'

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
  let settled: OrdinaryAuthorizationRecord
  try {
    settled = await cancelSubmittedOrdinaryAuthorization(submitted)
  } catch {
    return null
  }
  return startOrdinaryAuthorizationCleanup(settled)
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
    const first = await postOrdinaryPAR(submitted, controller.signal)
    let response = first.response
    if (response.status === 428) {
      submitted = await bindOrdinaryPARChallenge(
        submitted,
        response,
        first.startedAt,
        controller.signal,
      )
      response = (await postOrdinaryPAR(submitted, controller.signal)).response
    }
    if (response.status !== 201) {
      throw new OrdinaryAuthorizationPendingError()
    }
    if (!validOrdinaryPARResponseHeaders(response)) {
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
