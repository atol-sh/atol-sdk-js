import { bytesToBase64Url } from '../crypto/base64url'
import {
  CALLBACK_CLAIM_LIFETIME_MS,
  ORDINARY_AUTHORIZATION_STORE,
  OrdinaryAuthorizationPendingError,
  validCanonicalAttemptCapability,
  validCanonicalAuthorizationCode,
  validCanonicalSHA256,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import {
  openOrdinaryAuthorizationDB,
  ordinaryAuthorizationRequestResult as requestResult,
  ordinaryAuthorizationTransactionDone as transactionDone,
} from './ordinary-authorization-database'
export {
  ordinaryAuthorizationPointerStorage,
  parseOrdinaryAuthorizationPointer,
  serializeOrdinaryAuthorizationPointer,
} from './ordinary-authorization-pointer'
export {
  loadOrdinaryAuthorizationInventory,
  ORDINARY_AUTHORIZATION_INVENTORY_BATCH_SIZE,
  validateOrdinaryAuthorizationEnvelopeInventory,
  validateOrdinaryAuthorizationInventory,
  type OrdinaryAuthorizationInventoryBatch,
} from './ordinary-authorization-storage-inventory'

export async function loadOrdinaryAuthorizationRecord(
  key: string,
): Promise<OrdinaryAuthorizationRecord | undefined> {
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(ORDINARY_AUTHORIZATION_STORE, 'readonly')
    const result = await requestResult(
      transaction.objectStore(ORDINARY_AUTHORIZATION_STORE).get(key),
      'record read',
    )
    await transactionDone(transaction, 'record read')
    return result as OrdinaryAuthorizationRecord | undefined
  } finally {
    db.close()
  }
}

export async function addOrdinaryAuthorizationRecord(
  record: OrdinaryAuthorizationRecord,
): Promise<void> {
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    store.add(record)
    await transactionDone(transaction, 'record stage')
  } finally {
    db.close()
  }
}

export async function markOrdinaryAuthorizationPARSubmitted(
  expected: OrdinaryAuthorizationRecord,
): Promise<OrdinaryAuthorizationRecord> {
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    const current = (await requestResult(
      store.get(expected.slotKey),
      'PAR submission read',
    )) as OrdinaryAuthorizationRecord | undefined
    if (
      current &&
      (current.parPhase === 'submitted' || current.parPhase === 'admitted') &&
      current.stateId === expected.stateId &&
      current.form === expected.form &&
      current.cancellationSecret === expected.cancellationSecret &&
      !current.cleanupStarted &&
      !current.rejectionRequired
    ) {
      await transactionDone(transaction, 'stable PAR submission')
      return current
    }
    if (
      !current ||
      current.revision !== expected.revision ||
      current.stateId !== expected.stateId ||
      current.form !== expected.form ||
      current.cancellationSecret !== expected.cancellationSecret ||
      current.parPhase !== 'prepared' ||
      current.cleanupStarted ||
      current.rejectionRequired
    ) {
      transaction.abort()
      throw new OrdinaryAuthorizationPendingError()
    }
    const submitted: OrdinaryAuthorizationRecord = {
      ...current,
      revision: current.revision + 1,
      parPhase: 'submitted',
    }
    store.put(submitted)
    await transactionDone(transaction, 'PAR submission')
    return submitted
  } finally {
    db.close()
  }
}

function withOrdinaryAuthorizationAttemptCapability(
  form: string,
  attemptCapability: string,
): string {
  const parameters = new URLSearchParams(form)
  if (parameters.has('atol_attempt_capability')) {
    throw new Error(
      'ordinary browser authorization: attempt capability is already bound',
    )
  }
  parameters.set('atol_attempt_capability', attemptCapability)
  parameters.sort()
  return parameters.toString()
}

export async function bindOrdinaryAuthorizationAttemptCapability(
  expected: OrdinaryAuthorizationRecord,
  attemptCapability: string,
  attemptExpiresAt: number,
): Promise<OrdinaryAuthorizationRecord> {
  const now = Date.now()
  if (
    !validCanonicalAttemptCapability(attemptCapability) ||
    !Number.isSafeInteger(attemptExpiresAt) ||
    attemptExpiresAt <= now
  ) {
    throw new Error(
      'ordinary browser authorization: attempt capability is invalid',
    )
  }
  const updatedForm = withOrdinaryAuthorizationAttemptCapability(
    expected.form,
    attemptCapability,
  )
  const clippedExpiresAt = Math.min(
    expected.provisionalExpiresAt,
    attemptExpiresAt,
  )
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    const current = (await requestResult(
      store.get(expected.slotKey),
      'attempt capability read',
    )) as OrdinaryAuthorizationRecord | undefined
    if (
      current?.form === updatedForm &&
      current.attemptExpiresAtMs === clippedExpiresAt &&
      current.stateId === expected.stateId &&
      current.cancellationSecret === expected.cancellationSecret &&
      current.parPhase === 'submitted' &&
      !current.cleanupStarted &&
      !current.rejectionRequired
    ) {
      await transactionDone(transaction, 'stable attempt capability binding')
      return current
    }
    if (
      !current ||
      current.revision !== expected.revision ||
      current.stateId !== expected.stateId ||
      current.form !== expected.form ||
      current.cancellationSecret !== expected.cancellationSecret ||
      current.parPhase !== 'submitted' ||
      current.cleanupStarted ||
      current.rejectionRequired
    ) {
      transaction.abort()
      throw new OrdinaryAuthorizationPendingError()
    }
    const bound: OrdinaryAuthorizationRecord = {
      ...current,
      revision: current.revision + 1,
      form: updatedForm,
      attemptExpiresAtMs: clippedExpiresAt,
    }
    store.put(bound)
    await transactionDone(transaction, 'attempt capability binding')
    return bound
  } finally {
    db.close()
  }
}

export async function replaceOrdinaryAuthorizationRecord(
  expected: OrdinaryAuthorizationRecord,
  replacement: OrdinaryAuthorizationRecord,
): Promise<OrdinaryAuthorizationRecord> {
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    const current = (await requestResult(
      store.get(expected.slotKey),
      'record bind read',
    )) as OrdinaryAuthorizationRecord | undefined
    if (
      current &&
      !current.cleanupStarted &&
      current.stateId === expected.stateId &&
      current.form === expected.form &&
      current.stateStorage === expected.stateStorage &&
      current.parPhase === 'admitted' &&
      !current.rejectionRequired &&
      current.requestUri === replacement.requestUri &&
      current.terminalProof === replacement.terminalProof &&
      current.rootExpiresAt === replacement.rootExpiresAt &&
      current.rootExpiresAtMs === replacement.rootExpiresAtMs &&
      current.custodyExpiresAtMs === replacement.custodyExpiresAtMs
    ) {
      await transactionDone(transaction, 'stable record bind')
      return current
    }
    if (
      !current ||
      current.revision !== expected.revision ||
      current.stateId !== expected.stateId ||
      current.form !== expected.form ||
      current.stateStorage !== expected.stateStorage ||
      current.parPhase !== 'submitted' ||
      current.requestUri !== expected.requestUri ||
      current.terminalProof !== expected.terminalProof ||
      current.rootExpiresAt !== expected.rootExpiresAt ||
      current.cleanupStarted ||
      current.rejectionRequired
    ) {
      transaction.abort()
      throw new Error('ordinary browser authorization: custody was superseded')
    }
    const next = {
      ...replacement,
      revision: current.revision + 1,
    }
    store.put(next)
    await transactionDone(transaction, 'record bind')
    return next
  } finally {
    db.close()
  }
}

export async function requireOrdinaryAuthorizationRejection(
  expected: OrdinaryAuthorizationRecord,
): Promise<OrdinaryAuthorizationRecord> {
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    const current = (await requestResult(
      store.get(expected.slotKey),
      'rejection transition read',
    )) as OrdinaryAuthorizationRecord | undefined
    if (
      current?.rejectionRequired &&
      current.parPhase === 'admitted' &&
      current.stateId === expected.stateId &&
      current.form === expected.form
    ) {
      await transactionDone(transaction, 'stable rejection transition')
      return current
    }
    if (
      !current ||
      current.revision !== expected.revision ||
      current.stateId !== expected.stateId ||
      current.form !== expected.form ||
      current.parPhase !== 'admitted' ||
      current.cleanupStarted
    ) {
      transaction.abort()
      throw new OrdinaryAuthorizationPendingError()
    }
    const rejecting: OrdinaryAuthorizationRecord = {
      ...current,
      revision: current.revision + 1,
      callbackClaimId: null,
      callbackClaimExpiresAtMs: null,
      rejectionRequired: true,
    }
    store.put(rejecting)
    await transactionDone(transaction, 'rejection transition')
    return rejecting
  } finally {
    db.close()
  }
}

function newClaimID(): string {
  const value = new Uint8Array(32)
  crypto.getRandomValues(value)
  return bytesToBase64Url(value)
}

export async function claimOrdinaryAuthorizationRecord(
  expected: OrdinaryAuthorizationRecord,
  callbackCode: string | null,
  callbackCodeHash: string | null,
): Promise<OrdinaryAuthorizationRecord> {
  if (
    (callbackCode === null) !== (callbackCodeHash === null) ||
    (callbackCode !== null && !validCanonicalAuthorizationCode(callbackCode)) ||
    (callbackCodeHash !== null && !validCanonicalSHA256(callbackCodeHash))
  ) {
    throw new Error('ordinary browser authorization: callback code is invalid')
  }
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    const current = (await requestResult(
      store.get(expected.slotKey),
      'callback claim read',
    )) as OrdinaryAuthorizationRecord | undefined
    const now = Date.now()
    if (
      !current ||
      current.revision !== expected.revision ||
      current.stateId !== expected.stateId ||
      current.parPhase !== 'admitted' ||
      current.rejectionRequired ||
      current.cleanupStarted ||
      (current.callbackCode !== null &&
        current.callbackCode !== callbackCode) ||
      (current.callbackCodeHash !== null &&
        current.callbackCodeHash !== callbackCodeHash) ||
      (current.callbackCode === null && current.compensationRequired) ||
      (current.callbackClaimId !== null &&
        (current.callbackClaimExpiresAtMs as number) > now)
    ) {
      transaction.abort()
      throw new OrdinaryAuthorizationPendingError()
    }
    const claimExpiresAt = now + CALLBACK_CLAIM_LIFETIME_MS
    if (
      !Number.isSafeInteger(now) ||
      now < 0 ||
      !Number.isSafeInteger(claimExpiresAt) ||
      claimExpiresAt <= now
    ) {
      transaction.abort()
      throw new Error(
        'ordinary browser authorization: callback claim clock is invalid',
      )
    }
    const claimed: OrdinaryAuthorizationRecord = {
      ...current,
      revision: current.revision + 1,
      callbackClaimId: newClaimID(),
      callbackClaimExpiresAtMs: claimExpiresAt,
      callbackCode: current.callbackCode ?? callbackCode,
      callbackCodeHash: current.callbackCodeHash ?? callbackCodeHash,
    }
    store.put(claimed)
    await transactionDone(transaction, 'callback claim')
    return claimed
  } finally {
    db.close()
  }
}

export async function markOrdinaryAuthorizationCodeIssued(
  expected: OrdinaryAuthorizationRecord,
): Promise<OrdinaryAuthorizationRecord> {
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    const current = (await requestResult(
      store.get(expected.slotKey),
      'code issuance transition read',
    )) as OrdinaryAuthorizationRecord | undefined
    if (
      !current ||
      current.revision !== expected.revision ||
      current.stateId !== expected.stateId ||
      current.callbackClaimId !== expected.callbackClaimId ||
      current.callbackClaimId === null ||
      current.callbackCode === null ||
      current.callbackCodeHash === null ||
      current.compensationRequired ||
      current.rejectionRequired ||
      current.cleanupStarted
    ) {
      transaction.abort()
      throw new Error(
        'ordinary browser authorization: code issuance was superseded',
      )
    }
    const issued: OrdinaryAuthorizationRecord = {
      ...current,
      revision: current.revision + 1,
      compensationRequired: true,
    }
    store.put(issued)
    await transactionDone(transaction, 'code issuance transition')
    return issued
  } finally {
    db.close()
  }
}

export async function startOrdinaryAuthorizationCleanup(
  expected: OrdinaryAuthorizationRecord,
): Promise<OrdinaryAuthorizationRecord> {
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    const current = (await requestResult(
      store.get(expected.slotKey),
      'cleanup transition read',
    )) as OrdinaryAuthorizationRecord | undefined
    if (
      current?.cleanupStarted &&
      current.stateId === expected.stateId &&
      current.form === expected.form &&
      current.stateStorage === expected.stateStorage &&
      current.cancellationSecret === expected.cancellationSecret
    ) {
      await transactionDone(transaction, 'stable cleanup transition')
      return current
    }
    if (
      !current ||
      current.revision !== expected.revision ||
      current.stateId !== expected.stateId ||
      current.form !== expected.form ||
      current.stateStorage !== expected.stateStorage ||
      current.cancellationSecret !== expected.cancellationSecret ||
      current.cleanupStarted
    ) {
      transaction.abort()
      throw new Error('ordinary browser authorization: cleanup was superseded')
    }
    const cleaning: OrdinaryAuthorizationRecord = {
      ...current,
      revision: current.revision + 1,
      callbackClaimId: null,
      callbackClaimExpiresAtMs: null,
      cleanupStarted: true,
    }
    store.put(cleaning)
    await transactionDone(transaction, 'cleanup transition')
    return cleaning
  } finally {
    db.close()
  }
}

export async function releaseOrdinaryAuthorizationClaim(
  expected: OrdinaryAuthorizationRecord,
): Promise<void> {
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    const current = (await requestResult(
      store.get(expected.slotKey),
      'callback release read',
    )) as OrdinaryAuthorizationRecord | undefined
    if (
      !current ||
      current.revision !== expected.revision ||
      current.callbackClaimId !== expected.callbackClaimId ||
      current.callbackClaimId === null ||
      current.cleanupStarted
    ) {
      transaction.abort()
      throw new Error(
        'ordinary browser authorization: callback release was superseded',
      )
    }
    store.put({
      ...current,
      revision: current.revision + 1,
      callbackClaimId: null,
      callbackClaimExpiresAtMs: null,
      cleanupStarted: false,
    } satisfies OrdinaryAuthorizationRecord)
    await transactionDone(transaction, 'callback release')
  } finally {
    db.close()
  }
}

export async function deleteOrdinaryAuthorizationRecordRevision(
  expected: OrdinaryAuthorizationRecord,
): Promise<void> {
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(
      ORDINARY_AUTHORIZATION_STORE,
      'readwrite',
    )
    const store = transaction.objectStore(ORDINARY_AUTHORIZATION_STORE)
    const current = (await requestResult(
      store.get(expected.slotKey),
      'record discard read',
    )) as OrdinaryAuthorizationRecord | undefined
    if (!current) {
      await transactionDone(transaction, 'idempotent record discard')
      return
    }
    if (
      current.revision !== expected.revision ||
      current.stateId !== expected.stateId ||
      !current.cleanupStarted
    ) {
      transaction.abort()
      throw new Error('ordinary browser authorization: discard was superseded')
    }
    store.delete(expected.slotKey)
    await transactionDone(transaction, 'record discard')
  } finally {
    db.close()
  }
}
