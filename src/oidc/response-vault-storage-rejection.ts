import {
  RESPONSE_VAULT_CANONICAL_OPAQUE as CANONICAL_OPAQUE,
  RESPONSE_VAULT_DEFAULT_EXECUTION_LEASE_MS as DEFAULT_EXECUTION_LEASE_MS,
  RESPONSE_VAULT_RECORD_STORE as STORE,
  type MutableResponseVaultCancellationRecord,
  type ResponseVaultAuthorizationStatus,
  type ResponseVaultCancellation,
  type ResponseVaultCustody,
  type ResponseVaultExecutionClaim,
} from './response-vault-model'
import {
  assertCancellationBinding,
  assertReference,
  publicCancellation,
} from './response-vault-storage-custody'
import { openDB, requestResult, transactionDone } from './response-vault-storage-db'
import { assertExecutionClaim } from './response-vault-storage-execution'
import {
  assertCustodyRevision,
  assertHeldExecutionLock,
} from './response-vault-storage-lock'
import {
  materializeCancellationRecord,
  validCancellationRecord,
  validResponseVaultBinding,
} from './response-vault-storage-validation'

async function mutateCancellationRecord(
  cancellation: ResponseVaultCustody,
  expectedStatus:
    | ResponseVaultAuthorizationStatus
    | readonly ResponseVaultAuthorizationStatus[],
  operation: string,
  mutate: (record: MutableResponseVaultCancellationRecord) => void,
): Promise<ResponseVaultCancellation> {
  assertReference(cancellation.reference)
  if (!validResponseVaultBinding(cancellation.binding)) {
    throw new Error('response vault: invalid cancellation binding')
  }
  assertHeldExecutionLock(
    cancellation.reference,
    cancellation.executionClaim,
  )
  const db = await openDB()
  let record: MutableResponseVaultCancellationRecord | undefined
  let retainedClaim: ResponseVaultExecutionClaim | undefined
  try {
    const tx = db.transaction(STORE, 'readwrite')
    const store = tx.objectStore(STORE)
    record = (await requestResult(
      store.get(cancellation.reference.id),
      `${operation} read`,
    )) as MutableResponseVaultCancellationRecord | undefined
    const now = Date.now()
    assertCancellationBinding(
      record,
      cancellation.reference,
      cancellation.binding,
      now,
      false,
      true,
    )
    assertCustodyRevision(cancellation, record.revision)
    retainedClaim = assertExecutionClaim(
      record,
      cancellation.executionClaim,
      operation,
    )
    const statusMatches =
      typeof expectedStatus === 'string'
        ? record.status === expectedStatus
        : expectedStatus.includes(record.status)
    if (!statusMatches) {
      throw new Error(`response vault: ${operation} state mismatch`)
    }
    mutate(record)
    record.executionExpiresAt = Math.max(
      record.executionExpiresAt as number,
      now + DEFAULT_EXECUTION_LEASE_MS,
    )
    record.revision++
    record = materializeCancellationRecord(record)
    if (!validCancellationRecord(record, now, true)) {
      throw new Error(`response vault: ${operation} binding mismatch`)
    }
    store.put(record)
    await transactionDone(tx, operation)
  } finally {
    db.close()
  }
  return publicCancellation(
    record,
    cancellation.lifecycleEpoch,
    retainedClaim,
  )
}

/**
 * Persist the intent to revoke and consume a server-side transaction before
 * sending the rejection request. Rejection is monotonic, so this transition
 * deliberately remains available after local credential authority rotates.
 */
export function beginResponseVaultRejection(
  authorization: ResponseVaultCustody,
): Promise<ResponseVaultCancellation> {
  if (
    !authorization.transactionId ||
    !CANONICAL_OPAQUE.test(authorization.transactionId)
  ) {
    throw new Error('response vault: rejection binding is incomplete')
  }
  return mutateCancellationRecord(
    authorization,
    [
      'pushed',
      'initializing',
      'initialized',
      'redeeming',
      'relay_retry',
      'awaiting_ack',
      'publishing',
      'finalizing',
      'adopted',
      'published',
      'rejecting',
      'reject_retry',
      'reject_blocked',
    ],
    'rejection begin',
    (record) => {
      record.status = 'rejecting'
    },
  )
}

export function retryResponseVaultRejection(
  authorization: ResponseVaultCancellation,
): Promise<ResponseVaultCancellation> {
  return mutateCancellationRecord(
    authorization,
    'reject_retry',
    'rejection retry',
    (record) => {
      record.status = 'rejecting'
    },
  )
}

export function resetResponseVaultRejection(
  authorization: ResponseVaultCancellation,
): Promise<ResponseVaultCancellation> {
  return mutateCancellationRecord(
    authorization,
    'rejecting',
    'rejection reset',
    (record) => {
      record.status = 'reject_retry'
    },
  )
}

export function blockResponseVaultRejection(
  authorization: ResponseVaultCancellation,
): Promise<ResponseVaultCancellation> {
  return mutateCancellationRecord(
    authorization,
    'rejecting',
    'rejection blocked',
    (record) => {
      record.status = 'reject_blocked'
    },
  )
}
