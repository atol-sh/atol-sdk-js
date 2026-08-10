import { restoreDPoPKeyManager, type DPoPKeyManager } from '../dpop/dpop'
import {
  RESPONSE_VAULT_CANONICAL_OPAQUE as CANONICAL_OPAQUE,
  RESPONSE_VAULT_DEFAULT_EXECUTION_LEASE_MS as DEFAULT_EXECUTION_LEASE_MS,
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_SLOT_STORE as SLOT_STORE,
  RESPONSE_VAULT_STATUS_SCHEMA,
  type ResponseVaultAuthorization,
  type ResponseVaultAuthorizationStatus,
  type ResponseVaultBinding,
  type ResponseVaultExecutionClaim,
  type ResponseVaultRecord,
  type ResponseVaultReference,
  type ResponseVaultSettlement,
  type ResponseVaultSlotRecord,
} from './response-vault-model'
import {
  assertRecordBinding,
  assertReference,
  deleteExpired,
  publicAuthorization,
} from './response-vault-storage-custody'
import {
  openDB,
  requestResult,
  transactionDone,
} from './response-vault-storage-db'
import { assertExecutionClaim } from './response-vault-storage-execution'
import {
  assertCustodyRevision,
  assertHeldExecutionLock,
  releaseOwnedExecutionLock,
} from './response-vault-storage-lock'
import {
  slotKey,
  validRequestURI,
  validResponseVaultBinding,
  validResponseVaultTerminalProof,
  validSettlement,
  validSlotRecord,
} from './response-vault-storage-validation'

async function mutateRecord(
  reference: ResponseVaultReference,
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
  custody: ResponseVaultAuthorization,
  executionClaim: ResponseVaultExecutionClaim | undefined,
  expectedStatus:
    | ResponseVaultAuthorizationStatus
    | readonly ResponseVaultAuthorizationStatus[],
  operation: string,
  mutate: (record: ResponseVaultRecord) => void,
  requireCurrentGeneration = true,
  requireActiveSlot = true,
  allowExpiredBeforeMutation = false,
): Promise<ResponseVaultAuthorization> {
  assertReference(reference)
  if (!validResponseVaultBinding(binding)) {
    throw new Error('response vault: invalid authorization binding')
  }
  assertHeldExecutionLock(reference, executionClaim)
  const db = await openDB()
  let record: ResponseVaultRecord | undefined
  let activeSlot: ResponseVaultSlotRecord | undefined
  let retainedClaim: ResponseVaultExecutionClaim | undefined
  try {
    const tx = db.transaction([STORE, SLOT_STORE], 'readwrite')
    const store = tx.objectStore(STORE)
    record = (await requestResult(
      store.get(reference.id),
      `${operation} read`,
    )) as ResponseVaultRecord | undefined
    assertRecordBinding(
      record,
      reference,
      binding,
      Date.now(),
      requireCurrentGeneration,
      true,
    )
    assertCustodyRevision(custody, record.revision)
    if (
      record.expiresAt <= Date.now() &&
      RESPONSE_VAULT_STATUS_SCHEMA[record.status].locallyReapable &&
      !allowExpiredBeforeMutation
    ) {
      throw new Error(`response vault: ${operation} authority expired`)
    }
    if (requireActiveSlot) {
      activeSlot = (await requestResult(
        tx.objectStore(SLOT_STORE).get(slotKey(binding)),
        `${operation} slot read`,
      )) as ResponseVaultSlotRecord | undefined
      if (
        !validSlotRecord(activeSlot, slotKey(binding)) ||
        activeSlot.referenceId !== record.id ||
        activeSlot.expiresAt !== record.expiresAt
      ) {
        throw new Error(`response vault: ${operation} ownership mismatch`)
      }
    }
    retainedClaim = assertExecutionClaim(record, executionClaim, operation)
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
      Date.now() + DEFAULT_EXECUTION_LEASE_MS,
    )
    assertRecordBinding(
      record,
      reference,
      binding,
      Date.now(),
      requireCurrentGeneration,
      true,
    )
    record.revision++
    store.put(record)
    if (
      requireActiveSlot &&
      activeSlot &&
      activeSlot.expiresAt !== record.expiresAt
    ) {
      tx.objectStore(SLOT_STORE).put({
        ...activeSlot,
        expiresAt: record.expiresAt,
      } satisfies ResponseVaultSlotRecord)
    }
    deleteExpired(store, Date.now())
    await transactionDone(tx, operation)
  } finally {
    db.close()
  }
  let dpopKey: DPoPKeyManager
  try {
    dpopKey = restoreDPoPKeyManager(record.keys)
    if ((await dpopKey.thumbprint()) !== record.jkt) {
      throw new Error('response vault: stored key thumbprint mismatch')
    }
  } catch (error) {
    await releaseOwnedExecutionLock(
      reference,
      (executionClaim as ResponseVaultExecutionClaim).owner,
    )
    throw error
  }
  return publicAuthorization(record, dpopKey, lifecycleEpoch, retainedClaim)
}

export function bindResponseVaultPAR(
  authorization: ResponseVaultAuthorization,
  transactionId: string,
  requestUri: string,
  csrfToken: string,
  terminalProof: string,
  requestUriExpiresAt: number,
  transactionExpiresAt: number,
): Promise<ResponseVaultAuthorization> {
  if (
    !CANONICAL_OPAQUE.test(transactionId) ||
    !validRequestURI(requestUri) ||
    !CANONICAL_OPAQUE.test(csrfToken) ||
    !validResponseVaultTerminalProof(terminalProof) ||
    !Number.isSafeInteger(requestUriExpiresAt) ||
    !Number.isSafeInteger(transactionExpiresAt) ||
    requestUriExpiresAt > transactionExpiresAt
  ) {
    throw new Error('response vault: invalid pushed authorization response')
  }
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    ['par_pending', 'pushed'],
    'PAR binding',
    (record) => {
      if (record.status === 'par_pending') {
        record.status = 'pushed'
        record.transactionId = transactionId
        record.requestUri = requestUri
        record.csrfToken = csrfToken
        delete record.bootstrapTerminalProof
        record.terminalProof = terminalProof
        record.phaseExpiresAt = requestUriExpiresAt
        record.expiresAt = transactionExpiresAt
        return
      }
      if (
        record.transactionId !== transactionId ||
        record.requestUri !== requestUri ||
        record.csrfToken !== csrfToken ||
        record.terminalProof !== terminalProof
      ) {
        throw new Error('response vault: PAR replay binding mismatch')
      }
      record.phaseExpiresAt = Math.min(
        record.phaseExpiresAt as number,
        requestUriExpiresAt,
      )
      record.expiresAt = Math.min(record.expiresAt, transactionExpiresAt)
    },
    true,
    true,
    true,
  )
}

export function bindResponseVaultBootstrapAttempt(
  authorization: ResponseVaultAuthorization,
  attemptCapability: string,
  attemptExpiresAt: number,
): Promise<ResponseVaultAuthorization> {
  const now = Date.now()
  if (
    !validResponseVaultTerminalProof(attemptCapability) ||
    !Number.isSafeInteger(attemptExpiresAt) ||
    attemptExpiresAt <= now ||
    !Number.isSafeInteger(authorization.phaseExpiresAt) ||
    attemptExpiresAt > (authorization.phaseExpiresAt as number)
  ) {
    throw new Error('response vault: invalid bootstrap attempt capability')
  }
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'prepared',
    'bootstrap attempt binding',
    (record) => {
      if (
        record.bootstrapAttemptCapability !== undefined &&
        record.bootstrapAttemptCapability !== attemptCapability
      ) {
        throw new Error('response vault: bootstrap attempt capability mismatch')
      }
      record.bootstrapAttemptCapability = attemptCapability
      record.phaseExpiresAt = Math.min(
        record.phaseExpiresAt as number,
        attemptExpiresAt,
      )
    },
    true,
    true,
    true,
  )
}

export function bindResponseVaultBootstrap(
  authorization: ResponseVaultAuthorization,
  csrfToken: string,
  bootstrapTerminalProof: string,
  bootstrapExpiresAt: number,
): Promise<ResponseVaultAuthorization> {
  if (
    !CANONICAL_OPAQUE.test(csrfToken) ||
    !validResponseVaultTerminalProof(bootstrapTerminalProof) ||
    !Number.isSafeInteger(bootstrapExpiresAt)
  ) {
    throw new Error('response vault: invalid bootstrap response')
  }
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'prepared',
    'bootstrap binding',
    (record) => {
      const expiresAt = Math.min(record.expiresAt, bootstrapExpiresAt)
      record.status = 'par_pending'
      record.csrfToken = csrfToken
      record.bootstrapTerminalProof = bootstrapTerminalProof
      record.expiresAt = expiresAt
      record.phaseExpiresAt = expiresAt
    },
    true,
    true,
    true,
  )
}

export function markResponseVaultInitialized(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'initializing',
    'authorization init',
    (record) => {
      record.status = 'initialized'
      delete record.requestUri
      delete record.phaseExpiresAt
    },
  )
}

export function markResponseVaultInitializing(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'pushed',
    'authorization init begin',
    (record) => {
      if (
        !Number.isSafeInteger(record.phaseExpiresAt) ||
        (record.phaseExpiresAt as number) <= Date.now()
      ) {
        throw new Error(
          'response vault: pushed authorization request URI expired',
        )
      }
      record.status = 'initializing'
    },
  )
}

export function beginResponseVaultRelay(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'initialized',
    'relay begin',
    (record) => {
      record.status = 'redeeming'
    },
  )
}

export function retryResponseVaultRelay(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'relay_retry',
    'relay retry',
    (record) => {
      record.status = 'redeeming'
    },
  )
}

export function resetResponseVaultRelay(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'redeeming',
    'relay reset',
    (record) => {
      record.status = 'relay_retry'
    },
  )
}

export function recoverResponseVaultRelay(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'redeeming',
    'relay crash recovery',
    (record) => {
      record.status = 'relay_retry'
    },
  )
}

export function bindResponseVaultAcknowledgement(
  authorization: ResponseVaultAuthorization,
  csrfToken: string,
  settlement: ResponseVaultSettlement,
): Promise<ResponseVaultAuthorization> {
  if (!CANONICAL_OPAQUE.test(csrfToken) || !validSettlement(settlement)) {
    throw new Error('response vault: invalid acknowledgement binding')
  }
  if (authorization.status !== 'redeeming') {
    throw new Error('response vault: acknowledgement state mismatch')
  }
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    authorization.status,
    'acknowledgement binding',
    (record) => {
      record.status = 'awaiting_ack'
      record.csrfToken = csrfToken
      record.settlementKind = settlement.kind
      if (settlement.kind === 'error') {
        record.settlementErrorCode = settlement.errorCode
      } else {
        delete record.settlementErrorCode
      }
    },
  )
}

export function markResponseVaultPublishing(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'awaiting_ack',
    'publishing transition',
    (record) => {
      record.status = 'publishing'
    },
  )
}

export function beginResponseVaultFinalization(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'publishing',
    'finalization begin',
    (record) => {
      record.status = 'finalizing'
    },
  )
}

export function retryResponseVaultFinalization(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'finalizing',
    'finalization retry',
    () => undefined,
  )
}

export function markResponseVaultAdopted(
  authorization: ResponseVaultAuthorization,
): Promise<ResponseVaultAuthorization> {
  return mutateRecord(
    authorization.reference,
    authorization.binding,
    authorization.lifecycleEpoch,
    authorization,
    authorization.executionClaim,
    'finalizing',
    'finalization settlement',
    (record) => {
      record.status = 'adopted'
    },
  )
}
