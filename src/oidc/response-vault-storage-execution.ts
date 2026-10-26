import {
  dpopKeyPair,
  restoreDPoPKeyManager,
  type DPoPKeyManager,
} from '../dpop/dpop'
import {
  assertCredentialGenerationSnapshot,
  credentialGenerationSnapshot,
  currentCredentialAuthority,
  isCredentialGeneration,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import {
  RESPONSE_VAULT_CANONICAL_OPAQUE as CANONICAL_OPAQUE,
  RESPONSE_VAULT_DEFAULT_EXECUTION_LEASE_MS as DEFAULT_EXECUTION_LEASE_MS,
  RESPONSE_VAULT_MAX_EXECUTION_LEASE_MS as MAX_EXECUTION_LEASE_MS,
  RESPONSE_VAULT_PRE_TRANSACTION_TTL_MS as PRE_TRANSACTION_TTL_MS,
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_RECORD_VERSION as RECORD_VERSION,
  RESPONSE_VAULT_SLOT_STORE as SLOT_STORE,
  RESPONSE_VAULT_STATUS_SCHEMA,
  ResponseVaultAuthorizationBusyError,
  ResponseVaultExecutionBusyError,
  type MutableResponseVaultCancellationRecord,
  type ResponseVaultAuthorization,
  type ResponseVaultAuthorizationMode,
  type ResponseVaultAuthorizationStatus,
  type ResponseVaultBinding,
  type ResponseVaultCancellation,
  type ResponseVaultExecutionClaim,
  type ResponseVaultExactGenerationSupersession,
  type ResponseVaultIntent,
  type ResponseVaultRecord,
  type ResponseVaultSecrets,
  type ResponseVaultSlotRecord,
} from './response-vault-model'
import {
  assertCancellationBinding,
  assertRecordBinding,
  deleteExpired,
  publicAuthorization,
  publicCancellation,
} from './response-vault-storage-custody'
import { openDB, requestResult, transactionDone } from './response-vault-storage-db'
import {
  acquireExecutionLock,
  assertCustodyRevision,
  assertHeldExecutionLock,
  finishExecutionLockClaim,
  releaseOwnedExecutionLockIfHeld,
  rememberCustodyRevision,
  withExecutionLockRelease,
} from './response-vault-storage-lock'
import {
  classifyStoredRecord,
  randomOpaque,
  sameCredentialGeneration,
  slotKey,
  validCancellationRecord,
  validResponseVaultBinding,
  validResponseVaultIntent,
  validSecrets,
  validSlotRecord,
  validStoredRecord,
} from './response-vault-storage-validation'

export async function stageResponseVaultAuthorization(
  dpopKey: DPoPKeyManager,
  binding: ResponseVaultBinding,
  mode: ResponseVaultAuthorizationMode,
  intent: ResponseVaultIntent,
  lifecycleEpoch: number,
  secrets: ResponseVaultSecrets,
  expectedGeneration?: CredentialGenerationSnapshot,
): Promise<ResponseVaultAuthorization> {
  if (
    !validResponseVaultBinding(binding) ||
    !validResponseVaultIntent(intent, binding.redirectUri) ||
    !validSecrets(secrets) ||
    !Number.isSafeInteger(lifecycleEpoch) ||
    lifecycleEpoch < 0
  ) {
    throw new Error('response vault: invalid authorization input')
  }
  const now = Date.now()
  const generation = credentialGenerationSnapshot(binding)
  if (
    expectedGeneration !== undefined &&
    !sameCredentialGeneration(generation, expectedGeneration)
  ) {
    throw new Error('response vault: authorization authority was superseded')
  }
  const id = randomOpaque()
  const jkt = await dpopKey.thumbprint()
  assertCredentialGenerationSnapshot(binding, generation)
  if (!CANONICAL_OPAQUE.test(id) || !CANONICAL_OPAQUE.test(jkt)) {
    throw new Error('response vault: non-canonical authorization key')
  }
  const expiresAt = now + PRE_TRANSACTION_TTL_MS
  const record: ResponseVaultRecord = {
    version: RECORD_VERSION,
    revision: 1,
    id,
    issuer: binding.issuer,
    clientId: binding.clientId,
    redirectUri: binding.redirectUri,
    audience: binding.audience,
    scope: binding.scope,
    mode,
    prompt: intent.prompt,
    maxAge: intent.maxAge,
    acrValues: intent.acrValues,
    organizationId: intent.organizationId,
    returnTo: intent.returnTo,
    credentialGeneration: generation,
    status: 'prepared',
    jkt,
    ...secrets,
    createdAt: now,
    expiresAt,
    phaseExpiresAt: expiresAt,
    executionFence: 0,
    keys: dpopKeyPair(dpopKey),
  }
  const db = await openDB()
  try {
    const tx = db.transaction([STORE, SLOT_STORE], 'readwrite')
    const store = tx.objectStore(STORE)
    const slots = tx.objectStore(SLOT_STORE)
    const key = slotKey(binding)
    const occupied = (await requestResult(
      slots.get(key),
      'authorization slot read',
    )) as unknown
    if (occupied !== undefined && !validSlotRecord(occupied, key)) {
      throw new Error('response vault: active authorization slot is corrupt')
    }
    if (occupied) {
      const occupiedRecord = (await requestResult(
        store.get(occupied.referenceId),
        'authorization slot record read',
      )) as ResponseVaultRecord | undefined
      if (!occupiedRecord) {
        throw new Error(
          'response vault: active authorization record is missing',
        )
      } else {
        const classified = classifyStoredRecord(occupiedRecord, now, true)
        if (
          occupiedRecord.id !== occupied.referenceId ||
          occupiedRecord.expiresAt !== occupied.expiresAt ||
          !classified
        ) {
          throw new Error(
            'response vault: active authorization slot is corrupt',
          )
        }
        if (occupied.expiresAt > now) {
          throw new ResponseVaultAuthorizationBusyError()
        }
        if (
          !RESPONSE_VAULT_STATUS_SCHEMA[
            classified.record.status
          ].locallyReapable
        ) {
          throw new ResponseVaultAuthorizationBusyError()
        }
        slots.delete(key)
        store.delete(occupied.referenceId)
      }
    }
    deleteExpired(store, now)
    store.add(record)
    slots.put({
      version: RECORD_VERSION,
      key,
      referenceId: id,
      expiresAt: record.expiresAt,
    } satisfies ResponseVaultSlotRecord)
    await transactionDone(tx, 'authorization stage')
  } finally {
    db.close()
  }
  return publicAuthorization(record, dpopKey, lifecycleEpoch)
}

export function validExecutionLeaseDuration(value: number): boolean {
  return (
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= MAX_EXECUTION_LEASE_MS
  )
}

export function assertExecutionClaim(
  record: Pick<
    ResponseVaultRecord,
    'executionOwner' | 'executionFence' | 'executionExpiresAt'
  >,
  claim: ResponseVaultExecutionClaim | undefined,
  operation: string,
): ResponseVaultExecutionClaim {
  if (
    !claim ||
    !CANONICAL_OPAQUE.test(claim.owner) ||
    !Number.isSafeInteger(claim.fence) ||
    claim.fence < 1 ||
    record.executionOwner !== claim.owner ||
    record.executionFence !== claim.fence
  ) {
    throw new ResponseVaultExecutionBusyError()
  }
  if (record.executionExpiresAt === undefined) {
    throw new Error(`response vault: ${operation} execution lease is corrupt`)
  }
  return claim
}

/**
 * Atomically acquire the right to execute one durable authorization.
 *
 * The monotonically increasing fence prevents a stale runtime from mutating
 * or deleting custody after another runtime takes over an expired lease.
 */
export async function claimResponseVaultExecution(
  authorization: ResponseVaultAuthorization,
  owner: string,
  allowedStatuses: readonly ResponseVaultAuthorizationStatus[],
  leaseDurationMs = DEFAULT_EXECUTION_LEASE_MS,
  requireCurrentGeneration = true,
  requireActiveSlot = true,
  supersedeInvalidatedGeneration = false,
  exactSupersession?: ResponseVaultExactGenerationSupersession,
): Promise<ResponseVaultAuthorization> {
  if (
    !CANONICAL_OPAQUE.test(owner) ||
    allowedStatuses.length === 0 ||
    allowedStatuses.includes('navigating') ||
    !validExecutionLeaseDuration(leaseDurationMs) ||
    (
      exactSupersession !== undefined &&
      (
        !supersedeInvalidatedGeneration ||
        requireCurrentGeneration ||
        !isCredentialGeneration(
          exactSupersession.signedOutLogoutGeneration,
        ) ||
        !isCredentialGeneration(
          exactSupersession.invalidatedGeneration.logout,
        ) ||
        !isCredentialGeneration(
          exactSupersession.invalidatedGeneration.tabOwner,
        )
      )
    )
  ) {
    throw new Error('response vault: invalid execution claim')
  }
  const acquiredLock = await acquireExecutionLock(
    authorization.reference,
    owner,
    supersedeInvalidatedGeneration,
  )
  let db: IDBDatabase | undefined
  let record: ResponseVaultRecord | undefined
  let claim: ResponseVaultExecutionClaim | undefined
  let retainedLock = false
  try {
    try {
      db = await openDB()
      const tx = db.transaction([STORE, SLOT_STORE], 'readwrite')
      const store = tx.objectStore(STORE)
      record = (await requestResult(
        store.get(authorization.reference.id),
        'execution claim read',
      )) as ResponseVaultRecord | undefined
      const now = Date.now()
      assertRecordBinding(
        record,
        authorization.reference,
        authorization.binding,
        now,
        requireCurrentGeneration,
        true,
      )
      assertCustodyRevision(authorization, record.revision)
      if (
        record.expiresAt <= now &&
        RESPONSE_VAULT_STATUS_SCHEMA[record.status].locallyReapable
      ) {
        throw new ResponseVaultExecutionBusyError()
      }
      if (!allowedStatuses.includes(record.status)) {
        throw new ResponseVaultExecutionBusyError()
      }
      if (requireActiveSlot) {
        const activeSlot = (await requestResult(
          tx.objectStore(SLOT_STORE).get(slotKey(authorization.binding)),
          'execution claim slot read',
        )) as ResponseVaultSlotRecord | undefined
        if (
          !validSlotRecord(activeSlot, slotKey(authorization.binding)) ||
          activeSlot.referenceId !== record.id ||
          activeSlot.expiresAt !== record.expiresAt
        ) {
          throw new ResponseVaultExecutionBusyError()
        }
      }
      const supplied = authorization.executionClaim
      const renewsExactClaim =
        !acquiredLock &&
        supplied?.owner === owner &&
        record.executionOwner === supplied.owner &&
        record.executionFence === supplied.fence
      if (supersedeInvalidatedGeneration) {
        if (requireCurrentGeneration) {
          throw new Error(
            'response vault: invalid generation supersession claim',
          )
        }
        if (exactSupersession) {
          const currentAuthority = currentCredentialAuthority(
            authorization.binding,
          )
          if (
            !currentAuthority.signedOut ||
            currentAuthority.generation !==
              exactSupersession.signedOutLogoutGeneration ||
            record.mode !== exactSupersession.mode ||
            !sameCredentialGeneration(
              record.credentialGeneration,
              exactSupersession.invalidatedGeneration,
            ) ||
            record.credentialGeneration.logout ===
              exactSupersession.signedOutLogoutGeneration
          ) {
            throw new ResponseVaultExecutionBusyError()
          }
        } else {
          const currentGeneration = credentialGenerationSnapshot(
            authorization.binding,
          )
          const supersedesGeneration = !sameCredentialGeneration(
            currentGeneration,
            record.credentialGeneration,
          )
          if (!supersedesGeneration) {
            throw new ResponseVaultExecutionBusyError()
          }
        }
      }
      if (!renewsExactClaim) {
        if (record.executionFence >= Number.MAX_SAFE_INTEGER) {
          throw new Error('response vault: execution fence is exhausted')
        }
        record.executionFence++
      }
      const executionExpiresAt = now + leaseDurationMs
      record.executionOwner = owner
      record.executionExpiresAt = executionExpiresAt
      record.revision++
      if (!validStoredRecord(record, now, true)) {
        throw new Error('response vault: execution claim is invalid')
      }
      store.put(record)
      claim = { owner, fence: record.executionFence }
      await transactionDone(tx, 'execution claim')
    } finally {
      db?.close()
    }
    const dpopKey = restoreDPoPKeyManager(record.keys)
    if ((await dpopKey.thumbprint()) !== record.jkt) {
      throw new Error('response vault: stored key thumbprint mismatch')
    }
    const claimed = publicAuthorization(
      record,
      dpopKey,
      authorization.lifecycleEpoch,
      claim,
    )
    retainedLock = true
    return claimed
  } finally {
    try {
      if (!retainedLock) {
        await releaseOwnedExecutionLockIfHeld(authorization.reference, owner)
      }
    } finally {
      finishExecutionLockClaim(authorization.reference, owner)
    }
  }
}

export async function releaseResponseVaultExecution(
  authorization: ResponseVaultAuthorization,
  requireActiveSlot = true,
  requireCurrentGeneration = true,
): Promise<ResponseVaultAuthorization> {
  assertHeldExecutionLock(
    authorization.reference,
    authorization.executionClaim,
  )
  let db: IDBDatabase | undefined
  const record = await withExecutionLockRelease(
    authorization.reference,
    authorization.executionClaim,
    async () => {
      db = await openDB()
      const tx = db.transaction([STORE, SLOT_STORE], 'readwrite')
      const store = tx.objectStore(STORE)
      const stored = (await requestResult(
        store.get(authorization.reference.id),
        'execution release read',
      )) as ResponseVaultRecord | undefined
      assertRecordBinding(
        stored,
        authorization.reference,
        authorization.binding,
        Date.now(),
        requireCurrentGeneration,
        true,
      )
      assertCustodyRevision(authorization, stored.revision)
      assertExecutionClaim(
        stored,
        authorization.executionClaim,
        'execution release',
      )
      if (requireActiveSlot) {
        const activeSlot = (await requestResult(
          tx.objectStore(SLOT_STORE).get(slotKey(authorization.binding)),
          'execution release slot read',
        )) as ResponseVaultSlotRecord | undefined
        if (
          !validSlotRecord(activeSlot, slotKey(authorization.binding)) ||
          activeSlot.referenceId !== stored.id ||
          activeSlot.expiresAt !== stored.expiresAt
        ) {
          throw new ResponseVaultExecutionBusyError()
        }
      }
      delete stored.executionOwner
      delete stored.executionExpiresAt
      stored.revision++
      store.put(stored)
      await transactionDone(tx, 'execution release')
      return stored
    },
    () => db?.close(),
  )
  rememberCustodyRevision(authorization, record.revision)
  const dpopKey = restoreDPoPKeyManager(record.keys)
  if ((await dpopKey.thumbprint()) !== record.jkt) {
    throw new Error('response vault: stored key thumbprint mismatch')
  }
  return publicAuthorization(
    record,
    dpopKey,
    authorization.lifecycleEpoch,
  )
}

export async function releaseResponseVaultCancellationExecution(
  cancellation: ResponseVaultCancellation,
): Promise<ResponseVaultCancellation> {
  assertHeldExecutionLock(
    cancellation.reference,
    cancellation.executionClaim,
  )
  let db: IDBDatabase | undefined
  const record = await withExecutionLockRelease(
    cancellation.reference,
    cancellation.executionClaim,
    async () => {
      db = await openDB()
      const tx = db.transaction(STORE, 'readwrite')
      const store = tx.objectStore(STORE)
      const stored = (await requestResult(
        store.get(cancellation.reference.id),
        'cancellation execution release read',
      )) as MutableResponseVaultCancellationRecord | undefined
      const now = Date.now()
      assertCancellationBinding(
        stored,
        cancellation.reference,
        cancellation.binding,
        now,
        false,
        true,
      )
      assertCustodyRevision(cancellation, stored.revision)
      assertExecutionClaim(
        stored,
        cancellation.executionClaim,
        'cancellation execution release',
      )
      delete stored.executionOwner
      delete stored.executionExpiresAt
      stored.revision++
      if (!validCancellationRecord(stored, now, true)) {
        throw new Error(
          'response vault: cancellation execution release binding mismatch',
        )
      }
      store.put(stored)
      await transactionDone(tx, 'cancellation execution release')
      return stored
    },
    () => db?.close(),
  )
  rememberCustodyRevision(cancellation, record.revision)
  return publicCancellation(record, cancellation.lifecycleEpoch)
}

/**
 * Atomically release execution authority immediately before navigation while
 * retaining a distinct callback owner and deadline.
 */
