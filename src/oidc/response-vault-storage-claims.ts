import { restoreDPoPKeyManager } from '../dpop/dpop'
import { credentialGenerationSnapshot } from './credential-generation'
import {
  RESPONSE_VAULT_CANONICAL_OPAQUE as CANONICAL_OPAQUE,
  RESPONSE_VAULT_DEFAULT_EXECUTION_LEASE_MS as DEFAULT_EXECUTION_LEASE_MS,
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_SLOT_STORE as SLOT_STORE,
  ResponseVaultExecutionBusyError,
  type MutableResponseVaultCancellationRecord,
  type ResponseVaultAuthorization,
  type ResponseVaultAuthorizationMode,
  type ResponseVaultAuthorizationStatus,
  type ResponseVaultCancellation,
  type ResponseVaultCustody,
  type ResponseVaultExecutionClaim,
  type ResponseVaultRecord,
  type ResponseVaultSlotRecord,
} from './response-vault-model'
import {
  assertCancellationBinding,
  assertRecordBinding,
  publicAuthorization,
  publicCancellation,
} from './response-vault-storage-custody'
import { openDB, requestResult, transactionDone } from './response-vault-storage-db'
import {
  assertExecutionClaim,
  validExecutionLeaseDuration,
} from './response-vault-storage-execution'
import {
  acquireExecutionLock,
  assertCustodyRevision,
  assertHeldExecutionLock,
  finishExecutionLockClaim,
  releaseOwnedExecutionLockIfHeld,
  withExecutionLockRelease,
} from './response-vault-storage-lock'
import {
  materializeCancellationRecord,
  sameCredentialGeneration,
  slotKey,
  validCancellationRecord,
  validSlotRecord,
  validStoredRecord,
} from './response-vault-storage-validation'

export async function beginResponseVaultNavigation(
  authorization: ResponseVaultAuthorization,
  navigationExpiresAt: number,
): Promise<ResponseVaultAuthorization> {
  if (
    !Number.isSafeInteger(navigationExpiresAt) ||
    navigationExpiresAt > authorization.expiresAt
  ) {
    throw new Error('response vault: invalid navigation deadline')
  }
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
        'navigation begin read',
      )) as ResponseVaultRecord | undefined
      const now = Date.now()
      assertRecordBinding(
        stored,
        authorization.reference,
        authorization.binding,
        now,
        true,
        true,
      )
      assertCustodyRevision(authorization, stored.revision)
      const claim = assertExecutionClaim(
        stored,
        authorization.executionClaim,
        'navigation begin',
      )
      if (stored.status !== 'initialized') {
        throw new Error('response vault: navigation state mismatch')
      }
      const activeSlot = (await requestResult(
        tx.objectStore(SLOT_STORE).get(slotKey(authorization.binding)),
        'navigation begin slot read',
      )) as ResponseVaultSlotRecord | undefined
      if (
        !validSlotRecord(activeSlot, slotKey(authorization.binding)) ||
        activeSlot.referenceId !== stored.id ||
        activeSlot.expiresAt !== stored.expiresAt
      ) {
        throw new ResponseVaultExecutionBusyError()
      }
      stored.status = 'navigating'
      stored.navigationOwner = claim.owner
      stored.navigationExpiresAt = navigationExpiresAt
      delete stored.executionOwner
      delete stored.executionExpiresAt
      stored.revision++
      if (!validStoredRecord(stored, now, true)) {
        throw new Error('response vault: navigation transition is invalid')
      }
      store.put(stored)
      await transactionDone(tx, 'navigation begin')
      return stored
    },
    () => db?.close(),
  )
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

/**
 * Claim a clean callback and fence relay before the first server request.
 * Interactive callbacks are already same-tab and generation bound. Iframe
 * callbacks additionally require the runtime that created the iframe.
 */
export async function claimResponseVaultNavigation(
  authorization: ResponseVaultAuthorization,
  owner: string,
  mode: ResponseVaultAuthorizationMode,
  leaseDurationMs = DEFAULT_EXECUTION_LEASE_MS,
): Promise<ResponseVaultAuthorization> {
  if (
    !CANONICAL_OPAQUE.test(owner) ||
    !validExecutionLeaseDuration(leaseDurationMs)
  ) {
    throw new Error('response vault: invalid navigation claim')
  }
  await acquireExecutionLock(
    authorization.reference,
    owner,
    false,
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
        'navigation claim read',
      )) as ResponseVaultRecord | undefined
      const now = Date.now()
      assertRecordBinding(
        record,
        authorization.reference,
        authorization.binding,
        now,
        true,
        true,
      )
      assertCustodyRevision(authorization, record.revision)
      if (
        record.status !== 'navigating' ||
        record.mode !== mode ||
        (mode === 'iframe' && record.navigationOwner !== owner)
      ) {
        throw new ResponseVaultExecutionBusyError()
      }
      const activeSlot = (await requestResult(
        tx.objectStore(SLOT_STORE).get(slotKey(authorization.binding)),
        'navigation claim slot read',
      )) as ResponseVaultSlotRecord | undefined
      if (
        !validSlotRecord(activeSlot, slotKey(authorization.binding)) ||
        activeSlot.referenceId !== record.id ||
        activeSlot.expiresAt !== record.expiresAt
      ) {
        throw new ResponseVaultExecutionBusyError()
      }
      if (record.executionFence >= Number.MAX_SAFE_INTEGER) {
        throw new Error('response vault: execution fence is exhausted')
      }
      record.executionFence++
      record.executionOwner = owner
      record.executionExpiresAt = now + leaseDurationMs
      record.status = 'redeeming'
      delete record.navigationOwner
      delete record.navigationExpiresAt
      record.revision++
      if (!validStoredRecord(record, now, true)) {
        throw new Error('response vault: navigation claim is invalid')
      }
      store.put(record)
      claim = { owner, fence: record.executionFence }
      await transactionDone(tx, 'navigation claim')
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

/**
 * Atomically fence a recovery/invalidation claimant and persist monotonic
 * rejection intent before any cancellation request is sent.
 */
export async function claimResponseVaultRejection(
  authorization: ResponseVaultCustody,
  owner: string,
  allowedStatuses: readonly ResponseVaultAuthorizationStatus[],
  leaseDurationMs = DEFAULT_EXECUTION_LEASE_MS,
  requireCurrentGeneration = true,
  requireActiveSlot = false,
  supersedeInvalidatedGeneration = false,
  requiredProvenance?: 'interactive_cancel',
): Promise<ResponseVaultCancellation> {
  if (
    !CANONICAL_OPAQUE.test(owner) ||
    allowedStatuses.length === 0 ||
    !validExecutionLeaseDuration(leaseDurationMs)
  ) {
    throw new Error('response vault: invalid rejection claim')
  }
  const acquiredLock = await acquireExecutionLock(
    authorization.reference,
    owner,
    supersedeInvalidatedGeneration,
  )
  let db: IDBDatabase | undefined
  let record: MutableResponseVaultCancellationRecord | undefined
  let claim: ResponseVaultExecutionClaim | undefined
  let retainedLock = false
  try {
    try {
      db = await openDB()
      const tx = db.transaction([STORE, SLOT_STORE], 'readwrite')
      const store = tx.objectStore(STORE)
      record = (await requestResult(
        store.get(authorization.reference.id),
        'rejection claim read',
      )) as MutableResponseVaultCancellationRecord | undefined
      const now = Date.now()
      assertCancellationBinding(
        record,
        authorization.reference,
        authorization.binding,
        now,
        requireCurrentGeneration,
        true,
      )
      assertCustodyRevision(authorization, record.revision)
      if (
        !allowedStatuses.includes(record.status) ||
        !record.transactionId
      ) {
        throw new ResponseVaultExecutionBusyError()
      }
      if (requiredProvenance === 'interactive_cancel') {
        const hasCancellationCustody =
          record.custody === 'cancellation'
        const provesInteractiveCancellation = hasCancellationCustody
          ? record.rejectionProvenance === 'interactive_cancel'
          : record.mode === 'interactive'
        if (!provesInteractiveCancellation) {
          throw new ResponseVaultExecutionBusyError()
        }
      }
      if (requireActiveSlot) {
        const activeSlot = (await requestResult(
          tx.objectStore(SLOT_STORE).get(slotKey(authorization.binding)),
          'rejection claim slot read',
        )) as ResponseVaultSlotRecord | undefined
        if (
          !validSlotRecord(activeSlot, slotKey(authorization.binding)) ||
          activeSlot.referenceId !== record.id ||
          activeSlot.expiresAt !== record.expiresAt
        ) {
          throw new ResponseVaultExecutionBusyError()
        }
      }
      let supersedesGeneration = false
      if (supersedeInvalidatedGeneration) {
        if (requireCurrentGeneration) {
          throw new Error(
            'response vault: invalid rejection supersession claim',
          )
        }
        supersedesGeneration = !sameCredentialGeneration(
          credentialGenerationSnapshot(authorization.binding),
          record.credentialGeneration,
        )
        if (!supersedesGeneration) {
          throw new ResponseVaultExecutionBusyError()
        }
      }
      const supplied = authorization.executionClaim
      const renewsExactClaim =
        !acquiredLock &&
        supplied?.owner === owner &&
        record.executionOwner === supplied.owner &&
        record.executionFence === supplied.fence
      if (record.status === 'navigating') {
        const ownsNavigation = record.navigationOwner === owner
        if (
          !ownsNavigation &&
          !supersedesGeneration
        ) {
          throw new ResponseVaultExecutionBusyError()
        }
      }
      if (!renewsExactClaim) {
        if (record.executionFence >= Number.MAX_SAFE_INTEGER) {
          throw new Error('response vault: execution fence is exhausted')
        }
        record.executionFence++
      }
      record.executionOwner = owner
      record.executionExpiresAt = now + leaseDurationMs
      record.status = 'rejecting'
      record.revision++
      record = materializeCancellationRecord(
        record,
        record.status,
        record.revision,
        true,
        requiredProvenance ??
          record.rejectionProvenance ??
          'internal',
      )
      if (!validCancellationRecord(record, now, true)) {
        throw new Error('response vault: rejection claim is invalid')
      }
      store.put(record)
      claim = { owner, fence: record.executionFence }
      await transactionDone(tx, 'rejection claim')
    } finally {
      db?.close()
    }
    const claimed = publicCancellation(
      record,
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

/**
 * Fence an authenticated, non-mutating terminal-status probe for a cleanly
 * published transaction. The status remains `published`; only an exact server
 * terminal response may authorize deletion.
 */
export async function claimResponseVaultTerminalProbe(
  cancellation: ResponseVaultCancellation,
  owner: string,
  leaseDurationMs = DEFAULT_EXECUTION_LEASE_MS,
): Promise<ResponseVaultCancellation> {
  if (
    !CANONICAL_OPAQUE.test(owner) ||
    !validExecutionLeaseDuration(leaseDurationMs)
  ) {
    throw new Error('response vault: invalid terminal probe claim')
  }
  await acquireExecutionLock(
    cancellation.reference,
    owner,
    false,
  )
  let db: IDBDatabase | undefined
  let record: MutableResponseVaultCancellationRecord | undefined
  let claim: ResponseVaultExecutionClaim | undefined
  let retainedLock = false
  try {
    try {
      db = await openDB()
      const tx = db.transaction(STORE, 'readwrite')
      const store = tx.objectStore(STORE)
      record = (await requestResult(
        store.get(cancellation.reference.id),
        'terminal probe claim read',
      )) as MutableResponseVaultCancellationRecord | undefined
      const now = Date.now()
      assertCancellationBinding(
        record,
        cancellation.reference,
        cancellation.binding,
        now,
        true,
        true,
      )
      assertCustodyRevision(cancellation, record.revision)
      if (record.status !== 'published') {
        throw new ResponseVaultExecutionBusyError()
      }
      if (record.executionFence >= Number.MAX_SAFE_INTEGER) {
        throw new Error('response vault: execution fence is exhausted')
      }
      record.executionFence++
      record.executionOwner = owner
      record.executionExpiresAt = now + leaseDurationMs
      record.revision++
      record = materializeCancellationRecord(record)
      if (!validCancellationRecord(record, now, true)) {
        throw new Error('response vault: terminal probe claim is invalid')
      }
      store.put(record)
      claim = { owner, fence: record.executionFence }
      await transactionDone(tx, 'terminal probe claim')
    } finally {
      db?.close()
    }
    const claimed = publicCancellation(
      record,
      cancellation.lifecycleEpoch,
      claim,
    )
    retainedLock = true
    return claimed
  } finally {
    try {
      if (!retainedLock) {
        await releaseOwnedExecutionLockIfHeld(cancellation.reference, owner)
      }
    } finally {
      finishExecutionLockClaim(cancellation.reference, owner)
    }
  }
}
