import {
  currentCredentialAuthority,
  isCredentialGeneration,
} from './credential-generation'
import {
  RESPONSE_VAULT_CANONICAL_OPAQUE as CANONICAL_OPAQUE,
  RESPONSE_VAULT_DEFAULT_EXECUTION_LEASE_MS as DEFAULT_EXECUTION_LEASE_MS,
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_SLOT_STORE as SLOT_STORE,
  ResponseVaultExecutionBusyError,
  type MutableResponseVaultCancellationRecord,
  type ResponseVaultCancellation,
  type ResponseVaultExecutionClaim,
  type ResponseVaultExactGenerationSupersession,
  type ResponseVaultSlotRecord,
} from './response-vault-model'
import {
  assertCancellationBinding,
  publicCancellation,
} from './response-vault-storage-custody'
import { openDB, requestResult, transactionDone } from './response-vault-storage-db'
import { validExecutionLeaseDuration } from './response-vault-storage-execution'
import {
  acquireExecutionLock,
  assertCustodyRevision,
  finishExecutionLockClaim,
  releaseOwnedExecutionLockIfHeld,
} from './response-vault-storage-lock'
import {
  materializeCancellationRecord,
  sameCredentialGeneration,
  slotKey,
  validCancellationRecord,
  validSlotRecord,
} from './response-vault-storage-validation'

/**
 * Fence a non-mutating terminal probe for an exact failed-initialization
 * cancellation whose mutating rejection was conclusively refused.
 */
export async function claimFailedInitializationTerminalProbe(
  cancellation: ResponseVaultCancellation,
  owner: string,
  requiredProvenance: 'interactive_cancel' | 'failed_init_cancel',
  leaseDurationMs = DEFAULT_EXECUTION_LEASE_MS,
  exactSupersession?: ResponseVaultExactGenerationSupersession,
): Promise<ResponseVaultCancellation> {
  const requiredMode =
    requiredProvenance === 'interactive_cancel'
      ? 'interactive'
      : 'iframe'
  if (
    !CANONICAL_OPAQUE.test(owner) ||
    !validExecutionLeaseDuration(leaseDurationMs) ||
    (
      exactSupersession !== undefined &&
      (
        exactSupersession.mode !== requiredMode ||
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
    throw new Error(
      'response vault: invalid failed-init terminal probe claim',
    )
  }
  await acquireExecutionLock(
    cancellation.reference,
    owner,
    exactSupersession !== undefined,
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
        store.get(cancellation.reference.id),
        'failed-init terminal probe claim read',
      )) as MutableResponseVaultCancellationRecord | undefined
      const now = Date.now()
      assertCancellationBinding(
        record,
        cancellation.reference,
        cancellation.binding,
        now,
        exactSupersession === undefined,
        true,
      )
      assertCustodyRevision(cancellation, record.revision)
      if (exactSupersession) {
        const currentAuthority = currentCredentialAuthority(
          cancellation.binding,
        )
        if (
          !currentAuthority.signedOut ||
          currentAuthority.generation !==
            exactSupersession.signedOutLogoutGeneration ||
          !sameCredentialGeneration(
            record.credentialGeneration,
            exactSupersession.invalidatedGeneration,
          ) ||
          record.credentialGeneration.logout ===
            exactSupersession.signedOutLogoutGeneration
        ) {
          throw new ResponseVaultExecutionBusyError()
        }
      }
      if (
        record.custody !== 'cancellation' ||
        record.status !== 'reject_blocked' ||
        record.rejectionProvenance !== requiredProvenance
      ) {
        throw new ResponseVaultExecutionBusyError()
      }
      const activeSlot = (await requestResult(
        tx.objectStore(SLOT_STORE).get(slotKey(cancellation.binding)),
        'failed-init terminal probe slot read',
      )) as ResponseVaultSlotRecord | undefined
      if (
        !validSlotRecord(activeSlot, slotKey(cancellation.binding)) ||
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
      record.revision++
      record = materializeCancellationRecord(record)
      if (!validCancellationRecord(record, now, true)) {
        throw new Error(
          'response vault: failed-init terminal probe claim is invalid',
        )
      }
      store.put(record)
      claim = { owner, fence: record.executionFence }
      await transactionDone(tx, 'failed-init terminal probe claim')
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
        await releaseOwnedExecutionLockIfHeld(
          cancellation.reference,
          owner,
        )
      }
    } finally {
      finishExecutionLockClaim(cancellation.reference, owner)
    }
  }
}
