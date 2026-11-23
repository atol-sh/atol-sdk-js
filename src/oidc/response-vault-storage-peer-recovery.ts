import {
  assertCredentialGenerationSnapshot,
  currentCredentialAuthority,
  type CredentialGenerationSnapshot,
} from './credential-generation'
import {
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_SLOT_STORE as SLOT_STORE,
  ResponseVaultExecutionBusyError,
  type ResponseVaultBinding,
  type ResponseVaultBootstrapAuthority,
  type ResponseVaultCancellation,
  type ResponseVaultCustody,
  type ResponseVaultRecord,
} from './response-vault-model'
import {
  assertCancellationBinding,
  assertRecordBinding,
  publicCancellation,
} from './response-vault-storage-custody'
import { openDB, requestResult, transactionDone } from './response-vault-storage-db'
import {
  acquireExecutionLock,
  assertCustodyRevision,
  releaseOwnedExecutionLockIfHeld,
} from './response-vault-storage-lock'
import { randomOpaque, slotKey, validSlotRecord } from './response-vault-storage-validation'

export type ResponseVaultPeerTerminalAuthority =
  | { kind: 'bootstrap'; authority: ResponseVaultBootstrapAuthority }
  | { kind: 'transaction'; authority: ResponseVaultCancellation }

function isRejectionCustody(status: ResponseVaultCustody['status']): boolean {
  return status === 'rejecting' || status === 'reject_retry' || status === 'reject_blocked'
}

export function isExpiredPeerRecoveryCandidate(custody: ResponseVaultCustody): boolean {
  const mode = 'dpopKey' in custody ? custody.mode : custody.sourceMode
  return custody.expiresAt <= Date.now() && (
    mode === 'interactive' || isRejectionCustody(custody.status)
  )
}

async function checkExpiredPeerCustody(
  transaction: IDBTransaction,
  binding: ResponseVaultBinding,
  expected: ResponseVaultCustody,
  requester: CredentialGenerationSnapshot,
): Promise<ResponseVaultPeerTerminalAuthority> {
  const key = slotKey(binding)
  const slot = await requestResult(
    transaction.objectStore(SLOT_STORE).get(key),
    'expired peer slot read',
  ) as unknown
  const stored = await requestResult(
    transaction.objectStore(STORE).get(expected.reference.id),
    'expired peer custody read',
  ) as unknown
  const now = Date.now()
  assertCredentialGenerationSnapshot(binding, requester)
  const authority = currentCredentialAuthority(binding)
  if (
    authority.signedOut ||
    authority.generation !== requester.logout ||
    expected.credentialGeneration.logout !== requester.logout ||
    expected.credentialGeneration.tabOwner === requester.tabOwner ||
    expected.expiresAt > now ||
    !validSlotRecord(slot, key) ||
    slot.referenceId !== expected.reference.id ||
    slot.expiresAt !== expected.expiresAt
  ) {
    throw new ResponseVaultExecutionBusyError()
  }

  const validatePeer = (record: Pick<ResponseVaultRecord, 'revision' | 'expiresAt' | 'status' | 'credentialGeneration'>) => {
    assertCustodyRevision(expected, record.revision)
    if (
      record.status !== expected.status ||
      record.expiresAt !== expected.expiresAt ||
      record.credentialGeneration.logout !== expected.credentialGeneration.logout ||
      record.credentialGeneration.tabOwner !== expected.credentialGeneration.tabOwner
    ) {
      throw new ResponseVaultExecutionBusyError()
    }
  }
  if (expected.status === 'prepared' || expected.status === 'par_pending') {
    const record = stored as ResponseVaultRecord | undefined
    assertRecordBinding(record, expected.reference, binding, now, false, true)
    validatePeer(record)
    if (record.mode !== 'interactive') throw new ResponseVaultExecutionBusyError()
    return {
      kind: 'bootstrap',
      authority: {
        tabSecret: record.tabSecret,
        cancellationSecret: record.cancellationSecret,
        parIdempotencyKey: record.parIdempotencyKey,
        bootstrapAttemptCapability: record.bootstrapAttemptCapability,
      },
    }
  }
  assertCancellationBinding(stored, expected.reference, binding, now, false, true)
  validatePeer(stored)
  if (stored.custody === 'cancellation' ? !isRejectionCustody(stored.status) : stored.mode !== 'interactive') {
    throw new ResponseVaultExecutionBusyError()
  }
  return { kind: 'transaction', authority: publicCancellation(stored, expected.lifecycleEpoch) }
}

/** A peer tab can release only the exact expired custody the server proves terminal. */
export async function recoverExpiredPeerAuthorization(
  binding: ResponseVaultBinding,
  expected: ResponseVaultCustody,
  requester: CredentialGenerationSnapshot,
  probe: (candidate: ResponseVaultPeerTerminalAuthority) => Promise<'terminal' | 'nonterminal'>,
): Promise<boolean> {
  const owner = randomOpaque()
  await acquireExecutionLock(expected.reference, owner, false)
  try {
    const database = await openDB()
    try {
      // The Web Lock serializes this read/probe/delete with callback and
      // rejection claims. The durable grant owner and fence do not change.
      const read = database.transaction([STORE, SLOT_STORE], 'readonly')
      const candidate = await checkExpiredPeerCustody(read, binding, expected, requester)
      await transactionDone(read, 'expired peer custody read')
      if (await probe(candidate) !== 'terminal') {
        return false
      }
      const discard = database.transaction([STORE, SLOT_STORE], 'readwrite')
      await checkExpiredPeerCustody(discard, binding, expected, requester)
      discard.objectStore(SLOT_STORE).delete(slotKey(binding))
      discard.objectStore(STORE).delete(expected.reference.id)
      await transactionDone(discard, 'terminal peer custody discard')
      return true
    } finally {
      database.close()
    }
  } finally {
    await releaseOwnedExecutionLockIfHeld(expected.reference, owner)
  }
}
