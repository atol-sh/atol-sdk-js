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
  type ResponseVaultCancellation,
  type ResponseVaultCustody,
} from './response-vault-model'
import {
  assertCancellationBinding,
  publicCancellation,
} from './response-vault-storage-custody'
import { openDB, requestResult, transactionDone } from './response-vault-storage-db'
import {
  acquireExecutionLock,
  assertCustodyRevision,
  releaseOwnedExecutionLockIfHeld,
} from './response-vault-storage-lock'
import { randomOpaque, slotKey, validSlotRecord } from './response-vault-storage-validation'

async function checkExpiredPeerNavigation(
  transaction: IDBTransaction,
  binding: ResponseVaultBinding,
  expected: ResponseVaultCustody,
  requester: CredentialGenerationSnapshot,
) {
  const key = slotKey(binding)
  const slot = await requestResult(
    transaction.objectStore(SLOT_STORE).get(key),
    'expired navigation slot read',
  ) as unknown
  const stored = await requestResult(
    transaction.objectStore(STORE).get(expected.reference.id),
    'expired navigation custody read',
  ) as unknown
  const now = Date.now()
  assertCancellationBinding(stored, expected.reference, binding, now, false, true)
  assertCustodyRevision(expected, stored.revision)
  assertCredentialGenerationSnapshot(binding, requester)
  const authority = currentCredentialAuthority(binding)
  if (
    authority.signedOut ||
    authority.generation !== requester.logout ||
    stored.credentialGeneration.logout !== requester.logout ||
    stored.credentialGeneration.tabOwner === requester.tabOwner ||
    stored.custody !== undefined ||
    stored.mode !== 'interactive' ||
    stored.status !== 'navigating' ||
    stored.expiresAt > now ||
    !validSlotRecord(slot, key) ||
    slot.referenceId !== stored.id ||
    slot.expiresAt !== stored.expiresAt
  ) {
    throw new ResponseVaultExecutionBusyError()
  }
  return stored
}

/** A peer tab can release only the exact expired navigation the server proves terminal. */
export async function recoverExpiredPeerNavigation(
  binding: ResponseVaultBinding,
  expected: ResponseVaultCustody,
  requester: CredentialGenerationSnapshot,
  probe: (cancellation: ResponseVaultCancellation) => Promise<'terminal' | 'nonterminal'>,
): Promise<boolean> {
  const owner = randomOpaque()
  await acquireExecutionLock(expected.reference, owner, false)
  try {
    const database = await openDB()
    try {
      // Navigation owns its existing durable fence until the issuer proves
      // terminal state. The Web Lock serializes this read/probe/delete with
      // callback and rejection claims; no grant ownership changes here.
      const read = database.transaction([STORE, SLOT_STORE], 'readonly')
      const stored = await checkExpiredPeerNavigation(read, binding, expected, requester)
      await transactionDone(read, 'expired navigation read')
      if (await probe(publicCancellation(stored, expected.lifecycleEpoch)) !== 'terminal') {
        return false
      }
      const discard = database.transaction([STORE, SLOT_STORE], 'readwrite')
      await checkExpiredPeerNavigation(discard, binding, expected, requester)
      discard.objectStore(SLOT_STORE).delete(slotKey(binding))
      discard.objectStore(STORE).delete(expected.reference.id)
      await transactionDone(discard, 'terminal navigation discard')
      return true
    } finally {
      database.close()
    }
  } finally {
    await releaseOwnedExecutionLockIfHeld(expected.reference, owner)
  }
}
