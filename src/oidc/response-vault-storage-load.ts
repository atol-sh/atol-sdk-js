import { restoreDPoPKeyManager } from '../dpop/dpop'
import { assertCredentialGenerationSnapshot } from './credential-generation'
import {
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_RECORD_VERSION as RECORD_VERSION,
  RESPONSE_VAULT_SLOT_STORE as SLOT_STORE,
  RESPONSE_VAULT_STATUS_SCHEMA,
  ResponseVaultAuthorizationBusyError,
  type ResponseVaultActiveCustody,
  type ResponseVaultAuthorization,
  type ResponseVaultBinding,
  type ResponseVaultRecord,
  type ResponseVaultReference,
  type ResponseVaultSlotRecord,
} from './response-vault-model'
import {
  assertCancellationBinding,
  assertRecordBinding,
  publicAuthorization,
  publicCancellation,
  readRecord,
} from './response-vault-storage-custody'
import { openDB, requestResult, transactionDone } from './response-vault-storage-db'
import {
  classifyStoredRecord,
  clientOrigin,
  slotKey,
  validResponseVaultBinding,
  validSlotRecord,
} from './response-vault-storage-validation'

async function loadAuthorization(
  reference: ResponseVaultReference,
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
  requireCurrentGeneration: boolean,
  allowExpired = false,
): Promise<ResponseVaultAuthorization> {
  const record = await readRecord(reference)
  assertRecordBinding(
    record,
    reference,
    binding,
    Date.now(),
    requireCurrentGeneration,
    true,
  )
  if (
    !allowExpired &&
    record.expiresAt <= Date.now() &&
    RESPONSE_VAULT_STATUS_SCHEMA[record.status].locallyReapable
  ) {
    throw new Error('response vault: authorization authority expired')
  }
  const dpopKey = restoreDPoPKeyManager(record.keys)
  if ((await dpopKey.thumbprint()) !== record.jkt) {
    throw new Error('response vault: stored key thumbprint mismatch')
  }
  return publicAuthorization(record, dpopKey, lifecycleEpoch)
}

export function loadResponseVaultAuthorization(
  reference: ResponseVaultReference,
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
): Promise<ResponseVaultAuthorization> {
  return loadAuthorization(reference, binding, lifecycleEpoch, true)
}

export function loadResponseVaultAuthorizationForRejection(
  reference: ResponseVaultReference,
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
): Promise<ResponseVaultAuthorization> {
  return loadAuthorization(reference, binding, lifecycleEpoch, false, true)
}

interface ResponseVaultActiveRecord {
  slot: ResponseVaultSlotRecord
  record: ResponseVaultRecord | undefined
}

async function activeRecord(
  binding: ResponseVaultBinding,
): Promise<ResponseVaultActiveRecord | undefined> {
  const db = await openDB()
  try {
    const tx = db.transaction([STORE, SLOT_STORE], 'readonly')
    const key = slotKey(binding)
    const slot = (await requestResult(
      tx.objectStore(SLOT_STORE).get(key),
      'active authorization slot read',
    )) as unknown
    if (slot === undefined) {
      await transactionDone(tx, 'active authorization read')
      return undefined
    }
    if (!validSlotRecord(slot, key)) {
      throw new Error('response vault: active authorization slot is corrupt')
    }
    const record = (await requestResult(
      tx.objectStore(STORE).get(slot.referenceId),
      'active authorization record read',
    )) as ResponseVaultRecord | undefined
    await transactionDone(tx, 'active authorization read')
    return { slot, record }
  } finally {
    db.close()
  }
}

async function discardLocallyReapableActiveSlot(
  binding: ResponseVaultBinding,
  expected: ResponseVaultSlotRecord,
): Promise<void> {
  const db = await openDB()
  try {
    const tx = db.transaction([STORE, SLOT_STORE], 'readwrite')
    const slots = tx.objectStore(SLOT_STORE)
    const key = slotKey(binding)
    const current = (await requestResult(
      slots.get(key),
      'local authorization slot read',
    )) as unknown
    if (current !== undefined && !validSlotRecord(current, key)) {
      throw new Error('response vault: active authorization slot is corrupt')
    }
    if (
      current &&
      current.referenceId === expected.referenceId &&
      current.expiresAt === expected.expiresAt
    ) {
      const value = await requestResult(
        tx.objectStore(STORE).get(current.referenceId),
        'local authorization record read',
      )
      const now = Date.now()
      const classified = classifyStoredRecord(value, now, true)
      if (
        !classified ||
        classified.record.id !== current.referenceId ||
        classified.record.expiresAt !== current.expiresAt ||
        classified.record.expiresAt > now ||
        !RESPONSE_VAULT_STATUS_SCHEMA[
          classified.record.status
        ].locallyReapable
      ) {
        throw new Error(
          'response vault: active authorization slot is corrupt',
        )
      }
      slots.delete(key)
      tx.objectStore(STORE).delete(current.referenceId)
    }
    await transactionDone(tx, 'local authorization discard')
  } finally {
    db.close()
  }
}

export async function loadActiveResponseVaultAuthorization(
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
): Promise<ResponseVaultAuthorization | null> {
  const authorization =
    await loadActiveResponseVaultAuthorizationForRejection(
      binding,
      lifecycleEpoch,
    )
  if (!authorization) return null
  if (
    authorization.binding.issuer !== binding.issuer ||
    authorization.binding.clientId !== binding.clientId ||
    authorization.binding.redirectUri !== binding.redirectUri ||
    authorization.binding.audience !== binding.audience ||
    authorization.binding.scope !== binding.scope
  ) {
    throw new ResponseVaultAuthorizationBusyError()
  }
  assertCredentialGenerationSnapshot(
    binding,
    authorization.credentialGeneration,
  )
  return authorization
}

export async function loadActiveResponseVaultAuthorizationForRejection(
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
): Promise<ResponseVaultAuthorization | null> {
  if (!validResponseVaultBinding(binding)) {
    throw new Error('response vault: invalid authorization binding')
  }
  const active = await activeRecord(binding)
  if (!active) {
    return null
  }
  const { slot, record } = active
  const reference = { version: RECORD_VERSION, id: slot.referenceId } as const
  if (!record) {
    throw new Error('response vault: active authorization record is missing')
  }
  if (record.expiresAt !== slot.expiresAt) {
    throw new Error('response vault: active authorization slot is corrupt')
  }
  const storedBinding: ResponseVaultBinding = {
    issuer: record.issuer,
    clientId: record.clientId,
    redirectUri: record.redirectUri,
    audience: record.audience,
    scope: record.scope,
  }
  if (
    !validResponseVaultBinding(storedBinding) ||
    clientOrigin(storedBinding) !== clientOrigin(binding)
  ) {
    throw new Error('response vault: active authorization slot is corrupt')
  }
  assertRecordBinding(
    record,
    reference,
    storedBinding,
    Date.now(),
    false,
    true,
  )
  if (
    record.expiresAt <= Date.now() &&
    RESPONSE_VAULT_STATUS_SCHEMA[record.status].locallyReapable
  ) {
    await discardLocallyReapableActiveSlot(binding, slot)
    return null
  }
  const dpopKey = restoreDPoPKeyManager(record.keys)
  if ((await dpopKey.thumbprint()) !== record.jkt) {
    throw new Error('response vault: stored key thumbprint mismatch')
  }
  return publicAuthorization(record, dpopKey, lifecycleEpoch)
}

/**
 * Load the exact active custody while keeping grant restoration fail closed.
 *
 * A valid server cancellation capability remains usable when grant-only key
 * custody is damaged. The caller must reject that exact transaction before
 * surfacing grantError; only a fully restored and thumbprint-matched grant may
 * resume authorization.
 */
export async function loadActiveResponseVaultCustody(
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
): Promise<ResponseVaultActiveCustody> {
  if (!validResponseVaultBinding(binding)) {
    throw new Error('response vault: invalid authorization binding')
  }
  const active = await activeRecord(binding)
  if (!active) {
    return { custody: null }
  }
  const { slot, record } = active
  const reference = { version: RECORD_VERSION, id: slot.referenceId } as const
  const now = Date.now()
  if (!record) {
    throw new Error('response vault: active authorization record is missing')
  }
  if (record.expiresAt !== slot.expiresAt) {
    throw new Error('response vault: active authorization slot is corrupt')
  }
  const storedBinding: ResponseVaultBinding = {
    issuer: record.issuer,
    clientId: record.clientId,
    redirectUri: record.redirectUri,
    audience: record.audience,
    scope: record.scope,
  }
  if (
    !validResponseVaultBinding(storedBinding) ||
    clientOrigin(storedBinding) !== clientOrigin(binding)
  ) {
    throw new Error('response vault: active authorization slot is corrupt')
  }

  let grantError: unknown
  try {
    assertRecordBinding(
      record,
      reference,
      storedBinding,
      now,
      false,
      true,
    )
    if (
      record.expiresAt <= now &&
      RESPONSE_VAULT_STATUS_SCHEMA[record.status].locallyReapable
    ) {
      await discardLocallyReapableActiveSlot(binding, slot)
      return { custody: null }
    }
    const dpopKey = restoreDPoPKeyManager(record.keys)
    if ((await dpopKey.thumbprint()) !== record.jkt) {
      throw new Error('response vault: stored key thumbprint mismatch')
    }
    return {
      custody: publicAuthorization(record, dpopKey, lifecycleEpoch),
    }
  } catch (error) {
    grantError =
      error === undefined
        ? new Error('response vault: grant custody is corrupt')
        : error
  }

  try {
    assertCancellationBinding(
      record,
      reference,
      storedBinding,
      now,
      false,
      true,
    )
  } catch {
    throw grantError
  }
  return {
    custody: publicCancellation(record, lifecycleEpoch),
    grantError: record.custody === 'cancellation' ? undefined : grantError,
    rejectionOwner:
      record.status === 'navigating'
        ? record.navigationOwner
        : undefined,
  }
}
