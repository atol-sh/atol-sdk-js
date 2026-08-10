import {
  RESPONSE_VAULT_CANONICAL_OPAQUE as CANONICAL_OPAQUE,
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_RECORD_VERSION as RECORD_VERSION,
  RESPONSE_VAULT_SLOT_STORE as SLOT_STORE,
  ResponseVaultExecutionBusyError,
  type MutableResponseVaultCancellationRecord,
  type ResponseVaultAuthorization,
  type ResponseVaultBinding,
  type ResponseVaultCancellation,
  type ResponseVaultCancellationBatch,
  type ResponseVaultCustody,
  type ResponseVaultRecord,
  type ResponseVaultSlotRecord,
} from './response-vault-model'
import {
  assertCancellationBinding,
  assertRecordBinding,
  assertReference,
  publicCancellation,
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
  withExecutionLockRelease,
} from './response-vault-storage-lock'
import {
  clientOrigin,
  materializeCancellationRecord,
  recordBinding,
  slotKey,
  validCancellationRecord,
  validResponseVaultBinding,
  validSlotRecord,
} from './response-vault-storage-validation'

const COMPENSATION_SCAN_BATCH_SIZE = 64
const COMPENSATION_SCAN_CURSOR_PREFIX =
  'atol:response-vault:v1:compensation-scan:'

interface ResponseVaultScanBatch {
  records: unknown[]
  lastPrimaryKey: string | null
  exhausted: boolean
}

function compensationScanStorage(): Storage {
  if (typeof window === 'undefined') {
    throw new Error('response vault: scan storage is unavailable')
  }
  return window.localStorage
}

function compensationScanCursorKey(
  binding: ResponseVaultBinding,
  includePublished: boolean,
  scope: 'exact' | 'application',
  onlyPublished: boolean,
): string {
  return `${COMPENSATION_SCAN_CURSOR_PREFIX}${encodeURIComponent(
    JSON.stringify([
      binding.issuer,
      binding.clientId,
      scope === 'exact' ? binding.redirectUri : clientOrigin(binding),
      scope === 'exact' ? binding.audience : null,
      scope === 'exact' ? binding.scope : null,
      includePublished,
      onlyPublished,
    ]),
  )}`
}

function readCompensationScanCursor(
  storage: Storage,
  key: string,
): string | null {
  const value = storage.getItem(key)
  if (value !== null && !CANONICAL_OPAQUE.test(value)) {
    throw new Error('response vault: compensation scan cursor is corrupt')
  }
  return value
}

function commitCompensationScanCursor(
  storage: Storage,
  key: string,
  expected: string | null,
  scan: ResponseVaultScanBatch,
): void {
  if (readCompensationScanCursor(storage, key) !== expected) {
    throw new Error('response vault: compensation scan cursor was superseded')
  }
  if (scan.exhausted) {
    storage.removeItem(key)
  } else if (scan.lastPrimaryKey !== null) {
    storage.setItem(key, scan.lastPrimaryKey)
  } else {
    throw new Error('response vault: compensation scan made no progress')
  }
}

function loadBoundedResponseVaultScan(
  store: IDBObjectStore,
  after: string | null,
): Promise<ResponseVaultScanBatch> {
  return new Promise((resolve, reject) => {
    const records: unknown[] = []
    let lastPrimaryKey: string | null = null
    const range =
      after === null ? undefined : IDBKeyRange.lowerBound(after, true)
    const request = store.openCursor(range)
    request.onerror = () =>
      reject(
        request.error ?? new Error('response vault: compensation scan failed'),
      )
    request.onsuccess = () => {
      const cursor = request.result
      if (!cursor) {
        resolve({ records, lastPrimaryKey, exhausted: true })
        return
      }
      if (
        typeof cursor.primaryKey !== 'string' ||
        !CANONICAL_OPAQUE.test(cursor.primaryKey)
      ) {
        reject(
          new Error('response vault: compensation scan primary key is corrupt'),
        )
        return
      }
      records.push(cursor.value)
      lastPrimaryKey = cursor.primaryKey
      if (records.length === COMPENSATION_SCAN_BATCH_SIZE) {
        resolve({ records, lastPrimaryKey, exhausted: false })
        return
      }
      cursor.continue()
    }
  })
}

export async function discardResponseVaultAuthorization(
  authorization: ResponseVaultAuthorization,
): Promise<void> {
  assertReference(authorization.reference)
  assertHeldExecutionLock(authorization.reference, authorization.executionClaim)
  let db: IDBDatabase | undefined
  await withExecutionLockRelease(
    authorization.reference,
    authorization.executionClaim,
    async () => {
      db = await openDB()
      const tx = db.transaction([STORE, SLOT_STORE], 'readwrite')
      const store = tx.objectStore(STORE)
      const record = (await requestResult(
        store.get(authorization.reference.id),
        'authorization discard read',
      )) as ResponseVaultRecord | undefined
      assertRecordBinding(
        record,
        authorization.reference,
        authorization.binding,
        Date.now(),
        false,
        true,
      )
      assertCustodyRevision(authorization, record.revision)
      assertExecutionClaim(
        record,
        authorization.executionClaim,
        'authorization discard',
      )
      const key = slotKey(authorization.binding)
      const slots = tx.objectStore(SLOT_STORE)
      const slot = (await requestResult(
        slots.get(key),
        'authorization discard slot read',
      )) as ResponseVaultSlotRecord | undefined
      if (slot !== undefined && !validSlotRecord(slot, key)) {
        throw new Error('response vault: active authorization slot is corrupt')
      }
      if (slot?.referenceId === record.id) {
        if (slot.expiresAt !== record.expiresAt) {
          throw new ResponseVaultExecutionBusyError()
        }
        slots.delete(key)
      }
      store.delete(record.id)
      await transactionDone(tx, 'authorization discard')
    },
    () => db?.close(),
  )
}

export async function discardResponseVaultCancellation(
  cancellation: ResponseVaultCancellation,
): Promise<void> {
  assertReference(cancellation.reference)
  assertHeldExecutionLock(cancellation.reference, cancellation.executionClaim)
  let db: IDBDatabase | undefined
  await withExecutionLockRelease(
    cancellation.reference,
    cancellation.executionClaim,
    async () => {
      db = await openDB()
      const tx = db.transaction([STORE, SLOT_STORE], 'readwrite')
      const store = tx.objectStore(STORE)
      const record = (await requestResult(
        store.get(cancellation.reference.id),
        'cancellation discard read',
      )) as MutableResponseVaultCancellationRecord | undefined
      assertCancellationBinding(
        record,
        cancellation.reference,
        cancellation.binding,
        Date.now(),
        false,
        true,
      )
      assertCustodyRevision(cancellation, record.revision)
      assertExecutionClaim(
        record,
        cancellation.executionClaim,
        'cancellation discard',
      )
      const key = slotKey(cancellation.binding)
      const slots = tx.objectStore(SLOT_STORE)
      const slot = (await requestResult(
        slots.get(key),
        'cancellation discard slot read',
      )) as ResponseVaultSlotRecord | undefined
      if (slot !== undefined && !validSlotRecord(slot, key)) {
        throw new Error('response vault: active authorization slot is corrupt')
      }
      if (slot?.referenceId === record.id) {
        if (slot.expiresAt !== record.expiresAt) {
          throw new ResponseVaultExecutionBusyError()
        }
        slots.delete(key)
      }
      store.delete(record.id)
      await transactionDone(tx, 'cancellation discard')
    },
    () => db?.close(),
  )
}

/**
 * Release the host-wide live slot after local publication while retaining the
 * exact, bounded post-finalize cancellation capability. The retained record
 * is not eligible for relay or another publication.
 */
export async function releaseResponseVaultAuthorization(
  authorization: ResponseVaultAuthorization,
): Promise<void> {
  assertReference(authorization.reference)
  assertHeldExecutionLock(authorization.reference, authorization.executionClaim)
  let db: IDBDatabase | undefined
  await withExecutionLockRelease(
    authorization.reference,
    authorization.executionClaim,
    async () => {
      db = await openDB()
      const tx = db.transaction([STORE, SLOT_STORE], 'readwrite')
      const store = tx.objectStore(STORE)
      const record = (await requestResult(
        store.get(authorization.reference.id),
        'authorization release read',
      )) as ResponseVaultRecord | undefined
      const now = Date.now()
      assertRecordBinding(
        record,
        authorization.reference,
        authorization.binding,
        now,
        false,
        true,
      )
      assertCustodyRevision(authorization, record.revision)
      if (record.status !== 'adopted') {
        throw new Error('response vault: authorization release state mismatch')
      }
      assertExecutionClaim(
        record,
        authorization.executionClaim,
        'authorization release',
      )
      const key = slotKey(authorization.binding)
      const slots = tx.objectStore(SLOT_STORE)
      const slot = (await requestResult(
        slots.get(key),
        'authorization release slot read',
      )) as ResponseVaultSlotRecord | undefined
      if (slot !== undefined && !validSlotRecord(slot, key)) {
        throw new Error('response vault: active authorization slot is corrupt')
      }
      if (slot) {
        if (
          slot.referenceId !== record.id ||
          slot.expiresAt !== record.expiresAt
        ) {
          throw new Error(
            'response vault: authorization release ownership mismatch',
          )
        }
        slots.delete(key)
      }
      if (
        typeof record.transactionId !== 'string' ||
        !CANONICAL_OPAQUE.test(record.transactionId)
      ) {
        throw new Error(
          'response vault: authorization release binding is incomplete',
        )
      }
      const cancellation = materializeCancellationRecord(
        record,
        'published',
        record.revision + 1,
        false,
      )
      if (!validCancellationRecord(cancellation, now, true)) {
        throw new Error(
          'response vault: authorization release cancellation is invalid',
        )
      }
      store.put(cancellation)
      await transactionDone(tx, 'authorization release')
    },
    () => db?.close(),
  )
}

/**
 * Verify that one exact custody record no longer exists and no active slot
 * still references it. This is used only to classify a concurrent,
 * independently completed cleanup after an exact mutation lost its race.
 */
export async function responseVaultCustodyReleased(
  custody: Pick<ResponseVaultCustody, 'reference' | 'binding'>,
): Promise<boolean> {
  assertReference(custody.reference)
  if (!validResponseVaultBinding(custody.binding)) {
    throw new Error('response vault: invalid authorization binding')
  }
  const db = await openDB()
  try {
    const tx = db.transaction([STORE, SLOT_STORE], 'readonly')
    const record = await requestResult(
      tx.objectStore(STORE).get(custody.reference.id),
      'authorization release verification record read',
    )
    const key = slotKey(custody.binding)
    const slot = (await requestResult(
      tx.objectStore(SLOT_STORE).get(key),
      'authorization release verification slot read',
    )) as unknown
    await transactionDone(tx, 'authorization release verification')
    if (slot !== undefined && !validSlotRecord(slot, key)) {
      throw new Error('response vault: active authorization slot is corrupt')
    }
    return (
      record === undefined &&
      (slot === undefined || slot.referenceId !== custody.reference.id)
    )
  } finally {
    db.close()
  }
}

/**
 * Load bounded adopted records for exact post-publication compensation.
 * Callers decide ownership from the stored binding and generation.
 */
export async function loadResponseVaultCompensations(
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
): Promise<ResponseVaultCancellationBatch> {
  return loadResponseVaultCancellationRecords(binding, lifecycleEpoch, false)
}

/**
 * Load all bounded cancellation custody for explicit lifecycle invalidation,
 * including cleanly published grants that normal crash recovery must ignore.
 */
export async function loadResponseVaultLifecycleCancellations(
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
  scope: 'exact' | 'application',
): Promise<ResponseVaultCancellationBatch> {
  return loadResponseVaultCancellationRecords(
    binding,
    lifecycleEpoch,
    true,
    scope,
  )
}

export async function loadResponseVaultTerminalProbes(
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
): Promise<ResponseVaultCancellationBatch> {
  return loadResponseVaultCancellationRecords(
    binding,
    lifecycleEpoch,
    true,
    'exact',
    true,
  )
}

async function loadResponseVaultCancellationRecords(
  binding: ResponseVaultBinding,
  lifecycleEpoch: number,
  includePublished: boolean,
  scope: 'exact' | 'application' = 'exact',
  onlyPublished = false,
): Promise<ResponseVaultCancellationBatch> {
  if (!validResponseVaultBinding(binding)) {
    throw new Error('response vault: invalid compensation binding')
  }
  const cursorStorage = compensationScanStorage()
  const cursorKey = compensationScanCursorKey(
    binding,
    includePublished,
    scope,
    onlyPublished,
  )
  const after = readCompensationScanCursor(cursorStorage, cursorKey)
  const db = await openDB()
  let scan: ResponseVaultScanBatch
  try {
    const tx = db.transaction(STORE, 'readonly')
    scan = await loadBoundedResponseVaultScan(tx.objectStore(STORE), after)
    await transactionDone(tx, 'compensation scan')
  } finally {
    db.close()
  }
  const candidates = scan.records.filter((value) => {
    if (!value || typeof value !== 'object') return false
    const record = value as Partial<MutableResponseVaultCancellationRecord>
    if (
      onlyPublished
        ? record.status !== 'published'
        : record.status !== 'adopted' &&
          (!includePublished || record.status !== 'published') &&
          record.status !== 'rejecting' &&
          record.status !== 'reject_retry' &&
          record.status !== 'reject_blocked'
    ) {
      return false
    }
    if (scope === 'exact') {
      return (
        record.issuer === binding.issuer &&
        record.clientId === binding.clientId &&
        record.redirectUri === binding.redirectUri &&
        record.audience === binding.audience &&
        record.scope === binding.scope
      )
    }
    if (
      record.issuer !== binding.issuer ||
      record.clientId !== binding.clientId
    ) {
      return false
    }
    try {
      return (
        typeof record.redirectUri !== 'string' ||
        new URL(record.redirectUri).origin === clientOrigin(binding)
      )
    } catch {
      return true
    }
  })
  const cancellations: ResponseVaultCancellation[] = []
  const errors: unknown[] = []
  for (const value of candidates) {
    try {
      const record = value as MutableResponseVaultCancellationRecord
      const storedBinding = recordBinding(record)
      const reference = {
        version: RECORD_VERSION,
        id: record.id,
      } as const
      assertCancellationBinding(
        record,
        reference,
        storedBinding,
        Date.now(),
        false,
        true,
      )
      cancellations.push(publicCancellation(record, lifecycleEpoch))
    } catch (error) {
      errors.push(error)
    }
  }
  const hasMore = errors.length > 0 || !scan.exhausted
  return {
    cancellations,
    errors,
    hasMore,
    commit: () =>
      commitCompensationScanCursor(cursorStorage, cursorKey, after, scan),
  }
}
