import {
  RESPONSE_VAULT_CANONICAL_OPAQUE as CANONICAL_OPAQUE,
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_RECORD_VERSION as RECORD_VERSION,
  RESPONSE_VAULT_SLOT_MEMBERS,
  RESPONSE_VAULT_SLOT_STORE as SLOT_STORE,
  hasOnlyOwnMembers,
  type ResponseVaultSlotRecord,
} from './response-vault-model'
import {
  legacyGenerationSlotKey,
  migrateLegacyRecordV5,
  type LegacyMigrationEntry,
} from './response-vault-storage-migration'
import { recordBinding, slotKey } from './response-vault-storage-validation'

const STAGED_RECORDS = '__atol_v5_migration_records'
const GROUPS = '__atol_v5_migration_groups'
const TARGETS = '__atol_v5_migration_targets'
const FINAL_RECORDS = '__atol_v5_migration_final_records'
const FINAL_SLOTS = '__atol_v5_migration_final_slots'
const TEMPORARY_STORES = [
  STAGED_RECORDS,
  GROUPS,
  TARGETS,
  FINAL_RECORDS,
  FINAL_SLOTS,
] as const

interface StagedRecord {
  id: string
  slotKey: string
  entry: LegacyMigrationEntry
}

interface MigrationGroup {
  key: string
  requiredCount: number
  preferredRequiredId?: string
  preferredRequiredExpiresAt?: number
  parPendingCount: number
  parPendingId?: string
  targetCount: number
  preferredTargetId?: string
  preferredTargetExpiresAt?: number
  originCount: number
  originId?: string
  publishedTarget: boolean
  ownerId?: string
}

interface MigrationTarget {
  key: [string, string]
  origin: boolean
}

function abort(transaction: IDBTransaction): void {
  try {
    transaction.abort()
  } catch {
    // A concurrent request may already have aborted the version transaction.
  }
}

function requestFailed(request: IDBRequest, transaction: IDBTransaction): void {
  request.onerror = () => abort(transaction)
}

function preferred(
  currentId: string | undefined,
  currentExpiry: number | undefined,
  candidate: LegacyMigrationEntry,
): boolean {
  return (
    currentId === undefined ||
    currentExpiry === undefined ||
    candidate.record.expiresAt > currentExpiry ||
    (candidate.record.expiresAt === currentExpiry &&
      candidate.record.id < currentId)
  )
}

function createTemporaryStores(transaction: IDBTransaction): void {
  const database = transaction.db
  if (
    TEMPORARY_STORES.some((name) => database.objectStoreNames.contains(name))
  ) {
    abort(transaction)
    return
  }
  database.createObjectStore(STAGED_RECORDS, { keyPath: 'id' })
  database.createObjectStore(GROUPS, { keyPath: 'key' })
  database.createObjectStore(TARGETS, { keyPath: 'key' })
  database.createObjectStore(FINAL_RECORDS, { keyPath: 'id' })
  database.createObjectStore(FINAL_SLOTS, { keyPath: 'key' })
}

function stageRecords(
  transaction: IDBTransaction,
  now: number,
  done: () => void,
): void {
  const source = transaction.objectStore(STORE)
  const staged = transaction.objectStore(STAGED_RECORDS)
  const groups = transaction.objectStore(GROUPS)
  const cursorRequest = source.openCursor()
  requestFailed(cursorRequest, transaction)
  cursorRequest.onsuccess = () => {
    const cursor = cursorRequest.result
    if (!cursor) {
      done()
      return
    }
    const entry = migrateLegacyRecordV5(cursor.value, now)
    if (!entry) {
      abort(transaction)
      return
    }
    const key = slotKey(recordBinding(entry.record))
    const stagedPut = staged.put({
      id: entry.record.id,
      slotKey: key,
      entry,
    } satisfies StagedRecord)
    requestFailed(stagedPut, transaction)
    stagedPut.onsuccess = () => {
      if (entry.discard) {
        cursor.continue()
        return
      }
      const groupRequest = groups.get(key)
      requestFailed(groupRequest, transaction)
      groupRequest.onsuccess = () => {
        const group = (groupRequest.result as MigrationGroup | undefined) ?? {
          key,
          requiredCount: 0,
          parPendingCount: 0,
          targetCount: 0,
          originCount: 0,
          publishedTarget: false,
        }
        if (entry.requiresSlot) {
          group.requiredCount++
          if (
            preferred(
              group.preferredRequiredId,
              group.preferredRequiredExpiresAt,
              entry,
            )
          ) {
            group.preferredRequiredId = entry.record.id
            group.preferredRequiredExpiresAt = entry.record.expiresAt
          }
        }
        if (entry.legacyStatus === 'par_pending') {
          group.parPendingCount++
          group.parPendingId = entry.record.id
        }
        const groupPut = groups.put(group)
        requestFailed(groupPut, transaction)
        groupPut.onsuccess = () => cursor.continue()
      }
    }
  }
}

function validLegacySlot(value: unknown): value is ResponseVaultSlotRecord {
  if (
    !value ||
    typeof value !== 'object' ||
    Object.keys(value).length !== RESPONSE_VAULT_SLOT_MEMBERS.size ||
    !hasOnlyOwnMembers(value, RESPONSE_VAULT_SLOT_MEMBERS)
  ) {
    return false
  }
  const slot = value as Partial<ResponseVaultSlotRecord>
  return (
    slot.version === RECORD_VERSION &&
    typeof slot.key === 'string' &&
    typeof slot.referenceId === 'string' &&
    CANONICAL_OPAQUE.test(slot.referenceId) &&
    Number.isSafeInteger(slot.expiresAt)
  )
}

function updateTargetGroup(
  transaction: IDBTransaction,
  group: MigrationGroup,
  staged: StagedRecord,
  origin: boolean,
  isNewTarget: boolean,
  done: () => void,
): void {
  if (isNewTarget) {
    group.targetCount++
    if (
      preferred(
        group.preferredTargetId,
        group.preferredTargetExpiresAt,
        staged.entry,
      )
    ) {
      group.preferredTargetId = staged.id
      group.preferredTargetExpiresAt = staged.entry.record.expiresAt
    }
    if (staged.entry.legacyStatus === 'published') {
      group.publishedTarget = true
    }
  }
  if (origin) {
    group.originCount++
    group.originId = staged.id
  }
  const put = transaction.objectStore(GROUPS).put(group)
  requestFailed(put, transaction)
  put.onsuccess = done
}

function stageSlotTargets(transaction: IDBTransaction, done: () => void): void {
  const source = transaction.objectStore(SLOT_STORE)
  const stagedRecords = transaction.objectStore(STAGED_RECORDS)
  const targets = transaction.objectStore(TARGETS)
  const groups = transaction.objectStore(GROUPS)
  const cursorRequest = source.openCursor()
  requestFailed(cursorRequest, transaction)
  cursorRequest.onsuccess = () => {
    const cursor = cursorRequest.result
    if (!cursor) {
      done()
      return
    }
    if (!validLegacySlot(cursor.value)) {
      abort(transaction)
      return
    }
    const slot = cursor.value
    const stagedRequest = stagedRecords.get(slot.referenceId)
    requestFailed(stagedRequest, transaction)
    stagedRequest.onsuccess = () => {
      const staged = stagedRequest.result as StagedRecord | undefined
      if (
        !staged ||
        (slot.expiresAt !== staged.entry.record.expiresAt &&
          slot.expiresAt !== staged.entry.legacyExpiresAt) ||
        (slot.key !== staged.slotKey &&
          slot.key !== legacyGenerationSlotKey(staged.entry.record))
      ) {
        abort(transaction)
        return
      }
      if (staged.entry.discard) {
        cursor.continue()
        return
      }
      const targetKey: [string, string] = [staged.slotKey, staged.id]
      const targetRequest = targets.get(targetKey)
      requestFailed(targetRequest, transaction)
      targetRequest.onsuccess = () => {
        const existing = targetRequest.result as MigrationTarget | undefined
        const origin = slot.key === staged.slotKey
        if (existing && (!origin || existing.origin)) {
          cursor.continue()
          return
        }
        const targetPut = targets.put({
          key: targetKey,
          origin: existing?.origin === true || origin,
        } satisfies MigrationTarget)
        requestFailed(targetPut, transaction)
        targetPut.onsuccess = () => {
          const groupRequest = groups.get(staged.slotKey)
          requestFailed(groupRequest, transaction)
          groupRequest.onsuccess = () => {
            const group = groupRequest.result as MigrationGroup | undefined
            if (!group) {
              abort(transaction)
              return
            }
            updateTargetGroup(
              transaction,
              group,
              staged,
              origin && !existing?.origin,
              existing === undefined,
              () => cursor.continue(),
            )
          }
        }
      }
    }
  }
}

function selectGroupOwners(
  transaction: IDBTransaction,
  done: () => void,
): void {
  const groups = transaction.objectStore(GROUPS)
  const staged = transaction.objectStore(STAGED_RECORDS)
  const finalSlots = transaction.objectStore(FINAL_SLOTS)
  const cursorRequest = groups.openCursor()
  requestFailed(cursorRequest, transaction)
  cursorRequest.onsuccess = () => {
    const cursor = cursorRequest.result
    if (!cursor) {
      done()
      return
    }
    const group = cursor.value as MigrationGroup
    if (group.publishedTarget || group.parPendingCount > 1) {
      abort(transaction)
      return
    }
    if (group.parPendingCount === 1) {
      group.ownerId = group.parPendingId
    } else if (group.originCount === 1) {
      group.ownerId = group.originId
    } else if (group.targetCount > 0) {
      group.ownerId = group.preferredTargetId
    } else if (group.requiredCount > 0) {
      group.ownerId = group.preferredRequiredId
    }
    if ((group.targetCount > 0 || group.requiredCount > 0) && !group.ownerId) {
      abort(transaction)
      return
    }
    const verifyOwner = () => {
      const update = cursor.update(group)
      requestFailed(update, transaction)
      update.onsuccess = () => cursor.continue()
    }
    if (!group.ownerId) {
      verifyOwner()
      return
    }
    const targetRequest = transaction
      .objectStore(TARGETS)
      .get([group.key, group.ownerId])
    requestFailed(targetRequest, transaction)
    targetRequest.onsuccess = () => {
      if (group.parPendingCount === 1 && targetRequest.result === undefined) {
        abort(transaction)
        return
      }
      const ownerRequest = staged.get(group.ownerId as string)
      requestFailed(ownerRequest, transaction)
      ownerRequest.onsuccess = () => {
        const owner = ownerRequest.result as StagedRecord | undefined
        if (!owner) {
          abort(transaction)
          return
        }
        const slotPut = finalSlots.put({
          version: RECORD_VERSION,
          key: group.key,
          referenceId: owner.id,
          expiresAt: owner.entry.record.expiresAt,
        } satisfies ResponseVaultSlotRecord)
        requestFailed(slotPut, transaction)
        slotPut.onsuccess = verifyOwner
      }
    }
  }
}

function stageFinalRecords(
  transaction: IDBTransaction,
  done: () => void,
): void {
  const staged = transaction.objectStore(STAGED_RECORDS)
  const groups = transaction.objectStore(GROUPS)
  const targets = transaction.objectStore(TARGETS)
  const finalRecords = transaction.objectStore(FINAL_RECORDS)
  const cursorRequest = staged.openCursor()
  requestFailed(cursorRequest, transaction)
  cursorRequest.onsuccess = () => {
    const cursor = cursorRequest.result
    if (!cursor) {
      done()
      return
    }
    const stagedRecord = cursor.value as StagedRecord
    if (stagedRecord.entry.discard) {
      cursor.continue()
      return
    }
    const groupRequest = groups.get(stagedRecord.slotKey)
    requestFailed(groupRequest, transaction)
    groupRequest.onsuccess = () => {
      const group = groupRequest.result as MigrationGroup | undefined
      if (!group) {
        abort(transaction)
        return
      }
      const targetRequest = targets.get([stagedRecord.slotKey, stagedRecord.id])
      requestFailed(targetRequest, transaction)
      targetRequest.onsuccess = () => {
        const targeted = targetRequest.result !== undefined
        const losesLegacySlot = targeted && stagedRecord.id !== group.ownerId
        const losesRequiredOwnership =
          stagedRecord.entry.requiresSlot &&
          (stagedRecord.id !== group.ownerId || !targeted)
        let record = stagedRecord.entry.record
        if (losesLegacySlot || losesRequiredOwnership) {
          if (!stagedRecord.entry.cancellation) {
            abort(transaction)
            return
          }
          record = stagedRecord.entry.cancellation
        }
        const put = finalRecords.put(record)
        requestFailed(put, transaction)
        put.onsuccess = () => cursor.continue()
      }
    }
  }
}

function copyStore(
  transaction: IDBTransaction,
  sourceName: string,
  targetName: string,
  done: () => void,
): void {
  const target = transaction.objectStore(targetName)
  const request = transaction.objectStore(sourceName).openCursor()
  requestFailed(request, transaction)
  request.onsuccess = () => {
    const cursor = request.result
    if (!cursor) {
      done()
      return
    }
    const put = target.put(cursor.value)
    requestFailed(put, transaction)
    put.onsuccess = () => cursor.continue()
  }
}

function publishMigration(transaction: IDBTransaction): void {
  const clearRecords = transaction.objectStore(STORE).clear()
  const clearSlots = transaction.objectStore(SLOT_STORE).clear()
  requestFailed(clearRecords, transaction)
  requestFailed(clearSlots, transaction)
  let cleared = 0
  const afterClear = () => {
    cleared++
    if (cleared !== 2) return
    let copied = 0
    const afterCopy = () => {
      copied++
      if (copied !== 2) return
      for (const name of TEMPORARY_STORES) {
        transaction.db.deleteObjectStore(name)
      }
    }
    copyStore(transaction, FINAL_RECORDS, STORE, afterCopy)
    copyStore(transaction, FINAL_SLOTS, SLOT_STORE, afterCopy)
  }
  clearRecords.onsuccess = afterClear
  clearSlots.onsuccess = afterClear
}

export function migrateResponseVaultV5(
  transaction: IDBTransaction | null,
): void {
  if (!transaction) {
    throw new Error('response vault: database migration is unavailable')
  }
  createTemporaryStores(transaction)
  stageRecords(transaction, Date.now(), () => {
    stageSlotTargets(transaction, () => {
      selectGroupOwners(transaction, () => {
        stageFinalRecords(transaction, () => {
          publishMigration(transaction)
        })
      })
    })
  })
}
