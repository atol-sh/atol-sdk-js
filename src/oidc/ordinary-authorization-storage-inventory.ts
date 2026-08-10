import {
  ORDINARY_AUTHORIZATION_STORE,
  OrdinaryAuthorizationPendingError,
} from './ordinary-authorization-model'
import {
  openOrdinaryAuthorizationDB,
  ordinaryAuthorizationTransactionDone as transactionDone,
} from './ordinary-authorization-database'
import {
  classifyOrdinaryAuthorizationRecord,
  classifyOrdinaryAuthorizationRecordEnvelope,
} from './ordinary-authorization-validation'

export const ORDINARY_AUTHORIZATION_INVENTORY_BATCH_SIZE = 64
const INVENTORY_CURSOR_KEY = 'atol:browser-auth:v2:inventory-cursor'

export interface OrdinaryAuthorizationInventoryBatch {
  snapshots: unknown[]
  hasMore: boolean
  commit(): void
}

interface CursorBatch {
  snapshots: unknown[]
  lastPrimaryKey: string | null
  exhausted: boolean
}

function inventoryStorage(): Storage {
  if (typeof window === 'undefined') {
    throw new Error(
      'ordinary browser authorization: inventory storage is unavailable',
    )
  }
  return window.localStorage
}

function readCursor(storage: Storage): string | null {
  const value = storage.getItem(INVENTORY_CURSOR_KEY)
  if (value !== null && (value.length === 0 || value.length > 16 * 1024)) {
    throw new Error(
      'ordinary browser authorization: inventory cursor is corrupt',
    )
  }
  return value
}

function commitCursor(
  storage: Storage,
  expected: string | null,
  batch: CursorBatch,
): void {
  if (readCursor(storage) !== expected) {
    throw new OrdinaryAuthorizationPendingError()
  }
  if (batch.exhausted) {
    storage.removeItem(INVENTORY_CURSOR_KEY)
  } else if (batch.lastPrimaryKey !== null) {
    storage.setItem(INVENTORY_CURSOR_KEY, batch.lastPrimaryKey)
  } else {
    throw new Error(
      'ordinary browser authorization: inventory scan made no progress',
    )
  }
}

function loadBoundedInventory(
  store: IDBObjectStore,
  after: string | null,
): Promise<CursorBatch> {
  return new Promise((resolve, reject) => {
    const snapshots: unknown[] = []
    let lastPrimaryKey: string | null = null
    const range =
      after === null ? undefined : IDBKeyRange.lowerBound(after, true)
    const request = store.openCursor(range)
    request.onerror = () =>
      reject(
        request.error ??
          new Error('ordinary browser authorization: inventory scan failed'),
      )
    request.onsuccess = () => {
      const cursor = request.result
      if (!cursor) {
        resolve({ snapshots, lastPrimaryKey, exhausted: true })
        return
      }
      if (
        typeof cursor.primaryKey !== 'string' ||
        cursor.primaryKey.length === 0 ||
        cursor.primaryKey.length > 16 * 1024
      ) {
        reject(
          new Error(
            'ordinary browser authorization: inventory primary key is corrupt',
          ),
        )
        return
      }
      snapshots.push(cursor.value)
      lastPrimaryKey = cursor.primaryKey
      if (snapshots.length === ORDINARY_AUTHORIZATION_INVENTORY_BATCH_SIZE) {
        resolve({ snapshots, lastPrimaryKey, exhausted: false })
        return
      }
      cursor.continue()
    }
  })
}

export async function loadOrdinaryAuthorizationInventory(): Promise<OrdinaryAuthorizationInventoryBatch> {
  const storage = inventoryStorage()
  const after = readCursor(storage)
  const db = await openOrdinaryAuthorizationDB()
  try {
    const transaction = db.transaction(ORDINARY_AUTHORIZATION_STORE, 'readonly')
    const batch = await loadBoundedInventory(
      transaction.objectStore(ORDINARY_AUTHORIZATION_STORE),
      after,
    )
    await transactionDone(transaction, 'expired record inventory')
    for (const snapshot of batch.snapshots) {
      await classifyOrdinaryAuthorizationRecordEnvelope(snapshot)
    }
    return {
      snapshots: batch.snapshots,
      hasMore: !batch.exhausted,
      commit: () => commitCursor(storage, after, batch),
    }
  } finally {
    db.close()
  }
}

export async function validateOrdinaryAuthorizationInventory(): Promise<void> {
  const batch = await loadOrdinaryAuthorizationInventory()
  for (const snapshot of batch.snapshots) {
    await classifyOrdinaryAuthorizationRecord(snapshot)
  }
  batch.commit()
  if (batch.hasMore) throw new OrdinaryAuthorizationPendingError()
}

export async function validateOrdinaryAuthorizationEnvelopeInventory(): Promise<void> {
  const batch = await loadOrdinaryAuthorizationInventory()
  for (const snapshot of batch.snapshots) {
    await classifyOrdinaryAuthorizationRecordEnvelope(snapshot)
  }
  batch.commit()
  if (batch.hasMore) throw new OrdinaryAuthorizationPendingError()
}
