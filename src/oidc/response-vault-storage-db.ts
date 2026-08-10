import {
  RESPONSE_VAULT_DB_NAME as DB_NAME,
  RESPONSE_VAULT_DB_VERSION as DB_VERSION,
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_SLOT_STORE as SLOT_STORE,
} from './response-vault-model'
import { migrateResponseVaultV5 } from './response-vault-storage-migration-execution'

export function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('response vault: IndexedDB is unavailable'))
      return
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = (event) => {
      if (!request.result.objectStoreNames.contains(STORE)) {
        request.result.createObjectStore(STORE, { keyPath: 'id' })
      }
      if (!request.result.objectStoreNames.contains(SLOT_STORE)) {
        request.result.createObjectStore(SLOT_STORE, { keyPath: 'key' })
      }
      if ((event as IDBVersionChangeEvent).oldVersion > 0) {
        migrateResponseVaultV5(request.transaction)
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () =>
      reject(request.error ?? new Error('response vault: database open failed'))
    request.onblocked = () =>
      reject(new Error('response vault: database upgrade is blocked'))
  })
}

export function transactionDone(tx: IDBTransaction, operation: string): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve()
    tx.onerror = () =>
      reject(tx.error ?? new Error(`response vault: ${operation} failed`))
    tx.onabort = () =>
      reject(tx.error ?? new Error(`response vault: ${operation} aborted`))
  })
}

export function requestResult<T>(request: IDBRequest<T>, operation: string): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () =>
      reject(request.error ?? new Error(`response vault: ${operation} failed`))
  })
}
