import {
  ORDINARY_AUTHORIZATION_DB_NAME,
  ORDINARY_AUTHORIZATION_DB_VERSION,
  ORDINARY_AUTHORIZATION_STORE,
} from './ordinary-authorization-model'

export function openOrdinaryAuthorizationDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(
        new Error(
          'ordinary browser authorization: IndexedDB is unavailable',
        ),
      )
      return
    }
    const request = indexedDB.open(
      ORDINARY_AUTHORIZATION_DB_NAME,
      ORDINARY_AUTHORIZATION_DB_VERSION,
    )
    request.onupgradeneeded = () => {
      if (
        !request.result.objectStoreNames.contains(
          ORDINARY_AUTHORIZATION_STORE,
        )
      ) {
        request.result.createObjectStore(
          ORDINARY_AUTHORIZATION_STORE,
          { keyPath: 'slotKey' },
        )
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () =>
      reject(
        request.error ??
          new Error(
            'ordinary browser authorization: database open failed',
          ),
      )
    request.onblocked = () =>
      reject(
        new Error(
          'ordinary browser authorization: database open blocked',
        ),
      )
  })
}

export function ordinaryAuthorizationTransactionDone(
  transaction: IDBTransaction,
  operation: string,
): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () =>
      reject(
        transaction.error ??
          new Error(
            `ordinary browser authorization: ${operation} failed`,
          ),
      )
    transaction.onabort = () =>
      reject(
        transaction.error ??
          new Error(
            `ordinary browser authorization: ${operation} aborted`,
          ),
      )
  })
}

export function ordinaryAuthorizationRequestResult<T>(
  request: IDBRequest<T>,
  operation: string,
): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () =>
      reject(
        request.error ??
          new Error(
            `ordinary browser authorization: ${operation} failed`,
          ),
      )
  })
}
