import type { ResponseVault } from '../../src/oidc/response-vault'
import type { ResponseVaultAuthorization } from '../../src/oidc/response-vault-storage'
import {
  OPAQUE_A,
  OPAQUE_B,
  REQUEST_URI,
  TERMINAL_PROOF,
  jsonResponse,
} from './response-vault-regression-helpers'

export const BINDING = {
  issuer: 'https://id.example.com',
  clientId: 'example-spa',
  redirectUri: 'https://app.example.com/callback',
  audience: 'https://api.example.com',
  scope: 'openid profile email',
}

type StartableVault = {
  start(
    mode: 'interactive' | 'iframe',
    intent: Record<string, never>,
  ): Promise<ResponseVaultAuthorization>
}

export function start(
  vault: ResponseVault,
): Promise<ResponseVaultAuthorization> {
  return (vault as unknown as StartableVault).start('interactive', {})
}

export function pushedResponse(
  requestUriExpiresIn: number,
  transactionExpiresIn: number,
): Response {
  return jsonResponse(
    {
      version: 1,
      transaction_id: OPAQUE_A,
      request_uri: REQUEST_URI,
      expires_in: requestUriExpiresIn,
      transaction_expires_in: transactionExpiresIn,
      csrf_token: OPAQUE_B,
      terminal_proof: TERMINAL_PROOF,
    },
    201,
  )
}

export function mutateDatabase(
  stores: string | string[],
  mutation: (transaction: IDBTransaction) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('atol-sdk-response-vault', 5)
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const database = open.result
      const transaction = database.transaction(stores, 'readwrite')
      mutation(transaction)
      transaction.oncomplete = () => {
        database.close()
        resolve()
      }
      transaction.onerror = () => {
        database.close()
        reject(transaction.error)
      }
      transaction.onabort = () => {
        database.close()
        reject(transaction.error)
      }
    }
  })
}

export function deleteDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase('atol-sdk-response-vault')
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () =>
      reject(new Error('response vault: test database deletion was blocked'))
  })
}

export function createLegacyDatabase(
  version: 2 | 3 | 4,
  records: Array<Record<string, unknown>>,
  slots: Array<Record<string, unknown>>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('atol-sdk-response-vault', version)
    open.onupgradeneeded = () => {
      open.result.createObjectStore('authorizations', {
        keyPath: 'id',
      })
      open.result.createObjectStore('authorization-slots', {
        keyPath: 'key',
      })
    }
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const database = open.result
      const transaction = database.transaction(
        ['authorizations', 'authorization-slots'],
        'readwrite',
      )
      for (const record of records) {
        transaction.objectStore('authorizations').add(record)
      }
      for (const slot of slots) {
        transaction.objectStore('authorization-slots').add(slot)
      }
      transaction.oncomplete = () => {
        database.close()
        resolve()
      }
      transaction.onerror = () => {
        database.close()
        reject(transaction.error)
      }
    }
  })
}

export function readLegacyDatabase(version: 2 | 3 | 4): Promise<{
  records: Array<Record<string, unknown>>
  slots: Array<Record<string, unknown>>
}> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('atol-sdk-response-vault', version)
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const database = open.result
      const transaction = database.transaction(
        ['authorizations', 'authorization-slots'],
        'readonly',
      )
      const recordRequest = transaction.objectStore('authorizations').getAll()
      const slotRequest = transaction
        .objectStore('authorization-slots')
        .getAll()
      transaction.oncomplete = () => {
        database.close()
        resolve({
          records: recordRequest.result as Array<Record<string, unknown>>,
          slots: slotRequest.result as Array<Record<string, unknown>>,
        })
      }
      transaction.onerror = () => {
        database.close()
        reject(transaction.error)
      }
    }
  })
}

export function legacyGenerationSlotKey(
  record: Record<string, unknown>,
): string {
  const generation = record.credentialGeneration as {
    tabOwner: string
  }
  return JSON.stringify([
    record.issuer,
    record.clientId,
    record.redirectUri,
    record.audience,
    record.scope,
    generation.tabOwner,
  ])
}

export function originSlotKey(): string {
  return JSON.stringify([1, 'https://app.example.com'])
}
