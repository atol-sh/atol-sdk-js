import type { ResponseVault } from '../../src/oidc/response-vault'
import {
  claimResponseVaultExecution,
  loadResponseVaultAuthorizationForRejection,
  type ResponseVaultAuthorization,
} from '../../src/oidc/response-vault-storage'
import {
  BOOTSTRAP_TERMINAL_PROOF,
  OPAQUE_A,
  OPAQUE_B,
  REQUEST_URI,
  TERMINAL_PROOF,
  activeReference,
} from './response-vault-regression-helpers'

export const BINDING = {
  issuer: 'https://id.example.com',
  clientId: 'example-spa',
  redirectUri: 'https://app.example.com/callback',
  audience: 'https://api.example.com',
  scope: 'openid profile email',
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

export function canonicalRecordId(index: number): string {
  return index.toString(36).padStart(43, '0')
}

export function cancellationRecord(
  source: Record<string, unknown>,
  id: string,
  binding: Partial<typeof BINDING> = {},
): Record<string, unknown> {
  return {
    version: 1,
    revision: 1,
    id,
    issuer: binding.issuer ?? source.issuer,
    clientId: binding.clientId ?? source.clientId,
    redirectUri: binding.redirectUri ?? source.redirectUri,
    audience: binding.audience ?? source.audience,
    scope: binding.scope ?? source.scope,
    credentialGeneration: source.credentialGeneration,
    rejectionProvenance: 'internal',
    status: 'adopted',
    tabSecret: source.tabSecret,
    cancellationSecret: source.cancellationSecret,
    bootstrapAttemptCapability: source.bootstrapAttemptCapability,
    terminalProof: source.terminalProof,
    transactionId: source.transactionId,
    expiresAt: source.expiresAt,
    executionFence: 0,
    custody: 'cancellation',
  }
}

export async function activeAuthorization(
  vault: ResponseVault,
): Promise<ResponseVaultAuthorization> {
  const referenceId = activeReference()
  if (!referenceId) {
    throw new Error('test authorization reference is missing')
  }
  return loadResponseVaultAuthorizationForRejection(
    { version: 1, id: referenceId },
    BINDING,
    vault.lifecycleEpoch(),
  )
}

export async function claimedUnboundPARAuthorization(
  vault: ResponseVault,
): Promise<ResponseVaultAuthorization> {
  await vault.beginInteractive()
  const original = await activeAuthorization(vault)
  const phaseExpiresAt = Date.now() + 60_000
  await mutateDatabase(
    ['authorizations', 'authorization-slots'],
    (transaction) => {
      const records = transaction.objectStore('authorizations')
      const recordRequest = records.get(original.reference.id)
      recordRequest.onsuccess = () => {
        const record = recordRequest.result as Record<string, unknown>
        records.put({
          ...record,
          status: 'par_pending',
          transactionId: undefined,
          requestUri: undefined,
          bootstrapTerminalProof: BOOTSTRAP_TERMINAL_PROOF,
          terminalProof: undefined,
          settlementKind: undefined,
          settlementErrorCode: undefined,
          expiresAt: phaseExpiresAt,
          phaseExpiresAt,
          executionOwner: undefined,
          executionExpiresAt: undefined,
          navigationOwner: undefined,
          navigationExpiresAt: undefined,
        })
      }
      const slots = transaction.objectStore('authorization-slots')
      const slotRequest = slots.openCursor()
      slotRequest.onsuccess = () => {
        const cursor = slotRequest.result
        if (!cursor) return
        cursor.update({
          ...(cursor.value as Record<string, unknown>),
          expiresAt: phaseExpiresAt,
        })
      }
    },
  )
  const pending = await activeAuthorization(vault)
  return claimResponseVaultExecution(pending, 'Q'.repeat(43), ['par_pending'])
}

export function unboundPushedResponse(): {
  transactionId: string
  requestUri: string
  csrfToken: string
  terminalProof: string
  requestUriExpiresAt: number
  transactionExpiresAt: number
} {
  return {
    transactionId: OPAQUE_A,
    requestUri: REQUEST_URI,
    csrfToken: OPAQUE_B,
    terminalProof: TERMINAL_PROOF,
    requestUriExpiresAt: Date.now() + 60_000,
    transactionExpiresAt: Date.now() + 600_000,
  }
}

export async function replaceStoredKeys(
  referenceId: string,
  keys: unknown,
): Promise<void> {
  await mutateDatabase('authorizations', (transaction) => {
    const store = transaction.objectStore('authorizations')
    const request = store.get(referenceId)
    request.onsuccess = () => {
      store.put({
        ...(request.result as Record<string, unknown>),
        keys,
      })
    }
  })
}
