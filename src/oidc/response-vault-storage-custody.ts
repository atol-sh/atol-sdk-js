import type { DPoPKeyManager } from '../dpop/dpop'
import { assertCredentialGenerationSnapshot } from './credential-generation'
import { ResponseVaultAuthorizationBindingMismatchError } from './response-vault-contract'
import {
  RESPONSE_VAULT_CANONICAL_OPAQUE as CANONICAL_OPAQUE,
  RESPONSE_VAULT_RECORD_STORE as STORE,
  RESPONSE_VAULT_RECORD_VERSION as RECORD_VERSION,
  RESPONSE_VAULT_STATUS_SCHEMA,
  type MutableResponseVaultCancellationRecord,
  type ResponseVaultAuthorization,
  type ResponseVaultBinding,
  type ResponseVaultCancellation,
  type ResponseVaultExecutionClaim,
  type ResponseVaultRecord,
  type ResponseVaultReference,
} from './response-vault-model'
import { openDB, requestResult, transactionDone } from './response-vault-storage-db'
import { rememberCustodyRevision } from './response-vault-storage-lock'
import {
  classifyStoredRecord,
  clientOrigin,
  recordBinding,
  recordSettlement,
  validCancellationRecord,
  validStoredRecord,
} from './response-vault-storage-validation'

export function assertCancellationBinding(
  record: unknown,
  reference: ResponseVaultReference,
  binding: ResponseVaultBinding,
  now: number,
  requireCurrentGeneration = false,
  allowExpired = false,
): asserts record is MutableResponseVaultCancellationRecord {
  if (
    !validCancellationRecord(record, now, allowExpired) ||
    record.id !== reference.id ||
    record.issuer !== binding.issuer ||
    record.clientId !== binding.clientId ||
    record.redirectUri !== binding.redirectUri ||
    record.audience !== binding.audience ||
    record.scope !== binding.scope ||
    clientOrigin(recordBinding(record)) !== clientOrigin(binding)
  ) {
    throw new Error('response vault: cancellation binding mismatch')
  }
  if (requireCurrentGeneration) {
    assertCredentialGenerationSnapshot(binding, record.credentialGeneration)
  }
}

export function publicCancellation(
  record: MutableResponseVaultCancellationRecord,
  lifecycleEpoch: number,
  executionClaim?: ResponseVaultExecutionClaim,
): ResponseVaultCancellation {
  const retainedClaim =
    executionClaim ??
    (record.executionOwner !== undefined
      ? {
        owner: record.executionOwner,
        fence: record.executionFence,
      }
      : undefined)
  return rememberCustodyRevision({
    reference: { version: RECORD_VERSION, id: record.id },
    binding: recordBinding(record),
    lifecycleEpoch,
    credentialGeneration: record.credentialGeneration,
    ...(
      record.custody === undefined &&
      (record.mode === 'interactive' || record.mode === 'iframe')
        ? { sourceMode: record.mode }
        : {}
    ),
    rejectionProvenance:
      record.custody === 'cancellation'
        ? record.rejectionProvenance
        : 'internal',
    status: record.status,
    transactionId: record.transactionId,
    tabSecret: record.tabSecret,
    cancellationSecret: record.cancellationSecret,
    terminalProof: record.terminalProof,
    expiresAt: record.expiresAt,
    executionClaim: retainedClaim,
    executionLeaseExpiresAt: record.executionExpiresAt,
  }, record.revision)
}

export function deleteExpired(store: IDBObjectStore, now: number): void {
  const request = store.openCursor()
  request.onsuccess = () => {
    const cursor = request.result
    if (!cursor) return
    const classified = classifyStoredRecord(cursor.value, now, true)
    if (!classified) {
      store.transaction.abort()
      return
    }
    const { record } = classified
    if (
      record.expiresAt <= now &&
      RESPONSE_VAULT_STATUS_SCHEMA[record.status].locallyReapable
    ) {
      cursor.delete()
    }
    cursor.continue()
  }
  request.onerror = () => store.transaction.abort()
}

export function assertReference(reference: ResponseVaultReference): void {
  if (
    reference.version !== RECORD_VERSION ||
    !CANONICAL_OPAQUE.test(reference.id)
  ) {
    throw new Error('response vault: invalid authorization reference')
  }
}

export function assertRecordBinding(
  record: ResponseVaultRecord | undefined,
  reference: ResponseVaultReference,
  binding: ResponseVaultBinding,
  now: number,
  requireCurrentGeneration = true,
  allowExpired = false,
): asserts record is ResponseVaultRecord {
  if (
    !record ||
    record.id !== reference.id ||
    record.issuer !== binding.issuer ||
    record.clientId !== binding.clientId ||
    record.redirectUri !== binding.redirectUri ||
    record.audience !== binding.audience ||
    record.scope !== binding.scope ||
    !validStoredRecord(record, now, allowExpired)
  ) {
    throw new ResponseVaultAuthorizationBindingMismatchError()
  }
  if (requireCurrentGeneration) {
    assertCredentialGenerationSnapshot(binding, record.credentialGeneration)
  }
}

export async function readRecord(
  reference: ResponseVaultReference,
): Promise<ResponseVaultRecord | undefined> {
  assertReference(reference)
  const db = await openDB()
  try {
    const tx = db.transaction(STORE, 'readonly')
    const record = await requestResult(
      tx.objectStore(STORE).get(reference.id),
      'authorization read',
    )
    await transactionDone(tx, 'authorization read')
    return record as ResponseVaultRecord | undefined
  } finally {
    db.close()
  }
}

export function publicAuthorization(
  record: ResponseVaultRecord,
  dpopKey: DPoPKeyManager,
  lifecycleEpoch: number,
  executionClaim?: ResponseVaultExecutionClaim,
): ResponseVaultAuthorization {
  return rememberCustodyRevision({
    reference: { version: RECORD_VERSION, id: record.id },
    binding: {
      issuer: record.issuer,
      clientId: record.clientId,
      redirectUri: record.redirectUri,
      audience: record.audience,
      scope: record.scope,
    },
    mode: record.mode,
    intent: {
      prompt: record.prompt,
      maxAge: record.maxAge,
      acrValues: record.acrValues,
      organizationId: record.organizationId,
      returnTo: record.returnTo,
    },
    lifecycleEpoch,
    credentialGeneration: record.credentialGeneration,
    status: record.status,
    jkt: record.jkt,
    state: record.state,
    nonce: record.nonce,
    codeVerifier: record.codeVerifier,
    codeChallenge: record.codeChallenge,
    tabSecret: record.tabSecret,
    parIdempotencyKey: record.parIdempotencyKey,
    cancellationSecret: record.cancellationSecret,
    transactionId: record.transactionId,
    requestUri: record.requestUri,
    csrfToken: record.csrfToken,
    bootstrapAttemptCapability:
      record.bootstrapAttemptCapability,
    bootstrapTerminalProof: record.bootstrapTerminalProof,
    terminalProof: record.terminalProof,
    settlement: recordSettlement(record),
    expiresAt: record.expiresAt,
    phaseExpiresAt: record.phaseExpiresAt,
    executionClaim,
    executionLeaseExpiresAt: record.executionExpiresAt,
    navigationOwner: record.navigationOwner,
    navigationExpiresAt: record.navigationExpiresAt,
    dpopKey,
  }, record.revision)
}
