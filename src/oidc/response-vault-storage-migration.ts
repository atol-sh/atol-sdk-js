import {
  RESPONSE_VAULT_PRE_TRANSACTION_TTL_MS as PRE_TRANSACTION_TTL_MS,
  RESPONSE_VAULT_RECORD_MEMBERS,
  hasOnlyOwnMembers,
  type MutableResponseVaultCancellationRecord,
  type ResponseVaultAuthorizationStatus,
  type ResponseVaultRecord,
} from './response-vault-model'
import {
  CANCELLATION_SOURCE_STATUSES,
  materializeCancellationRecord,
  statusRequiresActiveSlot,
  validCancellationAuthority,
  validCancellationRecord,
  validStoredRecord,
} from './response-vault-storage-validation'

export type MigratedResponseVaultRecord =
  ResponseVaultRecord | MutableResponseVaultCancellationRecord

export interface LegacyMigrationEntry {
  record: MigratedResponseVaultRecord
  cancellation?: MutableResponseVaultCancellationRecord
  legacyStatus: ResponseVaultAuthorizationStatus
  legacyExpiresAt: number
  requiresSlot: boolean
  discard: boolean
}

export function legacyGenerationSlotKey(
  record: Pick<
    ResponseVaultRecord,
    | 'issuer'
    | 'clientId'
    | 'redirectUri'
    | 'audience'
    | 'scope'
    | 'credentialGeneration'
  >,
): string {
  return JSON.stringify([
    record.issuer,
    record.clientId,
    record.redirectUri,
    record.audience,
    record.scope,
    record.credentialGeneration.tabOwner,
  ])
}

export function migrateLegacyRecordV5(
  value: unknown,
  now: number,
): LegacyMigrationEntry | null | undefined {
  if (!value || typeof value !== 'object') return null
  const legacy = value as Partial<ResponseVaultRecord>
  if (!Number.isSafeInteger(legacy.expiresAt)) return null
  const legacyExpiresAt = legacy.expiresAt as number
  if (!hasOnlyOwnMembers(value, RESPONSE_VAULT_RECORD_MEMBERS)) return null
  const legacyStatus = legacy.status
  if (!legacyStatus || legacyStatus === 'reject_blocked') return null
  const record = {
    ...legacy,
    executionFence: 0,
  } as ResponseVaultRecord
  delete record.executionOwner
  delete record.executionExpiresAt
  delete record.navigationOwner
  delete record.navigationExpiresAt
  if (record.status === 'prepared') {
    record.phaseExpiresAt = Number.isSafeInteger(record.phaseExpiresAt)
      ? Math.min(record.expiresAt, record.phaseExpiresAt as number)
      : record.expiresAt
  } else if (record.status === 'par_pending' || record.status === 'pushed') {
    if (Number.isSafeInteger(record.phaseExpiresAt)) {
      record.phaseExpiresAt = record.phaseExpiresAt as number
    } else if (Number.isSafeInteger(record.createdAt)) {
      record.phaseExpiresAt = Math.min(
        record.expiresAt,
        record.createdAt + PRE_TRANSACTION_TTL_MS,
      )
    } else {
      delete record.phaseExpiresAt
    }
    if (record.status === 'par_pending') {
      if (!Number.isSafeInteger(record.phaseExpiresAt)) return null
      record.expiresAt = Math.min(
        record.expiresAt,
        record.phaseExpiresAt as number,
      )
    }
  } else {
    delete record.phaseExpiresAt
  }
  const fullGrantValid =
    Number.isSafeInteger(record.createdAt) &&
    validLegacyFullGrantRecord(record, now)
  if (legacyStatus === 'prepared') {
    return fullGrantValid
      ? {
          record,
          legacyStatus,
          legacyExpiresAt,
          requiresSlot: true,
          discard: true,
        }
      : null
  }
  if (legacyStatus === 'par_pending') {
    return fullGrantValid
      ? {
          record,
          legacyStatus,
          legacyExpiresAt,
          requiresSlot: true,
          discard: false,
        }
      : null
  }

  const cancellation = migrateLegacyCancellationV5(record, now)
  if (legacyStatus === 'published') {
    if (!fullGrantValid || !cancellation) return null
    const published = materializeCancellationRecord(
      record,
      'published',
      record.revision,
      false,
    )
    return validCancellationRecord(published, now, true)
      ? {
          record: published,
          cancellation: published,
          legacyStatus,
          legacyExpiresAt,
          requiresSlot: false,
          discard: false,
        }
      : null
  }
  if (legacyStatus === 'rejecting' || legacyStatus === 'reject_retry') {
    return cancellation
      ? {
          record: cancellation,
          cancellation,
          legacyStatus,
          legacyExpiresAt,
          requiresSlot: false,
          discard: false,
        }
      : null
  }
  if (fullGrantValid) {
    return {
      record,
      cancellation,
      legacyStatus,
      legacyExpiresAt,
      requiresSlot: statusRequiresActiveSlot(legacyStatus),
      discard: false,
    }
  }
  if (cancellation) {
    return {
      record: cancellation,
      cancellation,
      legacyStatus,
      legacyExpiresAt,
      requiresSlot: statusRequiresActiveSlot(legacyStatus),
      discard: false,
    }
  }
  return null
}

function validLegacyFullGrantRecord(
  record: ResponseVaultRecord,
  now: number,
): boolean {
  if (record.status !== 'published') {
    return validStoredRecord(record, now, true)
  }
  return validStoredRecord(
    {
      ...record,
      status: 'adopted',
    },
    now,
    true,
  )
}

function migrateLegacyCancellationV5(
  record: ResponseVaultRecord,
  now: number,
): MutableResponseVaultCancellationRecord | undefined {
  if (
    record.status === 'reject_blocked' ||
    !CANCELLATION_SOURCE_STATUSES.has(record.status) ||
    !validCancellationAuthority(record, now, true)
  ) {
    return undefined
  }
  const cancellation = materializeCancellationRecord(
    record,
    'reject_retry',
    record.revision,
    false,
  )
  return validCancellationRecord(cancellation, now, true)
    ? cancellation
    : undefined
}
