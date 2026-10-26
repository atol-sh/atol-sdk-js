import { base64ToBytes, bytesToBase64Url } from '../crypto/base64url'
import { restoreDPoPKeyManager } from '../dpop/dpop'
import { isCredentialGeneration } from './credential-generation'
import type { CredentialGenerationSnapshot } from './credential-generation'
import { normalizeSameOriginReturnTo } from './return-to'
import {
  RESPONSE_VAULT_CANONICAL_OPAQUE as CANONICAL_OPAQUE,
  RESPONSE_VAULT_OAUTH_NQCHAR as OAUTH_NQCHAR,
  RESPONSE_VAULT_RECORD_MEMBERS,
  RESPONSE_VAULT_RECORD_VERSION as RECORD_VERSION,
  RESPONSE_VAULT_REQUEST_URI_PREFIX as REQUEST_URI_PREFIX,
  RESPONSE_VAULT_SLOT_MEMBERS,
  RESPONSE_VAULT_STATUS_SCHEMA,
  RESPONSE_VAULT_TERMINAL_PROOF_BYTES as TERMINAL_PROOF_BYTES,
  RESPONSE_VAULT_TERMINAL_PROOF_LENGTH as TERMINAL_PROOF_LENGTH,
  RESPONSE_VAULT_TERMINAL_ERROR_CODES as TERMINAL_ERROR_CODES,
  hasExactCancellationMembers,
  hasOnlyOwnMembers,
  type MutableResponseVaultCancellationRecord,
  type ResponseVaultAuthorizationStatus,
  type ResponseVaultBinding,
  type ResponseVaultCancellationRecord,
  type ResponseVaultIntent,
  type ResponseVaultRecord,
  type ResponseVaultSecrets,
  type ResponseVaultSettlement,
  type ResponseVaultSlotRecord,
} from './response-vault-model'

export function randomOpaque(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return bytesToBase64Url(bytes)
}

function boundedProtocolString(
  value: unknown,
  maximum: number,
): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maximum &&
    value.trim() === value &&
    !/[\u0000-\u001F\u007F]/.test(value)
  )
}

/** Validate the canonical OIDC scope list supported by response-vault v1. */
export function validResponseVaultScope(scope: unknown): scope is string {
  if (typeof scope !== 'string' || scope.length === 0 || scope.length > 512) {
    return false
  }
  const scopes = scope.split(' ')
  return (
    scopes.includes('openid') &&
    new Set(scopes).size === scopes.length &&
    scopes.every((value) => OAUTH_NQCHAR.test(value))
  )
}

/** Validate a bounded, space-delimited OIDC acr_values string. */
export function validResponseVaultACRValues(
  acrValues: unknown,
): acrValues is string {
  if (
    typeof acrValues !== 'string' ||
    acrValues.length === 0 ||
    acrValues.length > 512
  ) {
    return false
  }
  const values = acrValues.split(' ')
  return (
    new Set(values).size === values.length &&
    values.every((value) => OAUTH_NQCHAR.test(value))
  )
}

export function validResponseVaultBinding(
  binding: ResponseVaultBinding,
): boolean {
  return (
    boundedProtocolString(binding.issuer, 2048) &&
    boundedProtocolString(binding.clientId, 512) &&
    boundedProtocolString(binding.redirectUri, 2048) &&
    boundedProtocolString(binding.audience, 512) &&
    validResponseVaultScope(binding.scope)
  )
}

export function validResponseVaultIntent(
  intent: ResponseVaultIntent,
  redirectUri: string,
): boolean {
  let normalizedReturnTo: string | undefined
  try {
    normalizedReturnTo = normalizeSameOriginReturnTo(
      intent.returnTo,
      redirectUri,
    )
  } catch {
    return false
  }
  return (
    (intent.prompt === undefined ||
      intent.prompt === 'login' ||
      intent.prompt === 'none') &&
    (intent.maxAge === undefined ||
      (Number.isInteger(intent.maxAge) &&
        intent.maxAge >= 0 &&
        intent.maxAge <= 86_400)) &&
    (intent.acrValues === undefined ||
      validResponseVaultACRValues(intent.acrValues)) &&
    (intent.organizationId === undefined ||
      /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(intent.organizationId)) &&
    normalizedReturnTo === intent.returnTo
  )
}

export function validSecrets(secrets: ResponseVaultSecrets): boolean {
  return (
    CANONICAL_OPAQUE.test(secrets.state) &&
    CANONICAL_OPAQUE.test(secrets.nonce) &&
    CANONICAL_OPAQUE.test(secrets.codeVerifier) &&
    CANONICAL_OPAQUE.test(secrets.codeChallenge) &&
    CANONICAL_OPAQUE.test(secrets.tabSecret) &&
    CANONICAL_OPAQUE.test(secrets.parIdempotencyKey) &&
    CANONICAL_OPAQUE.test(secrets.cancellationSecret)
  )
}

export function validRequestURI(value: string): boolean {
  return (
    value.startsWith(REQUEST_URI_PREFIX) &&
    CANONICAL_OPAQUE.test(value.slice(REQUEST_URI_PREFIX.length))
  )
}

export function validResponseVaultTerminalProof(
  value: unknown,
): value is string {
  if (typeof value !== 'string' || value.length !== TERMINAL_PROOF_LENGTH) {
    return false
  }
  try {
    const raw = base64ToBytes(value)
    return (
      raw.length === TERMINAL_PROOF_BYTES && bytesToBase64Url(raw) === value
    )
  } catch {
    return false
  }
}

export function validSettlement(
  settlement: ResponseVaultSettlement | undefined,
): boolean {
  return (
    settlement === undefined ||
    settlement.kind === 'success' ||
    (settlement.kind === 'error' &&
      TERMINAL_ERROR_CODES.has(settlement.errorCode))
  )
}

export function clientOrigin(binding: ResponseVaultBinding): string {
  return new URL(binding.redirectUri).origin
}

export function slotKey(binding: ResponseVaultBinding): string {
  return JSON.stringify([RECORD_VERSION, clientOrigin(binding)])
}

export function validSlotRecord(
  slot: unknown,
  expectedKey: string,
): slot is ResponseVaultSlotRecord {
  if (!slot || typeof slot !== 'object') return false
  const candidate = slot as Partial<ResponseVaultSlotRecord>
  return (
    Object.keys(candidate).length === RESPONSE_VAULT_SLOT_MEMBERS.size &&
    hasOnlyOwnMembers(candidate, RESPONSE_VAULT_SLOT_MEMBERS) &&
    candidate.version === RECORD_VERSION &&
    candidate.key === expectedKey &&
    typeof candidate.referenceId === 'string' &&
    CANONICAL_OPAQUE.test(candidate.referenceId) &&
    Number.isSafeInteger(candidate.expiresAt)
  )
}

export function recordBinding(
  record: Pick<
    ResponseVaultRecord,
    'issuer' | 'clientId' | 'redirectUri' | 'audience' | 'scope'
  >,
): ResponseVaultBinding {
  return {
    issuer: record.issuer,
    clientId: record.clientId,
    redirectUri: record.redirectUri,
    audience: record.audience,
    scope: record.scope,
  }
}

export function sameCredentialGeneration(
  left: CredentialGenerationSnapshot,
  right: CredentialGenerationSnapshot,
): boolean {
  return left.logout === right.logout && left.tabOwner === right.tabOwner
}

export function recordSettlement(
  record: ResponseVaultRecord,
): ResponseVaultSettlement | undefined {
  if (record.settlementKind === undefined) return undefined
  if (record.settlementKind === 'success') return { kind: 'success' }
  if (
    record.settlementKind === 'error' &&
    record.settlementErrorCode !== undefined
  ) {
    return { kind: 'error', errorCode: record.settlementErrorCode }
  }
  return undefined
}

export function statusRequiresSettlement(
  status: ResponseVaultAuthorizationStatus,
): boolean {
  return RESPONSE_VAULT_STATUS_SCHEMA[status].settlement
}

export function statusRequiresActiveSlot(
  status: ResponseVaultAuthorizationStatus,
): boolean {
  return RESPONSE_VAULT_STATUS_SCHEMA[status].activeSlot
}

export const CANCELLATION_SOURCE_STATUSES =
  new Set<ResponseVaultAuthorizationStatus>(
    (
      Object.keys(
        RESPONSE_VAULT_STATUS_SCHEMA,
      ) as ResponseVaultAuthorizationStatus[]
    ).filter((status) => RESPONSE_VAULT_STATUS_SCHEMA[status].cancellation),
  )

function validPhaseExpiry(record: ResponseVaultRecord): boolean {
  const requiresPhase =
    RESPONSE_VAULT_STATUS_SCHEMA[record.status].phaseDeadline
  if (!requiresPhase) return record.phaseExpiresAt === undefined
  return (
    Number.isSafeInteger(record.phaseExpiresAt) &&
    (record.phaseExpiresAt as number) <= record.expiresAt
  )
}

function validExecutionLease(
  record: Pick<
    ResponseVaultRecord,
    'executionFence' | 'executionOwner' | 'executionExpiresAt' | 'expiresAt'
  >,
): boolean {
  if (
    !Number.isSafeInteger(record.executionFence) ||
    record.executionFence < 0
  ) {
    return false
  }
  const hasOwner = record.executionOwner !== undefined
  const hasExpiry = record.executionExpiresAt !== undefined
  if (hasOwner !== hasExpiry) return false
  if (!hasOwner) return true
  return (
    CANONICAL_OPAQUE.test(record.executionOwner as string) &&
    Number.isSafeInteger(record.executionExpiresAt) &&
    (record.executionExpiresAt as number) >= 0
  )
}

function validNavigationLease(
  record: Pick<
    ResponseVaultRecord,
    | 'status'
    | 'navigationOwner'
    | 'navigationExpiresAt'
    | 'executionOwner'
    | 'executionExpiresAt'
    | 'expiresAt'
  >,
): boolean {
  if (record.status !== 'navigating') {
    return (
      record.navigationOwner === undefined &&
      record.navigationExpiresAt === undefined
    )
  }
  return (
    typeof record.navigationOwner === 'string' &&
    CANONICAL_OPAQUE.test(record.navigationOwner) &&
    Number.isSafeInteger(record.navigationExpiresAt) &&
    (record.navigationExpiresAt as number) <= record.expiresAt &&
    record.executionOwner === undefined &&
    record.executionExpiresAt === undefined
  )
}

function validStatusBinding(record: ResponseVaultRecord): boolean {
  const transactionBound =
    typeof record.transactionId === 'string' &&
    CANONICAL_OPAQUE.test(record.transactionId)
  const requestBound =
    typeof record.requestUri === 'string' && validRequestURI(record.requestUri)
  const csrfBound =
    typeof record.csrfToken === 'string' &&
    CANONICAL_OPAQUE.test(record.csrfToken)
  const transactionAbsent = record.transactionId === undefined
  const requestAbsent = record.requestUri === undefined
  const csrfAbsent = record.csrfToken === undefined
  let transactionBindingValid: boolean
  switch (RESPONSE_VAULT_STATUS_SCHEMA[record.status].transactionBinding) {
    case 'none':
      transactionBindingValid = transactionAbsent && requestAbsent && csrfAbsent
      break
    case 'par_pending':
      transactionBindingValid = transactionAbsent && requestAbsent && csrfBound
      break
    case 'request':
      transactionBindingValid = transactionBound && requestBound && csrfBound
      break
    case 'transaction':
      transactionBindingValid = transactionBound && requestAbsent && csrfBound
      break
  }
  if (!transactionBindingValid) return false

  const bootstrapProofBound = validResponseVaultTerminalProof(
    record.bootstrapTerminalProof,
  )
  const transactionProofBound = validResponseVaultTerminalProof(
    record.terminalProof,
  )
  switch (RESPONSE_VAULT_STATUS_SCHEMA[record.status].terminalProofBinding) {
    case 'none':
      return (
        record.bootstrapTerminalProof === undefined &&
        record.terminalProof === undefined
      )
    case 'bootstrap':
      return bootstrapProofBound && record.terminalProof === undefined
    case 'transaction':
      return (
        record.bootstrapTerminalProof === undefined && transactionProofBound
      )
  }
}

function validStoredSettlement(record: ResponseVaultRecord): boolean {
  if (record.settlementKind === undefined) {
    return record.settlementErrorCode === undefined
  }
  if (record.settlementKind === 'success') {
    return record.settlementErrorCode === undefined
  }
  return (
    record.settlementKind === 'error' &&
    typeof record.settlementErrorCode === 'string' &&
    TERMINAL_ERROR_CODES.has(record.settlementErrorCode)
  )
}

function validBootstrapAttemptCapability(record: ResponseVaultRecord): boolean {
  const valid = validResponseVaultTerminalProof(
    record.bootstrapAttemptCapability,
  )
  return record.status === 'prepared'
    ? record.bootstrapAttemptCapability === undefined || valid
    : valid
}

export function validStoredRecord(
  record: ResponseVaultRecord,
  now: number,
  allowExpired: boolean,
): boolean {
  const statusSchema = Object.prototype.hasOwnProperty.call(
    RESPONSE_VAULT_STATUS_SCHEMA,
    record.status,
  )
    ? RESPONSE_VAULT_STATUS_SCHEMA[
        record.status as ResponseVaultAuthorizationStatus
      ]
    : undefined
  const settlement = recordSettlement(record)
  if (
    !hasOnlyOwnMembers(record, RESPONSE_VAULT_RECORD_MEMBERS) ||
    record.version !== RECORD_VERSION ||
    (record as ResponseVaultRecord & { custody?: unknown }).custody !==
      undefined ||
    !Number.isSafeInteger(record.revision) ||
    record.revision < 1 ||
    typeof record.id !== 'string' ||
    !CANONICAL_OPAQUE.test(record.id) ||
    !validResponseVaultBinding(recordBinding(record)) ||
    (record.mode !== 'interactive' && record.mode !== 'iframe') ||
    !validResponseVaultIntent(
      {
        prompt: record.prompt,
        maxAge: record.maxAge,
        acrValues: record.acrValues,
        organizationId: record.organizationId,
        returnTo: record.returnTo,
      },
      record.redirectUri,
    ) ||
    !isCredentialGeneration(record.credentialGeneration?.logout) ||
    !isCredentialGeneration(record.credentialGeneration?.tabOwner) ||
    !statusSchema?.fullGrant ||
    !CANONICAL_OPAQUE.test(record.jkt) ||
    !validSecrets(record) ||
    !Number.isSafeInteger(record.createdAt) ||
    !Number.isSafeInteger(record.expiresAt) ||
    (!allowExpired && record.expiresAt <= now) ||
    !validPhaseExpiry(record) ||
    !validBootstrapAttemptCapability(record) ||
    !validStatusBinding(record) ||
    !validStoredSettlement(record) ||
    statusRequiresSettlement(record.status) !== (settlement !== undefined) ||
    !validExecutionLease(record) ||
    !validNavigationLease(record)
  ) {
    return false
  }
  try {
    restoreDPoPKeyManager(record.keys)
  } catch {
    return false
  }
  return true
}

export function validCancellationAuthority(
  value: unknown,
  now: number,
  allowExpired = false,
): value is MutableResponseVaultCancellationRecord {
  if (!value || typeof value !== 'object') return false
  const record = value as Partial<MutableResponseVaultCancellationRecord>
  const binding = {
    issuer: record.issuer,
    clientId: record.clientId,
    redirectUri: record.redirectUri,
    audience: record.audience,
    scope: record.scope,
  } as ResponseVaultBinding
  const membersValid =
    record.custody === 'cancellation'
      ? hasExactCancellationMembers(
          record as MutableResponseVaultCancellationRecord,
        )
      : record.custody === undefined &&
        hasOnlyOwnMembers(record, RESPONSE_VAULT_RECORD_MEMBERS)
  return (
    membersValid &&
    record.version === RECORD_VERSION &&
    Number.isSafeInteger(record.revision) &&
    (record.revision as number) >= 1 &&
    typeof record.id === 'string' &&
    CANONICAL_OPAQUE.test(record.id) &&
    validResponseVaultBinding(binding) &&
    isCredentialGeneration(record.credentialGeneration?.logout) &&
    isCredentialGeneration(record.credentialGeneration?.tabOwner) &&
    (
      record.custody === 'cancellation'
        ? record.rejectionProvenance === 'internal' ||
          record.rejectionProvenance === 'interactive_cancel' ||
          record.rejectionProvenance === 'failed_init_cancel'
        : record.rejectionProvenance === undefined &&
          (record.mode === 'interactive' || record.mode === 'iframe')
    ) &&
    CANCELLATION_SOURCE_STATUSES.has(
      record.status as ResponseVaultAuthorizationStatus,
    ) &&
    typeof record.transactionId === 'string' &&
    CANONICAL_OPAQUE.test(record.transactionId) &&
    typeof record.tabSecret === 'string' &&
    CANONICAL_OPAQUE.test(record.tabSecret) &&
    typeof record.cancellationSecret === 'string' &&
    CANONICAL_OPAQUE.test(record.cancellationSecret) &&
    validResponseVaultTerminalProof(record.bootstrapAttemptCapability) &&
    record.bootstrapTerminalProof === undefined &&
    validResponseVaultTerminalProof(record.terminalProof) &&
    Number.isSafeInteger(record.expiresAt) &&
    (allowExpired || (record.expiresAt as number) > now) &&
    validExecutionLease(record as MutableResponseVaultCancellationRecord)
  )
}

export function validCancellationRecord(
  value: unknown,
  now: number,
  allowExpired = false,
): value is MutableResponseVaultCancellationRecord {
  return (
    validCancellationAuthority(value, now, allowExpired) &&
    validNavigationLease(value)
  )
}

export type StoredResponseVaultRecord =
  | { kind: 'grant'; record: ResponseVaultRecord }
  | {
      kind: 'cancellation'
      record: MutableResponseVaultCancellationRecord
    }

/**
 * Positively classify the exact persisted v5 shapes. Damaged full records may
 * still expose a separately validated cancellation capability to recovery, but
 * they are never classified as ordinary custody and can never be reaped.
 */
export function classifyStoredRecord(
  value: unknown,
  now: number,
  allowExpired: boolean,
): StoredResponseVaultRecord | undefined {
  if (!value || typeof value !== 'object') return undefined
  if (validStoredRecord(value as ResponseVaultRecord, now, allowExpired)) {
    return { kind: 'grant', record: value as ResponseVaultRecord }
  }
  if (
    value &&
    typeof value === 'object' &&
    (value as { custody?: unknown }).custody === 'cancellation' &&
    validCancellationRecord(value, now, allowExpired)
  ) {
    return { kind: 'cancellation', record: value }
  }
  return undefined
}

export function materializeCancellationRecord(
  source: ResponseVaultCancellationRecord | ResponseVaultRecord,
  status = source.status,
  revision = source.revision,
  retainExecution = true,
  rejectionProvenance?: ResponseVaultCancellationRecord['rejectionProvenance'],
): MutableResponseVaultCancellationRecord {
  if (!source.transactionId || !source.terminalProof) {
    throw new Error(
      'response vault: cancellation materialization binding is incomplete',
    )
  }
  const durableProvenance =
    rejectionProvenance ??
    ('rejectionProvenance' in source
      ? source.rejectionProvenance
      : 'internal')
  const record: MutableResponseVaultCancellationRecord = {
    version: source.version,
    revision,
    id: source.id,
    issuer: source.issuer,
    clientId: source.clientId,
    redirectUri: source.redirectUri,
    audience: source.audience,
    scope: source.scope,
    credentialGeneration: {
      logout: source.credentialGeneration.logout,
      tabOwner: source.credentialGeneration.tabOwner,
    },
    rejectionProvenance: durableProvenance,
    status,
    tabSecret: source.tabSecret,
    cancellationSecret: source.cancellationSecret,
    bootstrapAttemptCapability: source.bootstrapAttemptCapability,
    transactionId: source.transactionId,
    terminalProof: source.terminalProof,
    expiresAt: source.expiresAt,
    executionFence: source.executionFence,
    custody: 'cancellation',
  }
  if (retainExecution && source.executionOwner !== undefined) {
    record.executionOwner = source.executionOwner
  }
  if (retainExecution && source.executionExpiresAt !== undefined) {
    record.executionExpiresAt = source.executionExpiresAt
  }
  return record
}
