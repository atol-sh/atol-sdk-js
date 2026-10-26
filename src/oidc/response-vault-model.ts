import type { DPoPKeyManager } from '../dpop/dpop'
import type { CredentialGenerationSnapshot } from './credential-generation'

export const RESPONSE_VAULT_DB_NAME = 'atol-sdk-response-vault'
export const RESPONSE_VAULT_DB_VERSION = 5
export const RESPONSE_VAULT_RECORD_STORE = 'authorizations'
export const RESPONSE_VAULT_SLOT_STORE = 'authorization-slots'
export const RESPONSE_VAULT_RECORD_VERSION = 1
export const RESPONSE_VAULT_PRE_TRANSACTION_TTL_MS = 60 * 1000
export const RESPONSE_VAULT_DEFAULT_EXECUTION_LEASE_MS = 30 * 1000
export const RESPONSE_VAULT_MAX_EXECUTION_LEASE_MS = 5 * 60 * 1000
export const RESPONSE_VAULT_EXECUTION_LOCK_WAIT_MS = 5 * 1000
export const RESPONSE_VAULT_CANONICAL_OPAQUE = /^[A-Za-z0-9_-]{43}$/
export const RESPONSE_VAULT_TERMINAL_PROOF_BYTES = 58
export const RESPONSE_VAULT_TERMINAL_PROOF_LENGTH = 78
export const RESPONSE_VAULT_REQUEST_URI_PREFIX =
  'urn:ietf:params:oauth:request_uri:'
export const RESPONSE_VAULT_TERMINAL_ERROR_CODES = new Set([
  'invalid_request',
  'access_denied',
  'login_required',
  'temporarily_unavailable',
  'server_error',
])
export const RESPONSE_VAULT_OAUTH_NQCHAR = /^[\x21\x23-\x5B\x5D-\x7E]+$/

export type ResponseVaultAuthorizationMode = 'interactive' | 'iframe'
export type ResponseVaultRejectionProvenance =
  | 'internal'
  | 'interactive_cancel'
  | 'failed_init_cancel'
export type ResponseVaultAuthorizationStatus =
  | 'prepared'
  | 'par_pending'
  | 'pushed'
  | 'initializing'
  | 'initialized'
  | 'navigating'
  | 'redeeming'
  | 'relay_retry'
  | 'awaiting_ack'
  | 'publishing'
  | 'finalizing'
  | 'adopted'
  | 'published'
  | 'rejecting'
  | 'reject_retry'
  | 'reject_blocked'

type ResponseVaultTransactionBinding =
  'none' | 'par_pending' | 'request' | 'transaction'

type ResponseVaultTerminalProofBinding = 'none' | 'bootstrap' | 'transaction'

interface ResponseVaultStatusSchema {
  fullGrant: boolean
  settlement: boolean
  activeSlot: boolean
  cancellation: boolean
  transactionBinding: ResponseVaultTransactionBinding
  terminalProofBinding: ResponseVaultTerminalProofBinding
  phaseDeadline: boolean
  locallyReapable: boolean
}

/**
 * Exhaustive persisted-state schema. Every validator, migration, and reaper
 * derives status semantics from this table so adding a state cannot silently
 * create a second interpretation of durable authority.
 */
export const RESPONSE_VAULT_STATUS_SCHEMA = {
  prepared: {
    fullGrant: true,
    settlement: false,
    activeSlot: true,
    cancellation: false,
    transactionBinding: 'none',
    terminalProofBinding: 'none',
    phaseDeadline: true,
    locallyReapable: false,
  },
  par_pending: {
    fullGrant: true,
    settlement: false,
    activeSlot: true,
    cancellation: false,
    transactionBinding: 'par_pending',
    terminalProofBinding: 'bootstrap',
    phaseDeadline: true,
    locallyReapable: false,
  },
  pushed: {
    fullGrant: true,
    settlement: false,
    activeSlot: true,
    cancellation: true,
    transactionBinding: 'request',
    terminalProofBinding: 'transaction',
    phaseDeadline: true,
    locallyReapable: false,
  },
  initializing: {
    fullGrant: true,
    settlement: false,
    activeSlot: true,
    cancellation: true,
    transactionBinding: 'request',
    terminalProofBinding: 'transaction',
    phaseDeadline: true,
    locallyReapable: false,
  },
  initialized: {
    fullGrant: true,
    settlement: false,
    activeSlot: true,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  navigating: {
    fullGrant: true,
    settlement: false,
    activeSlot: true,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  redeeming: {
    fullGrant: true,
    settlement: false,
    activeSlot: true,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  relay_retry: {
    fullGrant: true,
    settlement: false,
    activeSlot: true,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  awaiting_ack: {
    fullGrant: true,
    settlement: true,
    activeSlot: true,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  publishing: {
    fullGrant: true,
    settlement: true,
    activeSlot: true,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  finalizing: {
    fullGrant: true,
    settlement: true,
    activeSlot: true,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  adopted: {
    fullGrant: true,
    settlement: true,
    activeSlot: false,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  published: {
    fullGrant: false,
    settlement: false,
    activeSlot: false,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  rejecting: {
    fullGrant: false,
    settlement: false,
    activeSlot: false,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  reject_retry: {
    fullGrant: false,
    settlement: false,
    activeSlot: false,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
  reject_blocked: {
    fullGrant: false,
    settlement: false,
    activeSlot: false,
    cancellation: true,
    transactionBinding: 'transaction',
    terminalProofBinding: 'transaction',
    phaseDeadline: false,
    locallyReapable: false,
  },
} as const satisfies Record<
  ResponseVaultAuthorizationStatus,
  ResponseVaultStatusSchema
>

export type ResponseVaultSettlement =
  { kind: 'success' } | { kind: 'error'; errorCode: string }

export interface ResponseVaultBinding {
  issuer: string
  clientId: string
  redirectUri: string
  audience: string
  scope: string
}

/** Exact origin authority required to supersede one invalidated generation. */
export interface ResponseVaultExactGenerationSupersession {
  invalidatedGeneration: CredentialGenerationSnapshot
  signedOutLogoutGeneration: string
  mode: ResponseVaultAuthorizationMode
}

export interface ResponseVaultIntent {
  prompt?: string
  maxAge?: number
  acrValues?: string
  organizationId?: string
  returnTo?: string
}

export interface ResponseVaultSecrets {
  state: string
  nonce: string
  codeVerifier: string
  codeChallenge: string
  tabSecret: string
  parIdempotencyKey: string
  cancellationSecret: string
}

export interface ResponseVaultReference {
  version: 1
  id: string
}

export interface ResponseVaultExecutionClaim {
  owner: string
  fence: number
}

export interface ResponseVaultAuthorization {
  reference: ResponseVaultReference
  binding: ResponseVaultBinding
  mode: ResponseVaultAuthorizationMode
  intent: ResponseVaultIntent
  lifecycleEpoch: number
  credentialGeneration: CredentialGenerationSnapshot
  status: ResponseVaultAuthorizationStatus
  jkt: string
  state: string
  nonce: string
  codeVerifier: string
  codeChallenge: string
  tabSecret: string
  parIdempotencyKey: string
  cancellationSecret: string
  transactionId?: string
  requestUri?: string
  csrfToken?: string
  bootstrapAttemptCapability?: string
  bootstrapTerminalProof?: string
  terminalProof?: string
  settlement?: ResponseVaultSettlement
  expiresAt: number
  phaseExpiresAt?: number
  executionClaim?: ResponseVaultExecutionClaim
  executionLeaseExpiresAt?: number
  navigationOwner?: string
  navigationExpiresAt?: number
  dpopKey: DPoPKeyManager
}

/**
 * Minimal monotonic server-cancellation authority.
 *
 * This view deliberately excludes every grant-producing secret and the DPoP
 * key. The server's exact transaction, tab, cancellation, and terminal-proof
 * capabilities are sufficient for authenticated settlement and /reject, so
 * damaged or unavailable signing custody must not prevent revocation.
 */
export interface ResponseVaultCancellation {
  reference: ResponseVaultReference
  binding: ResponseVaultBinding
  lifecycleEpoch: number
  credentialGeneration: CredentialGenerationSnapshot
  sourceMode?: ResponseVaultAuthorizationMode
  rejectionProvenance: ResponseVaultRejectionProvenance
  status: ResponseVaultAuthorizationStatus
  transactionId: string
  tabSecret: string
  cancellationSecret: string
  terminalProof: string
  expiresAt: number
  executionClaim?: ResponseVaultExecutionClaim
  executionLeaseExpiresAt?: number
}

export type ResponseVaultCustody =
  ResponseVaultAuthorization | ResponseVaultCancellation

export interface ResponseVaultCancellationBatch {
  cancellations: ResponseVaultCancellation[]
  errors: unknown[]
  hasMore: boolean
  commit(): void
}

export interface ResponseVaultActiveCustody {
  custody: ResponseVaultCustody | null
  grantError?: unknown
  rejectionOwner?: string
}

export interface ResponseVaultRecord {
  version: 1
  revision: number
  id: string
  issuer: string
  clientId: string
  redirectUri: string
  audience: string
  scope: string
  mode: ResponseVaultAuthorizationMode
  prompt?: string
  maxAge?: number
  acrValues?: string
  organizationId?: string
  returnTo?: string
  credentialGeneration: CredentialGenerationSnapshot
  status: ResponseVaultAuthorizationStatus
  jkt: string
  state: string
  nonce: string
  codeVerifier: string
  codeChallenge: string
  tabSecret: string
  parIdempotencyKey: string
  cancellationSecret: string
  transactionId?: string
  requestUri?: string
  csrfToken?: string
  bootstrapAttemptCapability?: string
  bootstrapTerminalProof?: string
  terminalProof?: string
  settlementKind?: 'success' | 'error'
  settlementErrorCode?: string
  createdAt: number
  expiresAt: number
  phaseExpiresAt?: number
  executionFence: number
  executionOwner?: string
  executionExpiresAt?: number
  navigationOwner?: string
  navigationExpiresAt?: number
  keys: CryptoKeyPair
}

export type ResponseVaultCancellationRecord = Pick<
  ResponseVaultRecord,
  | 'version'
  | 'revision'
  | 'id'
  | 'issuer'
  | 'clientId'
  | 'redirectUri'
  | 'audience'
  | 'scope'
  | 'credentialGeneration'
  | 'status'
  | 'tabSecret'
  | 'cancellationSecret'
  | 'bootstrapAttemptCapability'
  | 'terminalProof'
  | 'transactionId'
  | 'expiresAt'
  | 'executionFence'
  | 'executionOwner'
  | 'executionExpiresAt'
> & {
  custody?: 'cancellation'
  rejectionProvenance: ResponseVaultRejectionProvenance
  transactionId: string
  terminalProof: string
}

export type MutableResponseVaultCancellationRecord =
  ResponseVaultCancellationRecord &
    Partial<ResponseVaultRecord> & {
      custody?: 'cancellation'
    }

export const RESPONSE_VAULT_RECORD_MEMBERS = new Set<string>([
  'version',
  'revision',
  'id',
  'issuer',
  'clientId',
  'redirectUri',
  'audience',
  'scope',
  'mode',
  'prompt',
  'maxAge',
  'acrValues',
  'organizationId',
  'returnTo',
  'credentialGeneration',
  'status',
  'jkt',
  'state',
  'nonce',
  'codeVerifier',
  'codeChallenge',
  'tabSecret',
  'parIdempotencyKey',
  'cancellationSecret',
  'transactionId',
  'requestUri',
  'csrfToken',
  'bootstrapAttemptCapability',
  'bootstrapTerminalProof',
  'terminalProof',
  'settlementKind',
  'settlementErrorCode',
  'createdAt',
  'expiresAt',
  'phaseExpiresAt',
  'executionFence',
  'executionOwner',
  'executionExpiresAt',
  'navigationOwner',
  'navigationExpiresAt',
  'keys',
])

const RESPONSE_VAULT_CANCELLATION_MEMBERS = new Set<string>([
  'version',
  'revision',
  'id',
  'issuer',
  'clientId',
  'redirectUri',
  'audience',
  'scope',
  'credentialGeneration',
  'rejectionProvenance',
  'status',
  'tabSecret',
  'cancellationSecret',
  'bootstrapAttemptCapability',
  'transactionId',
  'terminalProof',
  'expiresAt',
  'executionFence',
  'custody',
])

export const RESPONSE_VAULT_SLOT_MEMBERS = new Set<string>([
  'version',
  'key',
  'referenceId',
  'expiresAt',
])

export function hasOnlyOwnMembers(
  value: object,
  allowed: ReadonlySet<string>,
): boolean {
  return Object.keys(value).every((member) => allowed.has(member))
}

export function hasExactCancellationMembers(
  value: MutableResponseVaultCancellationRecord,
): boolean {
  const members = Object.keys(value)
  const hasExecutionOwner = Object.prototype.hasOwnProperty.call(
    value,
    'executionOwner',
  )
  const hasExecutionExpiry = Object.prototype.hasOwnProperty.call(
    value,
    'executionExpiresAt',
  )
  if (hasExecutionOwner !== hasExecutionExpiry) return false
  if (
    hasExecutionOwner &&
    (value.executionOwner === undefined ||
      value.executionExpiresAt === undefined)
  ) {
    return false
  }
  const expectedCount =
    RESPONSE_VAULT_CANCELLATION_MEMBERS.size + (hasExecutionOwner ? 2 : 0)
  return (
    members.length === expectedCount &&
    members.every(
      (member) =>
        RESPONSE_VAULT_CANCELLATION_MEMBERS.has(member) ||
        (hasExecutionOwner &&
          (member === 'executionOwner' || member === 'executionExpiresAt')),
    )
  )
}

export interface ResponseVaultSlotRecord {
  version: 1
  key: string
  referenceId: string
  expiresAt: number
}

export class ResponseVaultAuthorizationBusyError extends Error {
  constructor() {
    super('response vault: another authorization owns this tab slot')
    this.name = 'ResponseVaultAuthorizationBusyError'
  }
}

export class ResponseVaultExecutionBusyError extends ResponseVaultAuthorizationBusyError {
  constructor() {
    super()
    this.name = 'ResponseVaultExecutionBusyError'
  }
}
