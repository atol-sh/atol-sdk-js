import type { DPoPKeyManager } from '../dpop/dpop'
import type { TokenResponse } from './silent-renew'
import { NetworkError } from './token-recovery'
import type { CredentialGenerationSnapshot } from './credential-generation'
import type {
  ResponseVaultAuthorization,
  ResponseVaultAuthorizationStatus,
  ResponseVaultBinding,
} from './response-vault-storage'

export const RESPONSE_VAULT_PROTOCOL_VERSION = 1 as const
export const RESPONSE_MODE = 'atol_console_vault'
export const DISCOVERY_PATH = '/.well-known/openid-configuration'
export const BOOTSTRAP_PATH = '/auth/browser/v1/bootstrap'
export const PAR_PATH = '/auth/browser/v1/pushed-authorization-requests'
export const ISSUER_BOOTSTRAP_PATH = '/auth/browser/v1/issuer-bootstrap'
export const AUTHORIZATION_INIT_PATH = '/auth/browser/v1/authorization-init'
export const RELAY_PATH = '/auth/browser/v1/relay'
export const ACKNOWLEDGE_PATH = '/auth/browser/v1/acknowledge'
export const FINALIZE_PATH = '/auth/browser/v1/finalize'
export const REJECT_PATH = '/auth/browser/v1/reject'
export const TOKEN_PATH = '/auth/token'
export const AUTHORIZE_PATH = '/auth/authorize'
export const CSRF_HEADER = 'X-Atol-CSRF'
export const CANONICAL_OPAQUE = /^[A-Za-z0-9_-]{43}$/
export const DEFAULT_IFRAME_TIMEOUT_MS = 60_000
export const DEFAULT_OPERATION_TIMEOUT_MS = 15_000
export const MAX_RESPONSE_BODY_BYTES = 32 * 1024
export const BOOTSTRAP_MAX_LIFETIME_SECONDS = 60
export const REQUEST_URI_MAX_LIFETIME_SECONDS = 60
export const TRANSACTION_MAX_LIFETIME_SECONDS = 10 * 60

export const REJECTION_CLAIM_STATUSES = [
  'pushed',
  'initializing',
  'initialized',
  'navigating',
  'redeeming',
  'relay_retry',
  'awaiting_ack',
  'publishing',
  'finalizing',
  'adopted',
  'published',
  'rejecting',
  'reject_retry',
] as const satisfies readonly ResponseVaultAuthorizationStatus[]

export interface ResponseVaultConfig extends ResponseVaultBinding {
  iframeTimeoutMs?: number
  operationTimeoutMs?: number
}

export interface ResponseVaultGrant {
  tokens: TokenResponse
  nonce: string
  dpopKey: DPoPKeyManager
  dpopNonce?: string
  returnTo?: string
  credentialGeneration: CredentialGenerationSnapshot
  acknowledge(): Promise<void>
  finalize(): Promise<void>
  completePublication(): Promise<void>
  reject(): Promise<void>
}

const settlementPendingAuthorizations = new WeakMap<
  ResponseVaultSettlementPendingError,
  ResponseVaultAuthorization
>()
const deliveryUnavailableReturnTargets = new WeakMap<
  ResponseVaultDeliveryUnavailableError,
  string
>()

export class ResponseVaultSettlementPendingError extends NetworkError {
  readonly code = 'response_vault_settlement_pending'

  constructor(
    _cause: unknown,
    authorization?: ResponseVaultAuthorization,
  ) {
    super('response vault: settlement remains pending and can be retried')
    this.name = 'ResponseVaultSettlementPendingError'
    if (authorization) {
      settlementPendingAuthorizations.set(this, authorization)
    }
  }
}

/**
 * Internal one-shot recovery capability. This is deliberately absent from
 * the public response-vault facade: settlement custody must never become an
 * Error property or prototype accessor visible to logging and inspection.
 */
export function takeResponseVaultSettlementAuthorization(
  error: ResponseVaultSettlementPendingError,
): ResponseVaultAuthorization | undefined {
  const authorization = settlementPendingAuthorizations.get(error)
  settlementPendingAuthorizations.delete(error)
  return authorization
}

export class ResponseVaultDeliveryUnavailableError extends Error {
  readonly code = 'response_vault_delivery_unavailable'

  constructor(returnTo?: string) {
    super(
      'response vault: acknowledgement succeeded but the parsed delivery is no longer in memory',
    )
    this.name = 'ResponseVaultDeliveryUnavailableError'
    if (returnTo !== undefined) {
      deliveryUnavailableReturnTargets.set(this, returnTo)
    }
  }
}

/**
 * Internal one-shot recovery capability for the validated application route.
 * The route is deliberately absent from the public Error object because it may
 * contain application query or fragment data.
 */
export function takeResponseVaultDeliveryReturnTo(
  error: ResponseVaultDeliveryUnavailableError,
): string | undefined {
  const returnTo = deliveryUnavailableReturnTargets.get(error)
  deliveryUnavailableReturnTargets.delete(error)
  return returnTo
}

export class ResponseVaultRejectionPendingError extends NetworkError {
  constructor(_cause: unknown) {
    super('response vault: rejection remains pending and can be retried')
    this.name = 'ResponseVaultRejectionPendingError'
  }
}

export class ResponseVaultRejectionBlockedError extends Error {
  constructor(_cause: unknown) {
    super('response vault: rejection was denied and remains durably blocked')
    this.name = 'ResponseVaultRejectionBlockedError'
  }
}

export class ResponseVaultCleanupPendingError extends Error {
  readonly code = 'response_vault_cleanup_pending'

  constructor(_cause: unknown) {
    super('response vault: local settlement cleanup remains pending')
    this.name = 'ResponseVaultCleanupPendingError'
  }
}

export class ResponseVaultAuthorizationInvalidatedError extends Error {
  readonly code = 'response_vault_authorization_invalidated'

  constructor() {
    super('response vault: authorization was invalidated')
    this.name = 'ResponseVaultAuthorizationInvalidatedError'
  }
}

export class ResponseVaultAuthorizationBindingMismatchError extends Error {
  readonly code = 'response_vault_authorization_binding_mismatch'

  constructor() {
    super('response vault: authorization binding mismatch')
    this.name = 'ResponseVaultAuthorizationBindingMismatchError'
  }
}

export class ResponseVaultGrantRejectedError extends Error {
  constructor() {
    super('response vault: the authorization grant was rejected')
    this.name = 'ResponseVaultGrantRejectedError'
  }
}

export class ResponseVaultAuthenticatedTerminalError extends Error {
  constructor() {
    super('response vault: server authenticated terminal authorization')
    this.name = 'ResponseVaultAuthenticatedTerminalError'
  }
}

export function aggregateCleanupError(
  errors: readonly unknown[],
): ResponseVaultCleanupPendingError | undefined {
  if (errors.length === 0) return undefined
  return new ResponseVaultCleanupPendingError(undefined)
}

export interface BootstrapResponse {
 csrfToken: string
	bootstrapTerminalProof: string
	bootstrapExpiresAt: number
}

export interface BootstrapAttemptChallenge {
	attemptCapability: string
	attemptExpiresAt: number
}

export interface IssuerBootstrapResponse {
  csrfToken: string
  bootstrapExpiresAt: number
}

export interface PushedAuthorizationResponse {
  transactionId: string
  requestUri: string
  csrfToken: string
  terminalProof: string
  requestUriExpiresAt: number
  transactionExpiresAt: number
}

export interface RelaySuccess {
  tokens: TokenResponse
  csrfToken: string
}

export interface ResponseVaultEndpoints {
  bootstrap: string
  pushedAuthorizationRequest: string
  issuerBootstrap: string
  authorizationInit: string
  authorization: string
  relay: string
  acknowledgement: string
  finalization: string
  rejection: string
  token: string
}

export type PendingSettlement =
  | {
      kind: 'success'
      referenceId: string
      grant: ResponseVaultGrant
    }
  | {
      kind: 'error'
      referenceId: string
      authorization: ResponseVaultAuthorization
      error: Error
    }
