import type { DPoPKeyManager } from '../dpop/dpop'
import { base64ToBytes, bytesToBase64Url } from '../crypto/base64url'
import type { CredentialGenerationSnapshot } from './credential-generation'
import type { AuthorizationCodeCallback } from './oidc'
import { hasExactMembers, parseUniqueJSONObject } from './strict-json'

export const ORDINARY_AUTHORIZATION_DB_NAME = 'atol-sdk-browser-auth'
export const ORDINARY_AUTHORIZATION_DB_VERSION = 2
export const ORDINARY_AUTHORIZATION_STORE = 'ordinary-authorizations'
export const ORDINARY_AUTHORIZATION_RECORD_VERSION = 2
export const ORDINARY_AUTHORIZATION_POINTER_VERSION = 1
export const ORDINARY_AUTHORIZATION_PROTOCOL_VERSION = 2
export const AUTHORIZATION_CODE_LIFETIME_SECONDS = 600
export const MAX_CEREMONY_LIFETIME_SECONDS = 15 * 60
export const PAR_TIMEOUT_MS = 15_000
export const SETTLEMENT_TIMEOUT_MS = 15_000
export const CALLBACK_CLAIM_LIFETIME_MS = 2 * 60_000
export const CALLBACK_EXCHANGE_TIMEOUT_MS = 30_000
export const MAX_PAR_RESPONSE_BYTES = 16 * 1024
export const MAX_SETTLEMENT_RESPONSE_BYTES = 1024
export const TERMINAL_PROOF_BYTES = 58
export const TERMINAL_PROOF_LENGTH = 78
export const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:'
export const OIDC_CLIENT_STATE = /^[0-9a-f]{32}$/
export const CANONICAL_NONCE = /^[0-9a-f]{64}$/
export const CANONICAL_SHA256 = /^[A-Za-z0-9_-]{43}$/
export const CANONICAL_AUTHORIZATION_CODE = /^[A-Za-z0-9._~-]{1,8192}$/

export function validCanonicalAttemptCapability(
  value: unknown,
): value is string {
  if (typeof value !== 'string' || value.length !== TERMINAL_PROOF_LENGTH) {
    return false
  }
  try {
    const raw = base64ToBytes(value)
    return (
      raw.length === TERMINAL_PROOF_BYTES &&
      bytesToBase64Url(raw) === value &&
      raw[0] === 1 &&
      raw[1] === 2
    )
  } catch {
    return false
  }
}

export const ORDINARY_AUTHORIZATION_FORM_FIELDS = new Set([
  'atol_attempt_capability',
  'response_type',
  'response_mode',
  'client_id',
  'redirect_uri',
  'scope',
  'state',
  'nonce',
  'code_challenge',
  'code_challenge_method',
  'dpop_jkt',
  'prompt',
  'max_age',
  'login_hint',
  'acr_values',
  'audience',
  'atol_org_id',
  'derive_encryption_key',
])

export const ORDINARY_AUTHORIZATION_EXTENSION_FIELDS = new Set([
  'audience',
  'atol_org_id',
  'derive_encryption_key',
])

export interface OrdinaryAuthorizationBinding {
  issuer: string
  clientId: string
  redirectUri: string
  scope: string
}

export interface OrdinaryAuthorizationIntent {
  responseMode?: 'web_message'
  prompt?: string
  maxAge?: number
  acrValues?: string
  returnTo?: string
  extraQueryParams?: Record<string, string>
  dpopEnabled: boolean
  dpopRequired: boolean
}

export interface OrdinaryAuthorizationStart {
  intent: OrdinaryAuthorizationIntent
  credentialGeneration: CredentialGenerationSnapshot
  nonce: string
  state: Record<string, unknown>
  createDPoPKey: () => Promise<DPoPKeyManager | null>
}

export interface OrdinaryAuthorizationCallbackCustody {
  dpopKey: DPoPKeyManager | null
  compensationRequired: boolean
  markCodeIssued(): Promise<void>
  complete(): Promise<void>
  discard(): Promise<void>
  release(): Promise<void>
}

export interface OrdinaryAuthorizationCallbackRecovery {
  callback: AuthorizationCodeCallback
  custody: OrdinaryAuthorizationCallbackCustody
}

export interface OrdinaryAuthorizationDiscoveryContract {
  authorizationEndpoint: string
  pushedAuthorizationRequestEndpoint: string
  preNavigationCancellationEndpoint: string
  settlementEndpoint: string
  protocolVersion: number
  ceremonyLifetimeSeconds: number
  authorizationCodeLifetimeSeconds: number
}

export interface OrdinaryAuthorizationRecord {
  version: 2
  revision: number
  slotKey: string
  stateId: string
  issuer: string
  clientId: string
  redirectUri: string
  scope: string
  credentialGeneration: CredentialGenerationSnapshot
  intent: string
  stateStorage: string
  stateCreatedAt: number
  form: string
  createdAt: number
  provisionalExpiresAt: number
  attemptExpiresAtMs: number | null
  pushedAuthorizationRequestEndpoint: string
  preNavigationCancellationEndpoint: string
  settlementEndpoint: string
  authorizationEndpoint: string
  protocolVersion: number
  ceremonyLifetimeSeconds: number
  authorizationCodeLifetimeSeconds: number
  dpopJkt: string | null
  keys: CryptoKeyPair | null
  cancellationSecret: string
  parPhase: OrdinaryAuthorizationPARPhase
  requestUri: string | null
  terminalProof: string | null
  rootExpiresAt: string | null
  rootExpiresAtMs: number | null
  custodyExpiresAtMs: number | null
  callbackClaimId: string | null
  callbackClaimExpiresAtMs: number | null
  callbackCode: string | null
  callbackCodeHash: string | null
  compensationRequired: boolean
  rejectionRequired: boolean
  cleanupStarted: boolean
}

export type OrdinaryAuthorizationPARPhase =
  'prepared' | 'submitted' | 'admitted'

export interface OrdinaryAuthorizationPointer {
  version: 1
  stateId: string
  tabOwnerGeneration: string
}

export interface ParsedOrdinaryAuthorizationIntent {
  responseMode: 'web_message' | null
  prompt: string | null
  maxAge: number | null
  acrValues: string | null
  returnTo: string | null
  extraQueryParams: Record<string, string>
  dpopEnabled: boolean
  dpopRequired: boolean
}

export class OrdinaryAuthorizationPendingError extends Error {
  constructor() {
    super(
      'ordinary browser authorization outcome is uncertain; retry the same login',
    )
    this.name = 'OrdinaryAuthorizationPendingError'
  }
}

export function validCanonicalSHA256(value: string): boolean {
  if (!CANONICAL_SHA256.test(value)) return false
  try {
    const bytes = base64ToBytes(value)
    return bytes.length === 32 && bytesToBase64Url(bytes) === value
  } catch {
    return false
  }
}

export function validCanonicalAuthorizationCode(value: string): boolean {
  return CANONICAL_AUTHORIZATION_CODE.test(value)
}

export async function authorizationCodeSHA256(value: string): Promise<string> {
  if (!validCanonicalAuthorizationCode(value)) {
    throw new Error('ordinary browser authorization: callback code is invalid')
  }
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value),
  )
  return bytesToBase64Url(new Uint8Array(digest))
}

export function newOrdinaryAuthorizationCancellationSecret(): string {
  const secret = new Uint8Array(32)
  crypto.getRandomValues(secret)
  return bytesToBase64Url(secret)
}

function potentiallyTrustworthyURL(parsed: URL): boolean {
  if (parsed.protocol === 'https:') return true
  if (parsed.protocol !== 'http:') return false
  const host = parsed.hostname.toLowerCase()
  if (host === 'localhost' || host.endsWith('.localhost') || host === '[::1]') {
    return true
  }
  const octets = host.split('.').map(Number)
  return (
    octets.length === 4 &&
    octets.every(
      (octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255,
    ) &&
    octets[0] === 127
  )
}

function issuerRoot(raw: string): string {
  let parsed: URL
  try {
    parsed = new URL(raw)
  } catch {
    throw new Error('ordinary browser authorization: issuer is invalid')
  }
  if (
    !potentiallyTrustworthyURL(parsed) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.pathname !== '/' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error('ordinary browser authorization: issuer is invalid')
  }
  return parsed.origin
}

export function canonicalOrdinaryAuthorizationBinding(
  binding: OrdinaryAuthorizationBinding,
): OrdinaryAuthorizationBinding {
  const issuer = issuerRoot(binding.issuer)
  let redirect: URL
  try {
    redirect = new URL(binding.redirectUri)
  } catch {
    throw new Error('ordinary browser authorization: redirect URI is invalid')
  }
  if (
    !potentiallyTrustworthyURL(redirect) ||
    redirect.username !== '' ||
    redirect.password !== '' ||
    redirect.hash !== '' ||
    binding.clientId.length === 0 ||
    binding.clientId.length > 512 ||
    binding.scope.length === 0 ||
    binding.scope.length > 2048 ||
    !binding.scope.split(' ').includes('openid')
  ) {
    throw new Error('ordinary browser authorization: binding is invalid')
  }
  return {
    issuer,
    clientId: binding.clientId,
    redirectUri: redirect.href,
    scope: binding.scope,
  }
}

export function potentiallyTrustworthyEndpoint(
  value: unknown,
  expected: string,
  label: string,
): string {
  if (typeof value !== 'string' || value !== expected) {
    throw new Error(`ordinary browser authorization: ${label} is invalid`)
  }
  const parsed = new URL(value)
  if (
    !potentiallyTrustworthyURL(parsed) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error(`ordinary browser authorization: ${label} is invalid`)
  }
  return value
}

export function serializedOrdinaryAuthorizationIntent(
  intent: OrdinaryAuthorizationIntent,
): string {
  if (
    (intent.responseMode !== undefined &&
      intent.responseMode !== 'web_message') ||
    (intent.prompt !== undefined &&
      intent.prompt !== 'login' &&
      intent.prompt !== 'none') ||
    (intent.maxAge !== undefined &&
      (!Number.isSafeInteger(intent.maxAge) ||
        intent.maxAge < 0 ||
        intent.maxAge > 86_400)) ||
    (intent.acrValues !== undefined &&
      (intent.acrValues.length === 0 || intent.acrValues.length > 2048)) ||
    (intent.returnTo !== undefined && intent.returnTo.length > 2048) ||
    (intent.dpopRequired && !intent.dpopEnabled)
  ) {
    throw new Error('ordinary browser authorization: intent is invalid')
  }
  const extra = intent.extraQueryParams ?? {}
  const names = Object.keys(extra).sort()
  if (
    names.some(
      (name) =>
        !ORDINARY_AUTHORIZATION_EXTENSION_FIELDS.has(name) ||
        extra[name].length === 0 ||
        extra[name].length > 2048,
    )
  ) {
    throw new Error(
      'ordinary browser authorization: extra parameter is invalid',
    )
  }
  return JSON.stringify({
    response_mode: intent.responseMode ?? null,
    prompt: intent.prompt ?? null,
    max_age: intent.maxAge ?? null,
    acr_values: intent.acrValues ?? null,
    return_to: intent.returnTo ?? null,
    extra_query: names.map((name) => [name, extra[name]]),
    dpop_enabled: intent.dpopEnabled,
    dpop_required: intent.dpopRequired,
  })
}

export function parseOrdinaryAuthorizationIntent(
  value: string,
): ParsedOrdinaryAuthorizationIntent {
  const raw = parseUniqueJSONObject(value, 16 * 1024)
  if (
    !hasExactMembers(raw, [
      'response_mode',
      'prompt',
      'max_age',
      'acr_values',
      'return_to',
      'extra_query',
      'dpop_enabled',
      'dpop_required',
    ]) ||
    (raw.response_mode !== null &&
      raw.response_mode !== 'web_message') ||
    (raw.prompt !== null && raw.prompt !== 'login' && raw.prompt !== 'none') ||
    (raw.max_age !== null &&
      (!Number.isSafeInteger(raw.max_age) ||
        (raw.max_age as number) < 0 ||
        (raw.max_age as number) > 86_400)) ||
    (raw.acr_values !== null &&
      (typeof raw.acr_values !== 'string' ||
        raw.acr_values.length === 0 ||
        raw.acr_values.length > 2048)) ||
    (raw.return_to !== null &&
      (typeof raw.return_to !== 'string' || raw.return_to.length > 2048)) ||
    !Array.isArray(raw.extra_query) ||
    typeof raw.dpop_enabled !== 'boolean' ||
    typeof raw.dpop_required !== 'boolean' ||
    (raw.dpop_required && !raw.dpop_enabled)
  ) {
    throw new Error('ordinary browser authorization: stored intent is invalid')
  }
  const extraQueryParams: Record<string, string> = Object.create(null)
  let previous = ''
  for (const entry of raw.extra_query) {
    if (
      !Array.isArray(entry) ||
      entry.length !== 2 ||
      typeof entry[0] !== 'string' ||
      typeof entry[1] !== 'string' ||
      !ORDINARY_AUTHORIZATION_EXTENSION_FIELDS.has(entry[0]) ||
      entry[0] <= previous ||
      entry[1].length === 0 ||
      entry[1].length > 2048
    ) {
      throw new Error(
        'ordinary browser authorization: stored intent is invalid',
      )
    }
    previous = entry[0]
    extraQueryParams[entry[0]] = entry[1]
  }
  const parsed: ParsedOrdinaryAuthorizationIntent = {
    responseMode: raw.response_mode as 'web_message' | null,
    prompt: raw.prompt as string | null,
    maxAge: raw.max_age as number | null,
    acrValues: raw.acr_values as string | null,
    returnTo: raw.return_to as string | null,
    extraQueryParams,
    dpopEnabled: raw.dpop_enabled,
    dpopRequired: raw.dpop_required,
  }
  if (
    serializedOrdinaryAuthorizationIntent({
      responseMode: parsed.responseMode ?? undefined,
      prompt: parsed.prompt ?? undefined,
      maxAge: parsed.maxAge ?? undefined,
      acrValues: parsed.acrValues ?? undefined,
      returnTo: parsed.returnTo ?? undefined,
      extraQueryParams,
      dpopEnabled: parsed.dpopEnabled,
      dpopRequired: parsed.dpopRequired,
    }) !== value
  ) {
    throw new Error('ordinary browser authorization: stored intent is invalid')
  }
  return parsed
}

export function sameCredentialGeneration(
  left: CredentialGenerationSnapshot,
  right: CredentialGenerationSnapshot,
): boolean {
  return left.logout === right.logout && left.tabOwner === right.tabOwner
}

export function ordinaryAuthorizationPointerKey(
  binding: OrdinaryAuthorizationBinding,
): string {
  return `atol:browser-auth:v1:ordinary-authorization:${encodeURIComponent(
    JSON.stringify([binding.issuer, binding.clientId, binding.redirectUri]),
  )}`
}

export function ordinaryAuthorizationSlotKey(
  binding: OrdinaryAuthorizationBinding,
  tabOwnerGeneration: string,
): string {
  return JSON.stringify([
    binding.issuer,
    binding.clientId,
    binding.redirectUri,
    tabOwnerGeneration,
  ])
}

export function ordinaryAuthorizationRecordExpiresAt(
  record: OrdinaryAuthorizationRecord,
): number {
  return (
    record.custodyExpiresAtMs ??
    record.attemptExpiresAtMs ??
    record.provisionalExpiresAt
  )
}

export function ordinaryAuthorizationRecordExpired(
  record: OrdinaryAuthorizationRecord,
  now = Date.now(),
): boolean {
  return (
    !Number.isSafeInteger(now) ||
    now < record.createdAt ||
    now >= ordinaryAuthorizationRecordExpiresAt(record)
  )
}
