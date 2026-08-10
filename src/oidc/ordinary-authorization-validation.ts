import { bytesToBase64Url } from '../crypto/base64url'
import { restoreDPoPKeyManager } from '../dpop/dpop'
import type { CredentialGenerationSnapshot } from './credential-generation'
import type { AuthorizationCodeResponseState } from './oidc'
import {
  AUTHORIZATION_CODE_LIFETIME_SECONDS,
  CANONICAL_NONCE,
  MAX_CEREMONY_LIFETIME_SECONDS,
  OIDC_CLIENT_STATE,
  ORDINARY_AUTHORIZATION_FORM_FIELDS,
  ORDINARY_AUTHORIZATION_PROTOCOL_VERSION,
  ORDINARY_AUTHORIZATION_RECORD_VERSION,
  REQUEST_URI_PREFIX,
  authorizationCodeSHA256,
  ordinaryAuthorizationSlotKey,
  parseOrdinaryAuthorizationIntent,
  sameCredentialGeneration,
  validCanonicalAttemptCapability,
  validCanonicalAuthorizationCode,
  validCanonicalSHA256,
  canonicalOrdinaryAuthorizationBinding,
  type OrdinaryAuthorizationBinding,
  type OrdinaryAuthorizationRecord,
} from './ordinary-authorization-model'
import {
  ordinaryAuthorizationAttemptCapabilityDeadline,
  validOrdinaryAuthorizationTerminalProof,
} from './ordinary-authorization-protocol'
import {
  rfc3339NanoMilliseconds,
  rfc3339NanoNanoseconds,
} from './rfc3339-nano'
import { hasExactMembers, parseUniqueJSONObject } from './strict-json'

export function canonicalOrdinaryAuthorizationForm(
  authorizationURL: string,
  binding: OrdinaryAuthorizationBinding,
  created: {
    stateId: string
    nonce: string
    codeChallenge: string
  },
): string {
  const parsed = new URL(authorizationURL)
  if (
    `${parsed.origin}${parsed.pathname}` !==
      `${binding.issuer}/auth/authorize` ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error(
      'ordinary browser authorization: generated endpoint is invalid',
    )
  }
  const seen = new Set<string>()
  const values = new Map<string, string>()
  for (const [name, value] of parsed.searchParams) {
    if (
      !ORDINARY_AUTHORIZATION_FORM_FIELDS.has(name) ||
      seen.has(name) ||
      value.length > 2048
    ) {
      throw new Error(
        'ordinary browser authorization: generated form is invalid',
      )
    }
    seen.add(name)
    values.set(name, value)
  }
  if (
    values.get('response_type') !== 'code' ||
    values.get('client_id') !== binding.clientId ||
    values.get('redirect_uri') !== binding.redirectUri ||
    values.get('scope') !== binding.scope ||
    !binding.scope.split(' ').includes('openid') ||
    values.get('state') !== created.stateId ||
    !OIDC_CLIENT_STATE.test(created.stateId) ||
    values.get('nonce') !== created.nonce ||
    !CANONICAL_NONCE.test(created.nonce) ||
    values.get('code_challenge') !== created.codeChallenge ||
    !validCanonicalSHA256(created.codeChallenge) ||
    values.get('code_challenge_method') !== 'S256' ||
    (values.has('atol_attempt_capability') &&
      !validCanonicalAttemptCapability(
        values.get('atol_attempt_capability'),
      )) ||
    (values.has('dpop_jkt') &&
      !validCanonicalSHA256(values.get('dpop_jkt') as string))
  ) {
    throw new Error(
      'ordinary browser authorization: generated form binding is invalid',
    )
  }
  const canonical = new URLSearchParams()
  for (const name of Array.from(values.keys()).sort()) {
    canonical.set(name, values.get(name) as string)
  }
  return canonical.toString()
}

export function assertOrdinaryAuthorizationRecord(
  record: OrdinaryAuthorizationRecord,
  binding: OrdinaryAuthorizationBinding,
  generation: CredentialGenerationSnapshot,
  intent: string,
): void {
  const expectedSlot = ordinaryAuthorizationSlotKey(
    binding,
    generation.tabOwner,
  )
  if (
    record.version !== ORDINARY_AUTHORIZATION_RECORD_VERSION ||
    !Number.isSafeInteger(record.revision) ||
    record.revision <= 0 ||
    record.slotKey !== expectedSlot ||
    !OIDC_CLIENT_STATE.test(record.stateId) ||
    record.issuer !== binding.issuer ||
    record.clientId !== binding.clientId ||
    record.redirectUri !== binding.redirectUri ||
    record.scope !== binding.scope ||
    !sameCredentialGeneration(record.credentialGeneration, generation) ||
    record.intent !== intent ||
    typeof record.stateStorage !== 'string' ||
    record.stateStorage.length === 0 ||
    record.stateStorage.length > 32 * 1024 ||
    !Number.isSafeInteger(record.stateCreatedAt) ||
    record.stateCreatedAt < 0 ||
    typeof record.form !== 'string' ||
    record.form.length === 0 ||
    record.form.length > 16 * 1024 ||
    !Number.isSafeInteger(record.createdAt) ||
    record.createdAt < 0 ||
    !Number.isSafeInteger(record.provisionalExpiresAt) ||
    record.provisionalExpiresAt !==
      record.createdAt +
        (record.ceremonyLifetimeSeconds +
          record.authorizationCodeLifetimeSeconds) *
          1000 ||
    (record.attemptExpiresAtMs !== null &&
      (!Number.isSafeInteger(record.attemptExpiresAtMs) ||
        record.attemptExpiresAtMs <= record.createdAt ||
        record.attemptExpiresAtMs > record.provisionalExpiresAt)) ||
    record.protocolVersion !== ORDINARY_AUTHORIZATION_PROTOCOL_VERSION ||
    !Number.isSafeInteger(record.ceremonyLifetimeSeconds) ||
    record.ceremonyLifetimeSeconds <= 0 ||
    record.ceremonyLifetimeSeconds > MAX_CEREMONY_LIFETIME_SECONDS ||
    record.authorizationCodeLifetimeSeconds !==
      AUTHORIZATION_CODE_LIFETIME_SECONDS ||
    record.pushedAuthorizationRequestEndpoint !==
      `${binding.issuer}/auth/par` ||
    record.preNavigationCancellationEndpoint !==
      `${binding.issuer}/auth/par/pre-navigation-cancellation` ||
    record.settlementEndpoint !== `${binding.issuer}/auth/par/settlement` ||
    record.authorizationEndpoint !== `${binding.issuer}/auth/authorize` ||
    (record.dpopJkt === null) !== (record.keys === null) ||
    (record.dpopJkt !== null && !validCanonicalSHA256(record.dpopJkt)) ||
    !validCanonicalSHA256(record.cancellationSecret) ||
    (record.parPhase !== 'prepared' &&
      record.parPhase !== 'submitted' &&
      record.parPhase !== 'admitted') ||
    (record.parPhase === 'prepared' &&
      record.attemptExpiresAtMs !== null) ||
    (record.parPhase === 'admitted' &&
      record.attemptExpiresAtMs === null) ||
    (record.parPhase === 'admitted') !== (record.requestUri !== null) ||
    (record.parPhase === 'admitted') !== (record.terminalProof !== null) ||
    (record.parPhase === 'admitted') !== (record.rootExpiresAt !== null) ||
    (record.parPhase === 'admitted') !== (record.rootExpiresAtMs !== null) ||
    (record.parPhase === 'admitted') !== (record.custodyExpiresAtMs !== null) ||
    (record.callbackClaimId === null) !==
      (record.callbackClaimExpiresAtMs === null) ||
    (record.callbackCode === null) !== (record.callbackCodeHash === null) ||
    (record.callbackCode !== null &&
      !validCanonicalAuthorizationCode(record.callbackCode)) ||
    (record.callbackCodeHash !== null &&
      !validCanonicalSHA256(record.callbackCodeHash)) ||
    typeof record.compensationRequired !== 'boolean' ||
    (record.compensationRequired && record.callbackCode === null) ||
    typeof record.rejectionRequired !== 'boolean' ||
    (record.rejectionRequired && record.parPhase !== 'admitted') ||
    (record.rejectionRequired && record.callbackClaimId !== null) ||
    typeof record.cleanupStarted !== 'boolean' ||
    (record.cleanupStarted && record.callbackClaimId !== null) ||
    (record.callbackClaimId !== null &&
      (!validCanonicalSHA256(record.callbackClaimId) ||
        !Number.isSafeInteger(record.callbackClaimExpiresAtMs) ||
        (record.callbackClaimExpiresAtMs as number) <= 0))
  ) {
    throw new Error('ordinary browser authorization: custody binding mismatch')
  }
  const parameters = new URLSearchParams(record.form)
  const intentRecord = parseOrdinaryAuthorizationIntent(record.intent)
  if (
    canonicalOrdinaryAuthorizationForm(
      `${record.authorizationEndpoint}?${record.form}`,
      binding,
      {
        stateId: record.stateId,
        nonce: parameters.get('nonce') ?? '',
        codeChallenge: parameters.get('code_challenge') ?? '',
      },
    ) !== record.form ||
    parameters.get('dpop_jkt') !== record.dpopJkt ||
    parameters.has('atol_attempt_capability') !==
      (record.attemptExpiresAtMs !== null) ||
    parameters.get('response_mode') !== intentRecord.responseMode ||
    parameters.get('prompt') !== intentRecord.prompt ||
    parameters.get('max_age') !==
      (intentRecord.maxAge === null ? null : String(intentRecord.maxAge)) ||
    parameters.get('acr_values') !== intentRecord.acrValues ||
    Object.entries(intentRecord.extraQueryParams).some(
      ([name, value]) => parameters.get(name) !== value,
    ) ||
    (intentRecord.dpopRequired && record.dpopJkt === null) ||
    (!intentRecord.dpopEnabled && record.dpopJkt !== null)
  ) {
    throw new Error('ordinary browser authorization: custody form mismatch')
  }
  if (record.requestUri !== null) {
    const parsedDeadline = rfc3339NanoMilliseconds(
      record.rootExpiresAt as string,
    )
    if (
      !record.requestUri.startsWith(REQUEST_URI_PREFIX) ||
      !validCanonicalSHA256(
        record.requestUri.slice(REQUEST_URI_PREFIX.length),
      ) ||
      !validOrdinaryAuthorizationTerminalProof(
        record.terminalProof,
        record.rootExpiresAt as string,
      ) ||
      ordinaryAuthorizationAttemptCapabilityDeadline(
        parameters.get('atol_attempt_capability'),
      ) !==
        rfc3339NanoNanoseconds(
          record.rootExpiresAt as string,
        ) ||
      parsedDeadline !== record.rootExpiresAtMs ||
      Math.min(
        (record.attemptExpiresAtMs as number) +
          record.authorizationCodeLifetimeSeconds * 1000,
        record.provisionalExpiresAt,
      ) !== record.custodyExpiresAtMs
    ) {
      throw new Error(
        'ordinary browser authorization: custody deadline mismatch',
      )
    }
  }
}

export async function assertOrdinaryAuthorizationRecordState(
  record: OrdinaryAuthorizationRecord,
): Promise<void> {
  const state = parseUniqueJSONObject(record.stateStorage, 32 * 1024)
  if (
    !hasExactMembers(
      state,
      [
        'id',
        'data',
        'created',
        'request_type',
        'code_verifier',
        'authority',
        'client_id',
        'redirect_uri',
        'scope',
        'extraTokenParams',
        'nonce',
      ],
      ['response_mode'],
    ) ||
    state.id !== record.stateId ||
    state.created !== record.stateCreatedAt ||
    state.request_type !== 'si:r' ||
    typeof state.code_verifier !== 'string' ||
    !/^[0-9a-f]{96}$/.test(state.code_verifier) ||
    state.authority !== record.issuer ||
    state.client_id !== record.clientId ||
    state.redirect_uri !== record.redirectUri ||
    state.scope !== record.scope ||
    state.extraTokenParams === null ||
    typeof state.extraTokenParams !== 'object' ||
    Array.isArray(state.extraTokenParams) ||
    Object.keys(state.extraTokenParams as Record<string, unknown>).length !==
      0 ||
    typeof state.nonce !== 'string'
  ) {
    throw new Error(
      'ordinary browser authorization: stored OIDC state is invalid',
    )
  }
  const parameters = new URLSearchParams(record.form)
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(state.code_verifier),
  )
  if (
    parameters.get('state') !== state.id ||
    parameters.get('nonce') !== state.nonce ||
    parameters.get('code_challenge') !==
      bytesToBase64Url(new Uint8Array(digest))
  ) {
    throw new Error(
      'ordinary browser authorization: stored PKCE state mismatch',
    )
  }
  const data = state.data
  if (
    data === null ||
    typeof data !== 'object' ||
    Array.isArray(data) ||
    !hasExactMembers(data as Record<string, unknown>, ['atol_browser_auth'])
  ) {
    throw new Error(
      'ordinary browser authorization: stored application state is invalid',
    )
  }
  const atol = (data as Record<string, unknown>).atol_browser_auth
  if (
    atol === null ||
    typeof atol !== 'object' ||
    Array.isArray(atol) ||
    !hasExactMembers(
      atol as Record<string, unknown>,
      ['version', 'logout_generation', 'tab_owner_generation'],
      ['return_to'],
    )
  ) {
    throw new Error(
      'ordinary browser authorization: stored application state is invalid',
    )
  }
  const application = atol as Record<string, unknown>
  const intentRecord = parseOrdinaryAuthorizationIntent(record.intent)
  if (
    application.version !== 1 ||
    application.logout_generation !== record.credentialGeneration.logout ||
    application.tab_owner_generation !== record.credentialGeneration.tabOwner ||
    (state.response_mode ?? null) !== intentRecord.responseMode ||
    (application.return_to ?? null) !== intentRecord.returnTo
  ) {
    throw new Error(
      'ordinary browser authorization: stored application state mismatch',
    )
  }
}

export function assertOrdinaryAuthorizationCallbackMatches(
  record: OrdinaryAuthorizationRecord,
  callback: AuthorizationCodeResponseState,
  generation: CredentialGenerationSnapshot,
): void {
  const form = new URLSearchParams(record.form)
  const intentRecord = parseOrdinaryAuthorizationIntent(record.intent)
  if (
    record.requestUri === null ||
    record.custodyExpiresAtMs === null ||
    record.stateId !== callback.stateId ||
    record.stateStorage !== callback.stateStorage ||
    form.get('state') !== callback.stateId ||
    form.get('nonce') !== callback.nonce ||
    form.get('code_challenge') !== callback.codeChallenge ||
    form.get('redirect_uri') !== callback.redirectUri ||
    callback.credentialGeneration === undefined ||
    !sameCredentialGeneration(callback.credentialGeneration, generation) ||
    intentRecord.returnTo !== (callback.returnTo ?? null)
  ) {
    throw new Error('ordinary browser authorization: callback custody mismatch')
  }
}

const ORDINARY_AUTHORIZATION_RECORD_MEMBERS = [
  'version',
  'revision',
  'slotKey',
  'stateId',
  'issuer',
  'clientId',
  'redirectUri',
  'scope',
  'credentialGeneration',
  'intent',
  'stateStorage',
  'stateCreatedAt',
  'form',
  'createdAt',
  'provisionalExpiresAt',
  'attemptExpiresAtMs',
  'pushedAuthorizationRequestEndpoint',
  'preNavigationCancellationEndpoint',
  'settlementEndpoint',
  'authorizationEndpoint',
  'protocolVersion',
  'ceremonyLifetimeSeconds',
  'authorizationCodeLifetimeSeconds',
  'dpopJkt',
  'keys',
  'cancellationSecret',
  'parPhase',
  'requestUri',
  'terminalProof',
  'rootExpiresAt',
  'rootExpiresAtMs',
  'custodyExpiresAtMs',
  'callbackClaimId',
  'callbackClaimExpiresAtMs',
  'callbackCode',
  'callbackCodeHash',
  'compensationRequired',
  'rejectionRequired',
  'cleanupStarted',
] as const

/**
 * Positive full-v2 envelope classifier used by terminal reconciliation.
 * It verifies every binding except DPoP key usability so a corrupt key can
 * still authorize only exact server-side rejection.
 */
export async function classifyOrdinaryAuthorizationRecordEnvelope(
  value: unknown,
): Promise<OrdinaryAuthorizationRecord> {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    !hasExactMembers(value as Record<string, unknown>, [
      ...ORDINARY_AUTHORIZATION_RECORD_MEMBERS,
    ])
  ) {
    throw new Error(
      'ordinary browser authorization: unrecognized custody record',
    )
  }
  const record = value as OrdinaryAuthorizationRecord
  const generation = record.credentialGeneration
  if (
    generation === null ||
    typeof generation !== 'object' ||
    Array.isArray(generation) ||
    !hasExactMembers(generation as unknown as Record<string, unknown>, [
      'logout',
      'tabOwner',
    ]) ||
    !validCanonicalSHA256(generation.logout) ||
    !validCanonicalSHA256(generation.tabOwner)
  ) {
    throw new Error(
      'ordinary browser authorization: unrecognized custody record',
    )
  }
  if (
    typeof record.issuer !== 'string' ||
    typeof record.clientId !== 'string' ||
    typeof record.redirectUri !== 'string' ||
    typeof record.scope !== 'string' ||
    typeof record.intent !== 'string'
  ) {
    throw new Error(
      'ordinary browser authorization: unrecognized custody record',
    )
  }
  const binding = canonicalOrdinaryAuthorizationBinding({
    issuer: record.issuer,
    clientId: record.clientId,
    redirectUri: record.redirectUri,
    scope: record.scope,
  })
  assertOrdinaryAuthorizationRecord(record, binding, generation, record.intent)
  await assertOrdinaryAuthorizationRecordState(record)
  if (
    record.callbackCode !== null &&
    (await authorizationCodeSHA256(record.callbackCode)) !==
      record.callbackCodeHash
  ) {
    throw new Error(
      'ordinary browser authorization: unrecognized custody record',
    )
  }
  if (record.keys !== null) {
    if (
      typeof record.keys !== 'object' ||
      !hasExactMembers(record.keys as unknown as Record<string, unknown>, [
        'privateKey',
        'publicKey',
      ]) ||
      record.keys.privateKey === record.keys.publicKey
    ) {
      throw new Error(
        'ordinary browser authorization: unrecognized custody record',
      )
    }
  }
  return record
}

/**
 * Full classifier used before a record may supply credential authority.
 */
export async function classifyOrdinaryAuthorizationRecord(
  value: unknown,
): Promise<OrdinaryAuthorizationRecord> {
  const record = await classifyOrdinaryAuthorizationRecordEnvelope(value)
  if (record.keys !== null) {
    const manager = restoreDPoPKeyManager(record.keys)
    if ((await manager.thumbprint()) !== record.dpopJkt) {
      throw new Error(
        'ordinary browser authorization: unrecognized custody record',
      )
    }
  }
  return record
}
