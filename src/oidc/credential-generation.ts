import { bytesToBase64Url } from '../crypto/base64url'

const STORAGE_VERSION = 1
const CANONICAL_GENERATION = /^[A-Za-z0-9_-]{43}$/
const AUTHORITY_STATUS_ACTIVE = 'active'
const AUTHORITY_STATUS_SIGNED_OUT = 'signed_out'

type CredentialAuthorityStatus =
  | typeof AUTHORITY_STATUS_ACTIVE
  | typeof AUTHORITY_STATUS_SIGNED_OUT

interface PersistedCredentialAuthority {
  version: typeof STORAGE_VERSION
  generation: string
  status: CredentialAuthorityStatus
}

export interface CredentialAuthority {
  generation: string
  signedOut: boolean
}

export interface CredentialGenerationBinding {
  issuer: string
  clientId: string
  redirectUri: string
}

export interface CredentialGenerationSnapshot {
  logout: string
  tabOwner: string
}

export class CredentialGenerationInvalidatedError extends Error {
  readonly code = 'credential_generation_invalidated'

  constructor() {
    super('credential generation: authorization was invalidated')
    this.name = 'CredentialGenerationInvalidatedError'
  }
}

export class CredentialGenerationSupersededError extends Error {
  readonly code = 'credential_generation_superseded'

  constructor() {
    super('credential generation: tab owner was superseded')
    this.name = 'CredentialGenerationSupersededError'
  }
}

function randomGeneration(): string {
  const value = new Uint8Array(32)
  crypto.getRandomValues(value)
  return bytesToBase64Url(value)
}

function parsedBinding(binding: CredentialGenerationBinding): {
  issuer: string
  clientId: string
  redirectUri: string
  applicationOrigin: string
} {
  let issuer: URL
  let redirect: URL
  try {
    issuer = new URL(binding.issuer)
    redirect = new URL(binding.redirectUri)
  } catch {
    throw new Error('credential generation: invalid authorization binding')
  }
  if (
    (issuer.protocol !== 'https:' && issuer.protocol !== 'http:') ||
    (redirect.protocol !== 'https:' && redirect.protocol !== 'http:') ||
    issuer.username !== '' ||
    issuer.password !== '' ||
    issuer.search !== '' ||
    issuer.hash !== '' ||
    redirect.username !== '' ||
    redirect.password !== '' ||
    binding.clientId.length === 0 ||
    binding.clientId.length > 512
  ) {
    throw new Error('credential generation: invalid authorization binding')
  }
  return {
    issuer: issuer.href,
    clientId: binding.clientId,
    redirectUri: redirect.href,
    applicationOrigin: redirect.origin,
  }
}

function browserStorage(
  binding: CredentialGenerationBinding,
  kind: 'local' | 'session',
): Storage {
  if (typeof window === 'undefined') {
    throw new Error('credential generation: browser storage is unavailable')
  }
  const parsed = parsedBinding(binding)
  if (window.location.origin !== parsed.applicationOrigin) {
    throw new Error(
      'credential generation: current origin does not match the authorization binding',
    )
  }
  return kind === 'local' ? window.localStorage : window.sessionStorage
}

export function logoutGenerationStorageKey(
  binding: CredentialGenerationBinding,
): string {
  const parsed = parsedBinding(binding)
  return `atol:browser-auth:v${STORAGE_VERSION}:logout:${encodeURIComponent(
    JSON.stringify([
      parsed.issuer,
      parsed.clientId,
      parsed.applicationOrigin,
    ]),
  )}`
}

function tabOwnerGenerationKey(binding: CredentialGenerationBinding): string {
  const parsed = parsedBinding(binding)
  return `atol:browser-auth:v${STORAGE_VERSION}:tab-owner:${encodeURIComponent(
    JSON.stringify([
      parsed.issuer,
      parsed.clientId,
      parsed.redirectUri,
    ]),
  )}`
}

function requireCanonicalGeneration(stored: string | null): string {
  if (stored === null || !CANONICAL_GENERATION.test(stored)) {
    throw new Error('credential generation: persisted generation is corrupt')
  }
  return stored
}

function serializedAuthority(
  generation: string,
  status: CredentialAuthorityStatus,
): string {
  return JSON.stringify({
    version: STORAGE_VERSION,
    generation,
    status,
  } satisfies PersistedCredentialAuthority)
}

function parseAuthority(stored: string | null): PersistedCredentialAuthority {
  if (stored === null) {
    throw new Error('credential generation: persisted generation is corrupt')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(stored)
  } catch {
    throw new Error('credential generation: persisted generation is corrupt')
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    Array.isArray(parsed)
  ) {
    throw new Error('credential generation: persisted generation is corrupt')
  }
  const record = parsed as Record<string, unknown>
  if (
    Object.keys(record).length !== 3 ||
    record.version !== STORAGE_VERSION ||
    !CANONICAL_GENERATION.test(
      typeof record.generation === 'string' ? record.generation : '',
    ) ||
    (record.status !== AUTHORITY_STATUS_ACTIVE &&
      record.status !== AUTHORITY_STATUS_SIGNED_OUT)
  ) {
    throw new Error('credential generation: persisted generation is corrupt')
  }
  const authority = record as unknown as PersistedCredentialAuthority
  if (
    stored !== serializedAuthority(authority.generation, authority.status)
  ) {
    throw new Error('credential generation: persisted generation is corrupt')
  }
  return authority
}

function authorityResult(
  authority: PersistedCredentialAuthority,
): CredentialAuthority {
  return {
    generation: authority.generation,
    signedOut: authority.status === AUTHORITY_STATUS_SIGNED_OUT,
  }
}

function writeAuthority(
  binding: CredentialGenerationBinding,
  status: CredentialAuthorityStatus,
): CredentialAuthority {
  const storage = browserStorage(binding, 'local')
  const key = logoutGenerationStorageKey(binding)
  storage.setItem(key, serializedAuthority(randomGeneration(), status))
  return authorityResult(parseAuthority(storage.getItem(key)))
}

/**
 * Return the origin-wide credential authority and its durable signed-out
 * state. Both fields occupy one canonical localStorage record, so logout
 * cannot publish a new generation without publishing its tombstone.
 */
export function currentCredentialAuthority(
  binding: CredentialGenerationBinding,
): CredentialAuthority {
  const storage = browserStorage(binding, 'local')
  const key = logoutGenerationStorageKey(binding)
  const stored = storage.getItem(key)
  if (stored !== null) return authorityResult(parseAuthority(stored))
  storage.setItem(
    key,
    serializedAuthority(randomGeneration(), AUTHORITY_STATUS_ACTIVE),
  )
  return authorityResult(parseAuthority(storage.getItem(key)))
}

/**
 * Return the non-secret origin-wide logout generation for this browser
 * client. A missing generation is initialized with fresh random authority,
 * then reread so a concurrent writer's persisted value wins.
 */
export function currentLogoutGeneration(
  binding: CredentialGenerationBinding,
): string {
  return currentCredentialAuthority(binding).generation
}

/**
 * Read persisted origin-wide authority without initializing or rotating it.
 * Storage-event and broadcast reconciliation use this to distinguish a
 * current change from a delayed stale signal.
 */
export function persistedLogoutGeneration(
  binding: CredentialGenerationBinding,
): string | null {
  const stored = browserStorage(binding, 'local').getItem(
    logoutGenerationStorageKey(binding),
  )
  return stored === null ? null : parseAuthority(stored).generation
}

/**
 * Read the durable authority without initializing it. Storage-event
 * reconciliation uses the complete record so a delayed event cannot replay
 * an earlier state for the same application.
 */
export function persistedCredentialAuthority(
  binding: CredentialGenerationBinding,
): CredentialAuthority | null {
  const stored = browserStorage(binding, 'local').getItem(
    logoutGenerationStorageKey(binding),
  )
  return stored === null ? null : authorityResult(parseAuthority(stored))
}

/**
 * Synchronously invalidate every authorization snapshot on this origin for
 * the issuer/client pair and publish the durable signed-out tombstone in the
 * same storage write. No existing value is parsed, so corrupt storage cannot
 * block logout or session-ended handling.
 */
export function rotateLogoutGeneration(
  binding: CredentialGenerationBinding,
): string {
  const storage = browserStorage(binding, 'local')
  const key = logoutGenerationStorageKey(binding)
  const generation = randomGeneration()
  storage.setItem(
    key,
    serializedAuthority(generation, AUTHORITY_STATUS_SIGNED_OUT),
  )
  const authority = parseAuthority(storage.getItem(key))
  if (
    authority.status !== AUTHORITY_STATUS_SIGNED_OUT ||
    authority.generation !== generation
  ) {
    throw new Error('credential generation: logout was superseded')
  }
  return generation
}

/**
 * Begin an explicit user-directed login. A durable signed-out tombstone is
 * cleared only by replacing it with fresh active authority; an already
 * active authority remains stable.
 */
export function credentialGenerationForLogin(
  binding: CredentialGenerationBinding,
): CredentialGenerationSnapshot {
  const current = currentCredentialAuthority(binding)
  const authority = current.signedOut
    ? writeAuthority(binding, AUTHORITY_STATUS_ACTIVE)
    : current
  if (authority.signedOut) {
    throw new CredentialGenerationInvalidatedError()
  }
  return {
    logout: authority.generation,
    tabOwner: currentTabOwnerGeneration(binding),
  }
}

export function assertLogoutGeneration(
  binding: CredentialGenerationBinding,
  expected: string,
): void {
  const authority = currentCredentialAuthority(binding)
  if (
    !CANONICAL_GENERATION.test(expected) ||
    authority.signedOut ||
    authority.generation !== expected
  ) {
    throw new CredentialGenerationInvalidatedError()
  }
}

/**
 * Return the same-tab owner generation that survives an authorization
 * redirect. It scopes durable transaction ownership and is separate from
 * the browser-wide logout generation.
 */
export function currentTabOwnerGeneration(
  binding: CredentialGenerationBinding,
): string {
  const storage = browserStorage(binding, 'session')
  const key = tabOwnerGenerationKey(binding)
  const stored = storage.getItem(key)
  if (stored !== null) return requireCanonicalGeneration(stored)
  const created = randomGeneration()
  storage.setItem(key, created)
  return created
}

/**
 * Replace the tab owner without parsing the old value. Replacement and
 * destroy paths use this to invalidate same-tab work even if storage was
 * corrupted.
 */
export function rotateTabOwnerGeneration(
  binding: CredentialGenerationBinding,
): string {
  const next = randomGeneration()
  browserStorage(binding, 'session').setItem(
    tabOwnerGenerationKey(binding),
    next,
  )
  return next
}

export function assertTabOwnerGeneration(
  binding: CredentialGenerationBinding,
  expected: string,
): void {
  if (
    !CANONICAL_GENERATION.test(expected) ||
    currentTabOwnerGeneration(binding) !== expected
  ) {
    throw new CredentialGenerationSupersededError()
  }
}

export function isCredentialGeneration(value: unknown): value is string {
  return typeof value === 'string' && CANONICAL_GENERATION.test(value)
}

export function credentialGenerationSnapshot(
  binding: CredentialGenerationBinding,
): CredentialGenerationSnapshot {
  return {
    logout: currentLogoutGeneration(binding),
    tabOwner: currentTabOwnerGeneration(binding),
  }
}

export function assertCredentialGenerationSnapshot(
  binding: CredentialGenerationBinding,
  snapshot: CredentialGenerationSnapshot,
): void {
  assertLogoutGeneration(binding, snapshot.logout)
  assertTabOwnerGeneration(binding, snapshot.tabOwner)
}
