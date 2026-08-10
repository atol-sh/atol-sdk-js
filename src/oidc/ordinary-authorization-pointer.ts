import {
  OIDC_CLIENT_STATE,
  ORDINARY_AUTHORIZATION_POINTER_VERSION,
  validCanonicalSHA256,
  type OrdinaryAuthorizationPointer,
} from './ordinary-authorization-model'

export function ordinaryAuthorizationPointerStorage(): Storage {
  if (typeof window === 'undefined') {
    throw new Error(
      'ordinary browser authorization: session storage is unavailable',
    )
  }
  return window.sessionStorage
}

export function serializeOrdinaryAuthorizationPointer(
  pointer: OrdinaryAuthorizationPointer,
): string {
  return JSON.stringify({
    version: ORDINARY_AUTHORIZATION_POINTER_VERSION,
    stateId: pointer.stateId,
    tabOwnerGeneration: pointer.tabOwnerGeneration,
  })
}

export function parseOrdinaryAuthorizationPointer(
  raw: string | null,
): OrdinaryAuthorizationPointer | null {
  if (raw === null) return null
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    throw new Error(
      'ordinary browser authorization: pointer is corrupt',
    )
  }
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ) {
    throw new Error(
      'ordinary browser authorization: pointer is corrupt',
    )
  }
  const record = value as Record<string, unknown>
  if (
    Object.keys(record).sort().join(',') !==
      'stateId,tabOwnerGeneration,version' ||
    record.version !== ORDINARY_AUTHORIZATION_POINTER_VERSION ||
    typeof record.stateId !== 'string' ||
    !OIDC_CLIENT_STATE.test(record.stateId) ||
    typeof record.tabOwnerGeneration !== 'string' ||
    !validCanonicalSHA256(record.tabOwnerGeneration)
  ) {
    throw new Error(
      'ordinary browser authorization: pointer is corrupt',
    )
  }
  const pointer = record as unknown as OrdinaryAuthorizationPointer
  if (raw !== serializeOrdinaryAuthorizationPointer(pointer)) {
    throw new Error(
      'ordinary browser authorization: pointer is corrupt',
    )
  }
  return pointer
}
