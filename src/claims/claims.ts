import type { AtolUser } from './types'

/**
 * Parse Atol custom claims from a JWT token (ID token or access token).
 * Decodes the payload without verifying the signature — verification is
 * done by the OIDC library. This just extracts the user-facing fields.
 */
export function parseAtolUser(token: string): AtolUser {
  const payload = decodeJWTPayload(token)

  const str = (key: string): string => {
    const v = payload[key]
    return typeof v === 'string' ? v : ''
  }

  return {
    id: str('sub'),
    email: str('email'),
    emailVerified: payload['email_verified'] === true,
    name: str('name'),
    orgId: str('atol:org_id'),
    plan: str('atol:plan'),
    roles: Array.isArray(payload['atol:roles']) ? payload['atol:roles'] as string[] : [],
    authMethod: str('atol:auth_method'),
    mfaVerified: payload['atol:mfa_verified'] === true,
  }
}

/** Decode a JWT payload (the middle base64url segment) to a plain object. */
export function decodeJWTPayload(token: string): Record<string, unknown> {
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new Error('Invalid JWT: expected 3 parts')
  }

  const base64 = parts[1]
    .replace(/-/g, '+')
    .replace(/_/g, '/')

  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  const json = atob(padded)
  return JSON.parse(json)
}

/**
 * Parse the `exp` claim from a JWT without verifying the signature.
 * Returns the absolute expiry in milliseconds, or null when the token is
 * malformed or carries no numeric `exp`. Single source of truth for all
 * expiry math in the SDK (renew scheduling, stale checks, broadcasts).
 */
export function getTokenExpiry(token: string): number | null {
  try {
    const payload = decodeJWTPayload(token)
    return typeof payload.exp === 'number' ? payload.exp * 1000 : null
  } catch {
    return null
  }
}
