import { getTokenExpiry } from '../claims/claims'
import { isCredentialGeneration } from '../oidc/credential-generation'
import type { DPoPConfig } from './browser-auth'

export const DEFAULT_SCOPES = 'openid profile email'
export const RENEW_WINDOW_MS = 60_000
export const CANONICAL_ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/

const SIGNOUT_STATE_VERSION = 1
const SIGNOUT_STATE_KEY = 'atol_browser_auth_logout'

export function dpopEnabled(cfg: DPoPConfig | undefined): boolean {
  if (typeof cfg === 'boolean') return cfg
  return cfg?.required === true
}

export function dpopRequired(cfg: DPoPConfig | undefined): boolean {
  return typeof cfg === 'object' && cfg.required === true
}

export class StaleCredentialTransactionError extends Error {
  constructor() {
    super('credential transaction was superseded')
    this.name = 'StaleCredentialTransactionError'
  }
}

export function warnIfSeedTokenNotFresh(accessToken: string): void {
  const exp = getTokenExpiry(accessToken)
  if ((exp === null || exp <= Date.now()) && typeof console !== 'undefined') {
    console.warn(
      '[Atol] test session: the access token has no future `exp` claim; the ' +
        'seeded session may immediately attempt renewal and drop. Seed a token ' +
        'whose exp is in the future.',
    )
  }
}

export function normalizePostLogoutRedirectURI(
  value: string,
  redirectUri: string,
): string {
  let callback: URL
  let logout: URL
  try {
    callback = new URL(redirectUri)
    logout = new URL(value)
  } catch {
    throw new Error('postLogoutRedirectUri must be a valid absolute URL')
  }
  if (
    logout.origin !== callback.origin ||
    logout.username !== '' ||
    logout.password !== '' ||
    logout.search !== '' ||
    logout.hash !== ''
  ) {
    throw new Error(
      'postLogoutRedirectUri must be a clean URL on the redirectUri origin',
    )
  }
  return logout.href
}

export function signoutState(
  logoutGeneration: string,
): Record<string, unknown> {
  return {
    [SIGNOUT_STATE_KEY]: {
      version: SIGNOUT_STATE_VERSION,
      logout_generation: logoutGeneration,
    },
  }
}

export function signoutStateGeneration(value: unknown): string {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== 1
  ) {
    throw new Error('OIDC post-logout callback has invalid state')
  }
  const envelope = (value as Record<string, unknown>)[SIGNOUT_STATE_KEY]
  if (
    typeof envelope !== 'object' ||
    envelope === null ||
    Array.isArray(envelope) ||
    Object.keys(envelope).length !== 2
  ) {
    throw new Error('OIDC post-logout callback has invalid state')
  }
  const record = envelope as Record<string, unknown>
  if (
    record.version !== SIGNOUT_STATE_VERSION ||
    !isCredentialGeneration(record.logout_generation)
  ) {
    throw new Error('OIDC post-logout callback has invalid state')
  }
  return record.logout_generation
}
