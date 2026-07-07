/**
 * Direct unit tests for the token accessors on the oidc wrapper. These are
 * trivial but load-bearing (the browser auth client and React provider read
 * tokens exclusively through them), so they get explicit coverage.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { User } from 'oidc-client-ts'
import { createUserManager, getAccessToken, getIdToken } from '../../src/oidc/oidc'
import { makeAccessToken, makeIDToken } from '../helpers'

function user(over: Partial<ConstructorParameters<typeof User>[0]> = {}): User {
  return new User({
    access_token: makeAccessToken(),
    id_token: makeIDToken(),
    token_type: 'bearer',
    profile: { sub: 'user-1' } as never,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    ...over,
  })
}

describe('getAccessToken', () => {
  it('returns the access token from a User', () => {
    const u = user()
    expect(getAccessToken(u)).toBe(u.access_token)
  })
  it('returns undefined for a null user', () => {
    expect(getAccessToken(null)).toBeUndefined()
  })
})

describe('getIdToken', () => {
  it('returns the id token from a User', () => {
    const u = user()
    expect(getIdToken(u)).toBe(u.id_token)
  })
  it('returns undefined for a null user', () => {
    expect(getIdToken(null)).toBeUndefined()
  })
  it('returns undefined when the User carries no id token', () => {
    expect(getIdToken(user({ id_token: undefined }))).toBeUndefined()
  })
})

describe('createUserManager', () => {
  it('builds a UserManager configured for the given issuer/client/redirect', () => {
    const mgr = createUserManager(
      'https://auth.atol.test',
      'atol_kid_x',
      'https://app.test/cb',
      'openid profile email',
      'https://api.example.com',
    )
    expect(mgr.settings.authority).toBe('https://auth.atol.test')
    expect(mgr.settings.client_id).toBe('atol_kid_x')
    expect(mgr.settings.redirect_uri).toBe('https://app.test/cb')
    expect(mgr.settings.response_type).toBe('code')
    expect(mgr.settings.extraQueryParams).toEqual({ audience: 'https://api.example.com' })
  })

  it('adds no audience to extraQueryParams when none is supplied', () => {
    const mgr = createUserManager(
      'https://auth.atol.test',
      'atol_kid_x',
      'https://app.test/cb',
      'openid',
    )
    // oidc-client-ts normalizes undefined to {}; the point is no audience key.
    expect(mgr.settings.extraQueryParams ?? {}).not.toHaveProperty('audience')
  })

  describe('SSR (no window)', () => {
    let savedWindow: typeof window
    afterEach(() => {
      Object.defineProperty(globalThis, 'window', {
        configurable: true,
        value: savedWindow,
      })
    })

    it('falls back to in-memory state storage when window is undefined', () => {
      savedWindow = globalThis.window
      Object.defineProperty(globalThis, 'window', {
        configurable: true,
        value: undefined,
      })
      // Must not throw despite window (and thus sessionStorage) being absent.
      const mgr = createUserManager(
        'https://auth.atol.test',
        'atol_kid_x',
        'https://app.test/cb',
        'openid',
      )
      expect(mgr).toBeDefined()
      expect(mgr.settings.authority).toBe('https://auth.atol.test')
    })
  })
})
