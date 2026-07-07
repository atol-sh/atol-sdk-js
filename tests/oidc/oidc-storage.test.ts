/**
 * Token storage policy: the oidc-client-ts user store MUST be in-memory.
 * Storing a User -- including a refresh token -- must write NOTHING to
 * sessionStorage/localStorage. sessionStorage is reserved for OIDC
 * state/PKCE only.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { User } from 'oidc-client-ts'
import { createUserManager, userFromTokenResponse } from '../../src/oidc/oidc'
import { decodeJWTPayload } from '../../src/claims/claims'
import { makeAccessToken, makeIDToken } from '../helpers'

beforeEach(() => {
  sessionStorage.clear()
  globalThis.localStorage?.clear()
})

describe('createUserManager storage policy', () => {
  it('stores the user (incl. refresh token) in memory only', async () => {
    const mgr = createUserManager(
      'https://auth.atol.test',
      'atol_kid_x',
      'https://app.test/cb',
      'openid profile',
    )

    const user = new User({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'rt_super_secret',
      token_type: 'Bearer',
      profile: { sub: 'user-1' } as never,
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    })

    await mgr.storeUser(user)

    const got = await mgr.getUser()
    expect(got?.access_token).toBe(user.access_token)
    expect(got?.refresh_token).toBe('rt_super_secret')

    // ...without touching Web Storage.
    expect(sessionStorage.length).toBe(0)
    expect(globalThis.localStorage?.length ?? 0).toBe(0)
  })

  it('does not leak the refresh token into any Web Storage value', async () => {
    const mgr = createUserManager(
      'https://auth.atol.test',
      'atol_kid_x',
      'https://app.test/cb',
      'openid profile',
    )
    await mgr.storeUser(
      new User({
        access_token: makeAccessToken(),
        refresh_token: 'rt_never_persisted',
        token_type: 'Bearer',
        profile: { sub: 'user-1' } as never,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    )
    const haystacks: string[] = []
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i)!
      haystacks.push(sessionStorage.getItem(k) ?? '')
    }
    expect(haystacks.join('|')).not.toContain('rt_never_persisted')
  })
})

describe('userFromTokenResponse', () => {
  it('builds a non-expired User carrying all token material', () => {
    const accessToken = makeAccessToken(1800)
    const idToken = makeIDToken()
    const u = userFromTokenResponse({
      access_token: accessToken,
      id_token: idToken,
      refresh_token: 'rt_rotated',
      token_type: 'bearer',
      expires_in: 1800,
    })

    expect(u.access_token).toBe(accessToken)
    expect(u.id_token).toBe(idToken)
    expect(u.refresh_token).toBe('rt_rotated')
    expect(u.expired).toBe(false)
    const exp = decodeJWTPayload(accessToken).exp as number
    expect(u.expires_at).toBe(exp)
    expect(u.profile.sub).toBe('user-1')
  })

  it('falls back to expires_in for opaque access tokens', () => {
    const before = Math.floor(Date.now() / 1000)
    const u = userFromTokenResponse({
      access_token: 'opaque-token',
      token_type: 'bearer',
      expires_in: 600,
    })
    expect(u.expires_at).toBeGreaterThanOrEqual(before + 600)
    expect(u.expires_at).toBeLessThanOrEqual(before + 602)
  })

  it('tolerates a malformed id_token (stores tokens, empty profile)', () => {
    const u = userFromTokenResponse({
      access_token: makeAccessToken(),
      id_token: 'not-a-jwt',
      token_type: 'bearer',
      expires_in: 600,
    })
    expect(u.access_token).toBeTruthy()
    // Malformed id_token -> profile parsing skipped; sub is absent.
    expect(u.profile.sub).toBeUndefined()
  })
})
