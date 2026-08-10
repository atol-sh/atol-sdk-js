/**
 * Token storage policy: the oidc-client-ts user store MUST be in-memory.
 * Storing a User -- including a refresh token -- must write NOTHING to
 * sessionStorage/localStorage. sessionStorage is reserved for OIDC
 * state/PKCE only.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SigninState, User } from 'oidc-client-ts'
import {
  authorizationState,
  createUserManager,
  ensureAuthorizationRequestState,
  readAuthorizationCodeCallback,
  removeAuthorizationRequestState,
  userFromTokenResponse,
} from '../../src/oidc/oidc'
import { decodeJWTPayload } from '../../src/claims/claims'
import { makeAccessToken, makeIDToken } from '../helpers'

beforeEach(() => {
  sessionStorage.clear()
  globalThis.localStorage?.clear()
})

describe('createUserManager storage policy', () => {
  it('does not extend oidc-client state beyond its default stale-state policy', () => {
    const mgr = createUserManager(
      'https://auth.atol.test',
      'atol_kid_x',
      'https://app.test/cb',
      'openid profile',
    )

    expect(mgr.settings.staleStateAgeInSeconds).toBe(900)
  })

  it('builds exact transaction-bound custom state', () => {
    expect(authorizationState('/settings/security')).toEqual({
      atol_browser_auth: {
        version: 1,
        return_to: '/settings/security',
      },
    })
    expect(authorizationState()).toEqual({})
  })

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

  it('restores missing authorization state and fences substituted state', async () => {
    const mgr = createUserManager(
      'https://auth.atol.test',
      'atol_kid_x',
      'https://app.test/cb',
      'openid',
    )

    await ensureAuthorizationRequestState(mgr, 'request-state', 'exact-state')
    expect(await mgr.settings.stateStore.get('request-state')).toBe('exact-state')
    await expect(
      ensureAuthorizationRequestState(mgr, 'request-state', 'substituted-state'),
    ).rejects.toThrow(/storage mismatch/)
    await expect(
      removeAuthorizationRequestState(mgr, 'request-state', 'substituted-state'),
    ).rejects.toThrow(/storage mismatch/)
    await expect(
      removeAuthorizationRequestState(mgr, 'request-state', 'exact-state'),
    ).resolves.toBeUndefined()
    expect(await mgr.settings.stateStore.get('request-state')).toBeNull()
  })

  it('reads callback PKCE state without settling its public state store', async () => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid profile')
    const state = await SigninState.create({
      id: 'callback-state',
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid profile',
      nonce: 'oidc-nonce',
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())

    const callback = await readAuthorizationCodeCallback(
      mgr,
      `${redirectUri}?code=authorization-code&state=${state.id}`,
    )

    expect(callback).toEqual({
      code: 'authorization-code',
      codeVerifier: 'pkce-verifier',
      redirectUri,
      nonce: 'oidc-nonce',
    })
    expect(await mgr.settings.stateStore.get(state.id)).toBe(
      state.toStorageString(),
    )
  })

  it('does not invent a local callback deadline outside durable custody', async () => {
    const now = 1_800_000_000_000
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(now)
    try {
      const authority = 'https://auth.atol.test'
      const clientId = 'atol_kid_x'
      const redirectUri = 'https://app.test/cb'
      const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
      const state = await SigninState.create({
        id: 'expired-callback-state',
        created: Math.floor(now / 1000) - 1_500,
        request_type: 'si:r',
        code_verifier: 'pkce-verifier',
        authority,
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: 'openid',
        nonce: 'oidc-nonce',
      })
      await mgr.settings.stateStore.set(state.id, state.toStorageString())

      await expect(
        readAuthorizationCodeCallback(
          mgr,
          `${redirectUri}?code=authorization-code&state=${state.id}`,
        ),
      ).resolves.toMatchObject({ code: 'authorization-code' })
      expect(await mgr.settings.stateStore.get(state.id)).toBe(
        state.toStorageString(),
      )
    } finally {
      nowSpy.mockRestore()
    }
  })

  it('returns transaction-bound application state without a DPoP reference', async () => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
    const state = await SigninState.create({
      id: 'return-to-state',
      data: {
        atol_browser_auth: {
          version: 1,
          return_to: '/settings/security',
        },
      },
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
      nonce: 'oidc-nonce',
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())

    await expect(
      readAuthorizationCodeCallback(
        mgr,
        `${redirectUri}?code=authorization-code&state=${state.id}`,
      ),
    ).resolves.toMatchObject({ returnTo: '/settings/security' })
  })

  it('parses the reserved namespace while preserving unrelated consumer state compatibility', async () => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
    const data = {
      consumer: { selectedTab: 'security' },
      ...authorizationState('/settings/security', {
        logout: 'A'.repeat(43),
        tabOwner: 'B'.repeat(43),
      }),
    }
    const state = await SigninState.create({
      id: 'coexisting-consumer-state',
      data,
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
      nonce: 'oidc-nonce',
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())

    await expect(
      readAuthorizationCodeCallback(
        mgr,
        `${redirectUri}?code=authorization-code&state=${state.id}`,
      ),
    ).resolves.toMatchObject({
      returnTo: '/settings/security',
      credentialGeneration: {
        logout: 'A'.repeat(43),
        tabOwner: 'B'.repeat(43),
      },
    })
  })

  it.each([
    ['non-string', 42],
    ['cross-origin URL', 'https://evil.test/steal'],
    ['network-path reference', '//evil.test/steal'],
    ['non-canonical path', '/settings/../admin'],
  ])('rejects %s returnTo custom state', async (_name, returnTo) => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
    const state = await SigninState.create({
      id: `invalid-return-to-${_name.replace(/ /g, '-')}`,
      data: {
        atol_browser_auth: {
          version: 1,
          return_to: returnTo,
        },
      },
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
      nonce: 'oidc-nonce',
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())

    await expect(
      readAuthorizationCodeCallback(
        mgr,
        `${redirectUri}?code=authorization-code&state=${state.id}`,
      ),
    ).rejects.toThrow(/returnTo|same-origin/)
  })

  it.each([
    ['primitive consumer state', 42],
    ['array consumer state', []],
    ['object consumer state', { arbitrary: { nested: true } }],
  ])('ignores unrelated %s', async (_name, data) => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
    const state = await SigninState.create({
      id: `consumer-state-${_name.replace(/ /g, '-')}`,
      data,
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
      nonce: 'oidc-nonce',
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())

    await expect(
      readAuthorizationCodeCallback(
        mgr,
        `${redirectUri}?code=authorization-code&state=${state.id}`,
      ),
    ).resolves.toMatchObject({ code: 'authorization-code' })
  })

  it.each([
    ['primitive reserved state', { atol_browser_auth: 42 }],
    ['wrong namespace version', {
      atol_browser_auth: {
        version: 2,
      },
    }],
    ['extra namespace field', {
      arbitrary: 'preserved',
      atol_browser_auth: {
        version: 1,
        extra: true,
      },
    }],
    ['incomplete credential generation', {
      atol_browser_auth: {
        version: 1,
        logout_generation: 'A'.repeat(43),
      },
    }],
    ['invalid credential generation', {
      atol_browser_auth: {
        version: 1,
        logout_generation: 'invalid',
        tab_owner_generation: 'B'.repeat(43),
      },
    }],
  ])('rejects reserved custom state with %s', async (_name, data) => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
    const state = await SigninState.create({
      id: `invalid-dpop-${_name.replace(/ /g, '-')}`,
      data,
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
      nonce: 'oidc-nonce',
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())

    await expect(
      readAuthorizationCodeCallback(
        mgr,
        `${redirectUri}?code=authorization-code&state=${state.id}`,
      ),
    ).rejects.toThrow(/custom state|credential generation/)
  })

  it('rejects callback state with an empty redirect URI before exchange', async () => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const mgr = createUserManager(authority, clientId, 'https://app.test/cb', 'openid')
    const state = await SigninState.create({
      id: 'empty-redirect-state',
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: '',
      scope: 'openid',
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())

    await expect(
      readAuthorizationCodeCallback(
        mgr,
        `https://app.test/cb?code=authorization-code&state=${state.id}`,
      ),
    ).rejects.toThrow(/missing the redirect URI/)
  })

  it('[R46] rejects callback state without an OIDC nonce', async () => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
    const state = await SigninState.create({
      id: 'missing-nonce-state',
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())

    await expect(
      readAuthorizationCodeCallback(
        mgr,
        `${redirectUri}?code=authorization-code&state=${state.id}`,
      ),
    ).rejects.toThrow(/missing the nonce/)
  })

  it('rejects callbacks for a UserManager not created by the SDK', async () => {
    await expect(
      readAuthorizationCodeCallback(
        {} as never,
        'https://app.test/cb?code=authorization-code&state=unknown',
      ),
    ).rejects.toThrow(/protocol client is unavailable/)
  })

  it.each([
    ['state identity', { id: 'embedded-state' }, 'lookup-state', /state mismatch/],
    ['request type', { request_type: 'so:r' }, 'callback-state', /unexpected request type/],
    ['authority', { authority: 'https://other.atol.test' }, 'callback-state', /authority mismatch/],
    ['client', { client_id: 'other-client' }, 'callback-state', /client mismatch/],
  ])('rejects callback %s mismatch before exchange', async (_name, overrides, storageKey, error) => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
    const state = await SigninState.create({
      id: 'callback-state',
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
      nonce: 'oidc-nonce',
      ...overrides,
    })
    await mgr.settings.stateStore.set(storageKey, state.toStorageString())

    await expect(
      readAuthorizationCodeCallback(
        mgr,
        `${redirectUri}?code=authorization-code&state=${storageKey}`,
      ),
    ).rejects.toThrow(error)
  })

  it.each([
    ['login_required', true],
    ['temporarily_unavailable', false],
  ])('maps callback protocol error %s to a typed error', async (protocolError, loginRequired) => {
    const sentinel = 'sentinel-secret-provider-description'
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
    const state = await SigninState.create({
      id: `error-${protocolError}`,
      request_type: 'si:r',
      code_verifier: 'pkce-verifier',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
      nonce: 'oidc-nonce',
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())

    const error = await readAuthorizationCodeCallback(
      mgr,
      `${redirectUri}?error=${protocolError}&error_description=${sentinel}&state=${state.id}`,
    ).catch((caught: unknown) => caught)
    if (loginRequired) {
      expect(error).toMatchObject({ name: 'LoginRequiredError' })
    } else {
      expect(error).toMatchObject({
        name: 'OAuthProtocolError',
        code: protocolError,
      })
    }
    expect(error).not.toHaveProperty('description')
    expect(error).not.toHaveProperty('cause')
    if (!(error instanceof Error)) {
      throw new Error('expected an Error')
    }
    expect(
      [
        error.message,
        error.stack ?? '',
        JSON.stringify(error),
        ...Object.getOwnPropertyNames(error).map((name) =>
          String(Reflect.get(error, name)),
        ),
      ].join('\n'),
    ).not.toContain(sentinel)
  })

  it('does not retain a callback URL when third-party parsing fails', async () => {
    const sentinel = 'sentinel-secret-callback-query'
    const mgr = createUserManager(
      'https://auth.atol.test',
      'atol_kid_x',
      'https://app.test/cb',
      'openid',
    )

    const error = await readAuthorizationCodeCallback(
      mgr,
      `https://app.test/cb?code=${sentinel}&state=${sentinel}`,
    ).catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(Error)
    expect(error).not.toHaveProperty('cause')
    if (!(error instanceof Error)) {
      throw new Error('expected an Error')
    }
    expect(error.message).toBe(
      'OIDC callback response could not be read',
    )
    expect(
      [
        error.message,
        error.stack ?? '',
        JSON.stringify(error),
      ].join('\n'),
    ).not.toContain(sentinel)
  })

  it.each([
    ['authorization code', { code_verifier: 'pkce-verifier' }, /authorization code/],
    ['PKCE verifier', { code_verifier: '' }, /PKCE verifier/],
  ])('rejects a callback missing its %s', async (_name, overrides, error) => {
    const authority = 'https://auth.atol.test'
    const clientId = 'atol_kid_x'
    const redirectUri = 'https://app.test/cb'
    const mgr = createUserManager(authority, clientId, redirectUri, 'openid')
    const state = await SigninState.create({
      id: `missing-${_name.replace(/ /g, '-')}`,
      request_type: 'si:r',
      authority,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
      nonce: 'oidc-nonce',
      ...overrides,
    })
    await mgr.settings.stateStore.set(state.id, state.toStorageString())
    const code = _name === 'authorization code' ? '' : '&code=authorization-code'

    await expect(
      readAuthorizationCodeCallback(mgr, `${redirectUri}?state=${state.id}${code}`),
    ).rejects.toThrow(error)
  })

  it('rejects authorization state removal that does not clear storage', async () => {
    const mgr = createUserManager(
      'https://auth.atol.test',
      'atol_kid_x',
      'https://app.test/cb',
      'openid',
    )
    vi.spyOn(mgr.settings.stateStore, 'get').mockResolvedValue('exact-state')
    vi.spyOn(mgr.settings.stateStore, 'remove').mockResolvedValue('exact-state')

    await expect(
      removeAuthorizationRequestState(mgr, 'request-state', 'exact-state'),
    ).rejects.toThrow(/removal failed/)
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
