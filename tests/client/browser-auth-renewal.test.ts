/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  CLIENT_ID,
  ISSUER,
  LoginRequiredError,
  OAuthProtocolError,
  makeAccessToken,
  makeClient,
  makeIDToken,
  makeJWT,
  manager,
  mockAuthorize,
  ordinaryBeginSpy,
  mockExchange,
  mockRefresh,
  mockRevoke,
  tokenResponse,
} from './browser-auth-harness'

describe('createAtolBrowserAuth -- forceRenew', () => {
  it('rotates the refresh token via the refresh grant and writes it back', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'rt_one',
    })
    // Refresh-token strategy: forceRenew goes through the refresh grant.
    const client = makeClient(false, true)
    await client.init()

    mockRefresh.mockResolvedValue(tokenResponse({ refresh_token: 'rt_two' }))
    const newToken = await client.forceRenew()
    expect(typeof newToken).toBe('string')
    expect(mockRefresh).toHaveBeenCalledWith(
      ISSUER,
      CLIENT_ID,
      'rt_one',
      expect.any(String),
      undefined,
      undefined,
    )
    // Rotated token stored back.
    const lastStore = manager.storeUser.mock.calls.at(-1)![0] as { refresh_token?: string }
    expect(lastStore.refresh_token).toBe('rt_two')
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- renewal model (iframe default vs refresh opt-in)', () => {
  const CHANNEL = `atol:tokens:${ISSUER}:${CLIENT_ID}`

  it('default: authorize scope OMITS offline_access', async () => {
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    mockExchange.mockResolvedValue(tokenResponse({ refresh_token: undefined }))
    const client = makeClient()
    await client.init()

    // The iframe authorize request must carry the caller scope verbatim --
    // no offline_access is force-added in the default model.
    const cfg = ordinaryBeginSpy().mock.calls[0][1] as {
      scope: string
    }
    expect(cfg.scope.split(' ')).not.toContain('offline_access')
    expect(cfg.scope).toBe('openid profile email')
    client.destroy()
  })

  it('default: renewal goes through the IFRAME path, never the refresh grant', async () => {
    // Log in with an access token already inside the renew window so the
    // first getAccessToken triggers a renew.
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    // Restore-time exchange establishes the session (stale token forces renew).
    mockExchange.mockResolvedValueOnce(
      tokenResponse({ access_token: makeAccessToken(30), refresh_token: 'rt_stray' }),
    )
    const client = makeClient()
    await client.init()

    // The stray server RT must NOT have been retained.
    mockExchange.mockResolvedValueOnce(
      tokenResponse({ access_token: makeAccessToken(3600), refresh_token: undefined }),
    )
    const token = await client.forceRenew()

    expect(typeof token).toBe('string')
    // Iframe path used; refresh grant never called.
    expect(mockAuthorize).toHaveBeenCalled()
    expect(mockRefresh).not.toHaveBeenCalled()
    client.destroy()
  })

  it('default: no refresh token is stored or broadcast on renewal', async () => {
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    mockExchange.mockResolvedValueOnce(
      tokenResponse({ access_token: makeAccessToken(30), refresh_token: 'rt_stray' }),
    )
    const client = makeClient()
    await client.init()

    const heard: Array<Record<string, unknown>> = []
    const listener = new BroadcastChannel(CHANNEL)
    listener.onmessage = (e) => heard.push(e.data as Record<string, unknown>)

    mockExchange.mockResolvedValueOnce(
      tokenResponse({ access_token: makeAccessToken(3600), refresh_token: 'rt_stray_2' }),
    )
    await client.forceRenew()
    await new Promise((r) => setTimeout(r, 20))

    // Nothing written back to the store carries a refresh token.
    for (const call of manager.storeUser.mock.calls) {
      expect((call[0] as { refresh_token?: string }).refresh_token).toBeUndefined()
    }
    // Cross-tab traffic is a signal only and carries no credentials.
    const signals = heard.filter((m) => m.type === 'credentials-invalidated')
    expect(signals.length).toBeGreaterThan(0)
    for (const m of signals) {
      expect(m.accessToken).toBeUndefined()
      expect(m.idToken).toBeUndefined()
      expect(m.refreshToken).toBeUndefined()
    }
    listener.close()
    client.destroy()
  })

  it('default: getAccessToken still returns a token and DPoP proof attaches', async () => {
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    let at = ''
    mockExchange.mockImplementation(async (...args) => {
      const signer = args[5] as unknown as { thumbprint: () => Promise<string> }
      at = makeJWT({
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 3600,
        cnf: { jkt: await signer.thumbprint() },
      })
      return tokenResponse({
        access_token: at,
        refresh_token: undefined,
        token_type: 'DPoP',
      })
    })
    const client = makeClient(true) // DPoP on, useRefreshTokens default (false)
    await client.init()
    await vi.waitFor(() => expect(client.isDPoPActive()).toBe(true))

    const res = await client.getAccessToken({
      dpop: { method: 'GET', url: 'https://api.example.com/me' },
    })
    expect(res?.token).toBe(at)
    expect(res?.proof).toBeTruthy()
    const header = JSON.parse(Buffer.from(res!.proof!.split('.')[0], 'base64url').toString())
    expect(header.typ).toBe('dpop+jwt')
    // The iframe code exchange received the DPoP key (proof-bound exchange).
    expect(mockExchange).toHaveBeenCalled()
    const dpopArg = mockExchange.mock.calls[0][5]
    expect(dpopArg).toBeTruthy()
    client.destroy()
  })

  it('useRefreshTokens: authorize scope APPENDS offline_access', async () => {
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    mockExchange.mockResolvedValue(tokenResponse())
    const client = makeClient(false, true)
    await client.init()

    const cfg = ordinaryBeginSpy().mock.calls[0][1] as {
      scope: string
    }
    expect(cfg.scope.split(' ')).toContain('offline_access')
    client.destroy()
  })

  it('useRefreshTokens: renewal stores the RT but broadcasts only invalidation', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'rt_one',
    })
    const client = makeClient(false, true)
    await client.init()

    const heard: Array<Record<string, unknown>> = []
    const listener = new BroadcastChannel(CHANNEL)
    listener.onmessage = (e) => heard.push(e.data as Record<string, unknown>)

    mockRefresh.mockResolvedValue(tokenResponse({ refresh_token: 'rt_two' }))
    const token = await client.forceRenew()
    await new Promise((r) => setTimeout(r, 20))

    expect(typeof token).toBe('string')
    expect(mockRefresh).toHaveBeenCalledWith(
      ISSUER,
      CLIENT_ID,
      'rt_one',
      expect.stringContaining('offline_access'),
      undefined,
      undefined,
    )
    // Rotated RT stays local; the channel carries only invalidation.
    const lastStore = manager.storeUser.mock.calls.at(-1)![0] as { refresh_token?: string }
    expect(lastStore.refresh_token).toBe('rt_two')
    const signals = heard.filter((m) => m.type === 'credentials-invalidated')
    expect(signals).toHaveLength(1)
    expect(signals[0]?.refreshToken).toBeUndefined()
    listener.close()
    client.destroy()
  })

  it('useRefreshTokens: logout revokes the stored refresh token', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'rt_revoke_me',
    })
    const client = makeClient(false, true)
    await client.init()
    await client.logout()
    expect(mockRevoke).toHaveBeenCalledWith(ISSUER, CLIENT_ID, 'rt_revoke_me')
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- useRefreshTokensFallback', () => {
  /** Log in via the redirect callback with a stored refresh token. */
  async function loggedInWithRefreshToken(fallback: boolean) {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'rt_one',
    })
    const client = makeClient(false, true, fallback)
    await client.init()
    return client
  }

  it('fallback true: a TRANSIENT refresh-grant failure falls back to the iframe, session preserved', async () => {
    const client = await loggedInWithRefreshToken(true)

    // The refresh grant fails transiently (5xx -> RecoveryAction.Retry).
    mockRefresh.mockRejectedValue(new OAuthProtocolError('server_error'))
    // The iframe fallback succeeds and re-establishes a fresh token.
    const freshToken = makeAccessToken(3600)
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    mockExchange.mockClear()
    mockExchange.mockResolvedValue(
      tokenResponse({ access_token: freshToken, refresh_token: 'rt_two' }),
    )

    const token = await client.forceRenew()

    // Fell back to the iframe path: authorize + exchange ran once.
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    expect(mockAuthorize).toHaveBeenCalledTimes(1)
    expect(mockExchange).toHaveBeenCalledTimes(1)
    expect(token).toBe(freshToken)
    // Session is preserved (not cleared): the token is still available.
    const res = await client.getAccessToken()
    expect(res?.token).toBe(freshToken)
    client.destroy()
  })

  it('fallback false: a TRANSIENT refresh-grant failure re-throws for backoff, no iframe', async () => {
    const client = await loggedInWithRefreshToken(false)

    mockRefresh.mockRejectedValue(new OAuthProtocolError('server_error'))
    mockAuthorize.mockClear()
    mockExchange.mockClear()

    // Retry -> renewOnce re-throws; forceRenew surfaces the rejection.
    await expect(client.forceRenew()).rejects.toBeInstanceOf(OAuthProtocolError)
    // The iframe path was NOT taken.
    expect(mockAuthorize).not.toHaveBeenCalled()
    expect(mockExchange).not.toHaveBeenCalled()
    // Session survives a transient failure (deny-by-default is only for
    // terminal auth errors): the previously stored token is still served.
    const res = await client.getAccessToken()
    expect(res?.token).toBeTruthy()
    client.destroy()
  })

  it('fallback true: a TERMINAL refresh-grant failure still clears the session (no iframe)', async () => {
    const client = await loggedInWithRefreshToken(true)

    // login_required -> RecoveryAction.ForceReauth: terminal, must NOT fall
    // back to the iframe and MUST clear the session.
    mockRefresh.mockRejectedValue(new LoginRequiredError('login_required'))
    mockAuthorize.mockClear()
    mockExchange.mockClear()

    const token = await client.forceRenew()

    expect(token).toBeUndefined()
    // No iframe fallback for a terminal error.
    expect(mockAuthorize).not.toHaveBeenCalled()
    expect(mockExchange).not.toHaveBeenCalled()
    // Session cleared: no token, unauthenticated.
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })
})
