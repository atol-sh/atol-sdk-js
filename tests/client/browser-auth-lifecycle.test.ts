/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import { KEKVault } from '../../src/crypto/kek-vault'
import {
  credentialGenerationSnapshot,
  rotateLogoutGeneration,
} from '../../src/oidc/credential-generation'
import { OrdinaryAuthorizationPendingError } from '../../src/oidc/ordinary-authorization'
import {
  CLIENT_ID,
  ISSUER,
  LoginRequiredError,
  OAuthProtocolError,
  REDIRECT,
  createAtolBrowserAuth,
  makeAccessToken,
  makeClient,
  makeIDToken,
  makeJWT,
  manager,
  mockAuthorize,
  ordinaryBeginSpy,
  mockExchange,
  mockInvalidateOrdinarySignedOut,
  mockRefresh,
  tokenResponse,
} from './browser-auth-harness'

describe('createAtolBrowserAuth -- renewal edge cases', () => {
  /**
   * Log in with a STALE access token (inside the exp-60s renew window) so
   * the first getAccessToken triggers a real renew through the refresh
   * grant. Returns the client.
   */
  async function loggedInStale() {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(30), // 30s left -> inside renew window
      id_token: makeIDToken(),
      refresh_token: 'rt_stale',
    })
    const client = makeClient(false, true)
    await client.init()
    return client
  }

  it('single-flight: concurrent getAccessToken calls collapse to ONE renew', async () => {
    const client = await loggedInStale()

    let resolveGrant: ((v: ReturnType<typeof tokenResponse>) => void) | undefined
    mockRefresh.mockImplementation(
      () =>
        new Promise((res) => {
          resolveGrant = res
        }),
    )

    // Fire three concurrent callers while the token is stale.
    const p1 = client.getAccessToken()
    const p2 = client.getAccessToken()
    const p3 = client.getAccessToken()

    // Let the microtasks settle so all three reach the single-flight guard.
    await Promise.resolve()
    resolveGrant!(tokenResponse({ access_token: makeAccessToken(3600), refresh_token: 'rt_new' }))

    const [r1, r2, r3] = await Promise.all([p1, p2, p3])
    // Exactly one network renew despite three concurrent callers.
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    expect(r1?.token).toBe(r2?.token)
    expect(r2?.token).toBe(r3?.token)
    client.destroy()
  })

  it('terminal error clears the session and does NOT loop (no retry storm)', async () => {
    const client = await loggedInStale()

    // Every renew attempt returns a terminal auth failure.
    mockRefresh.mockRejectedValue(new LoginRequiredError('login_required'))

    const token = await client.forceRenew()
    expect(token).toBeUndefined()
    // Session cleared -> subsequent getAccessToken is undefined.
    expect(await client.getAccessToken()).toBeUndefined()
    // The terminal failure did not spin into a second grant attempt.
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    client.destroy()
  })

  it('a TRANSIENT renew failure rejects but preserves the session (retry later)', async () => {
    const client = await loggedInStale()

    // A 5xx (server_error) is transient -> RecoveryAction.Retry -> re-throw.
    mockRefresh.mockRejectedValueOnce(new OAuthProtocolError('server_error'))
    await expect(client.forceRenew()).rejects.toBeInstanceOf(OAuthProtocolError)

    // Session survives; the NEXT renew succeeds and returns a fresh token.
    const fresh = makeAccessToken(3600)
    mockRefresh.mockResolvedValueOnce(tokenResponse({ access_token: fresh, refresh_token: 'rt2' }))
    const res = await client.getAccessToken()
    expect(res?.token).toBe(fresh)
    client.destroy()
  })

  it('iframe timeout surfaces without clearing the session (default model)', async () => {
    // Default (iframe) model: log in with a stale token via the restore path.
    mockAuthorize.mockResolvedValueOnce({ code: 'silent', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    mockExchange.mockResolvedValueOnce(
      tokenResponse({ access_token: makeAccessToken(30), refresh_token: undefined }),
    )
    const client = makeClient() // default: iframe renewal
    await client.init()

    // Next renew: the silent authorize times out -> a plain Error (not an
    // OAuthProtocolError), classified as Surface -> re-thrown, session kept.
    mockAuthorize.mockRejectedValueOnce(new Error('silent renew timed out'))
    await expect(client.forceRenew()).rejects.toThrow(/timed out/)

    // Session preserved: a later successful iframe renew restores freshness.
    const fresh = makeAccessToken(3600)
    mockAuthorize.mockResolvedValueOnce({ code: 'silent2', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    mockExchange.mockResolvedValueOnce(
      tokenResponse({ access_token: fresh, refresh_token: undefined }),
    )
    const res = await client.getAccessToken()
    expect(res?.token).toBe(fresh)
    client.destroy()
  })

  it('proactive timer renews at (exp - 60s) and reschedules for the new token', async () => {
    vi.useFakeTimers()
    try {
      // Access token with 90s of life: proactive renew is armed for ~30s
      // out (exp - 60s). Use the refresh-grant model for a deterministic,
      // iframe-free renew.
      window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
      manager.signinRedirectCallback.mockResolvedValue({
        access_token: makeAccessToken(90),
        id_token: makeIDToken(),
        refresh_token: 'rt_proactive',
      })
      const client = makeClient(false, true)
      await client.init()

      // The scheduled renew fires and rotates to a long-lived token.
      mockRefresh.mockResolvedValueOnce(
        tokenResponse({ access_token: makeAccessToken(3600), refresh_token: 'rt_next' }),
      )
      // Advance past (exp - 60s) ~= 30s so the proactive timer fires.
      await vi.advanceTimersByTimeAsync(31_000)

      expect(mockRefresh).toHaveBeenCalledTimes(1)
      client.destroy()
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('createAtolBrowserAuth -- deriveEncryptionKey plumbing', () => {
  it('does not expose candidate credentials while encryption preparation is pending', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    const idToken = makeIDToken({ 'atol:wrapped_dek': 'wrapped-dek' })
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idToken,
    })
    let releaseRehydrate: ((key: Uint8Array) => void) | undefined
    vi.spyOn(KEKVault.prototype, 'rehydrate').mockImplementation(
      () =>
        new Promise((resolve) => {
          releaseRehydrate = resolve
        }),
    )
    const client = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      deriveEncryptionKey: true,
    })
    const snapshots: boolean[] = []
    client.onSessionChange((value) => {
      snapshots.push(value.isAuthenticated)
    })

    const pending = client.init()
    await vi.waitFor(() =>
      expect(KEKVault.prototype.rehydrate).toHaveBeenCalledTimes(1),
    )
    expect(client.getIdToken()).toBeUndefined()
    expect(await client.getAccessToken()).toBeUndefined()
    expect(snapshots).toEqual([false])

    releaseRehydrate?.(new Uint8Array(32).fill(7))
    await pending
    expect(client.getIdToken()).toBe(idToken)
    expect((await client.getAccessToken())?.token).toBeDefined()
    expect(snapshots.at(-1)).toBe(true)
    client.destroy()
  })

  it('appends derive_encryption_key=true to the login authorize request', async () => {
    const client = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      deriveEncryptionKey: true,
    })
    await client.beginLogin()
    const args = manager.signinRedirect.mock.calls[0][0] as {
      extraQueryParams: Record<string, string>
    }
    expect(args.extraQueryParams.derive_encryption_key).toBe('true')
    client.destroy()
  })

  it('asks the iframe silent renew to re-emit the wrapped-DEK claim', async () => {
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    mockExchange.mockResolvedValue(tokenResponse({ refresh_token: undefined }))
    const client = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      deriveEncryptionKey: true,
    })
    await client.init() // restore path -> ordinary PAR iframe authorization
    const start = ordinaryBeginSpy().mock.calls[0][0] as {
      intent: { extraQueryParams?: Record<string, string> }
    }
    expect(start.intent.extraQueryParams?.derive_encryption_key).toBe(
      'true',
    )
    client.destroy()
  })

  it('omits derive_encryption_key when the flag is off (default)', async () => {
    const client = makeClient()
    await client.beginLogin()
    const args = manager.signinRedirect.mock.calls[0][0] as {
      extraQueryParams: Record<string, string>
    }
    expect(args.extraQueryParams.derive_encryption_key).toBeUndefined()
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- cross-tab broadcast', () => {
  const CHANNEL = `atol:tokens:${ISSUER}:${CLIENT_ID}`

  function broadcast(msg: Record<string, unknown>) {
    const leader = new BroadcastChannel(CHANNEL)
    leader.postMessage(msg)
    leader.close()
  }

  async function loggedInClient(dpop = false, useRefreshTokens = false) {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(1800),
      id_token: makeIDToken(),
      refresh_token: 'rt_follower_own',
    })
    const client = makeClient(dpop, useRefreshTokens)
    await client.init()
    window.history.replaceState({}, '', '/')
    return client
  }

  it('renews locally when another tab invalidates credentials', async () => {
    const client = await loggedInClient(false, true)
    const localToken = makeAccessToken(7200)
    mockRefresh.mockResolvedValue(
      tokenResponse({ access_token: localToken, refresh_token: 'rt_follower_rotated' }),
    )

    broadcast({
      type: 'credentials-invalidated',
      sentAt: Date.now(),
    })

    await vi.waitFor(() => expect(mockRefresh).toHaveBeenCalledTimes(1))
    expect(mockRefresh.mock.calls[0]?.[2]).toBe('rt_follower_own')
    expect((await client.getAccessToken())?.token).toBe(localToken)
    client.destroy()
  })

  it('clears local credentials on a session-ended signal', async () => {
    const client = await loggedInClient(false)
    const logoutGeneration = rotateLogoutGeneration({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    })
    const resultingGeneration = credentialGenerationSnapshot({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    })
    broadcast({
      type: 'session-ended',
      logoutGeneration,
      sentAt: Date.now(),
    })
    await vi.waitFor(async () => expect(await client.getAccessToken()).toBeUndefined())
    expect(
      credentialGenerationSnapshot({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT,
      }),
    ).toEqual(resultingGeneration)
    client.destroy()
  })

  it('[R09] under DPoP, never adopts a foreign access or refresh token', async () => {
    const client = await loggedInClient(true, true)
    await vi.waitFor(() => expect(client.isDPoPActive()).toBe(true))
    const ownAccessToken = (await client.getAccessToken())!.token
    manager.storeUser.mockClear()

    const foreignAccessToken = makeAccessToken(7200)

    broadcast({
      type: 'token-rotated',
      accessToken: foreignAccessToken,
      idToken: makeIDToken(),
      refreshToken: 'rt_leader_bound',
      expiresAt: Date.now() + 7200_000,
      sentAt: Date.now(),
    })

    await new Promise((resolve) => setTimeout(resolve, 30))
    const accessAfterForeignBroadcast = (await client.getAccessToken())!.token
    const storedCredentials = manager.storeUser.mock.calls.map((call) =>
      call[0] as { access_token?: string; refresh_token?: string },
    )
    client.destroy()

    expect(accessAfterForeignBroadcast).toBe(ownAccessToken)
    expect(storedCredentials.every((user) => user.access_token !== foreignAccessToken)).toBe(true)
    expect(storedCredentials.every((user) => user.refresh_token !== 'rt_leader_bound')).toBe(true)
  })

  it('[R09] under DPoP, an invalidation signal renews with this tab key and refresh token', async () => {
    const client = await loggedInClient(true, true)
    await vi.waitFor(() => expect(client.isDPoPActive()).toBe(true))
    let locallyBoundAccessToken = ''
    mockRefresh.mockImplementation(async (...args) => {
      const signer = args[5] as unknown as { thumbprint: () => Promise<string> }
      locallyBoundAccessToken = makeJWT({
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 7200,
        cnf: { jkt: await signer.thumbprint() },
      })
      return tokenResponse({
        access_token: locallyBoundAccessToken,
        refresh_token: 'rt_follower_rotated',
        token_type: 'DPoP',
      })
    })

    broadcast({
      type: 'credentials-invalidated',
      sentAt: Date.now(),
    })

    await new Promise((resolve) => setTimeout(resolve, 30))
    const refreshCalls = mockRefresh.mock.calls.slice()
    const currentAccessToken = (await client.getAccessToken())!.token
    client.destroy()

    expect(refreshCalls).toHaveLength(1)
    expect(refreshCalls[0]?.[2]).toBe('rt_follower_own')
    expect(refreshCalls[0]?.[5]).toBeTruthy()
    expect(currentAccessToken).toBe(locallyBoundAccessToken)
  })
})

describe('createAtolBrowserAuth -- signed-out ordinary reconciliation', () => {
  it('reconciles ordinary custody before reporting signed-out startup', async () => {
    window.history.replaceState({}, '', '/')
    rotateLogoutGeneration({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    })
    const client = makeClient()

    await expect(client.init()).resolves.toMatchObject({
      isAuthenticated: false,
    })

    expect(mockInvalidateOrdinarySignedOut).toHaveBeenCalledOnce()
    expect(mockAuthorize).not.toHaveBeenCalled()
    client.destroy()
  })

  it('surfaces uncertain ordinary reconciliation instead of claiming success', async () => {
    window.history.replaceState({}, '', '/')
    rotateLogoutGeneration({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    })
    mockInvalidateOrdinarySignedOut
      .mockRejectedValue(new OrdinaryAuthorizationPendingError())
    const client = makeClient()

    await expect(client.init()).rejects.toBeInstanceOf(
      OrdinaryAuthorizationPendingError,
    )

    expect(mockInvalidateOrdinarySignedOut).toHaveBeenCalledOnce()
    expect(mockAuthorize).not.toHaveBeenCalled()
    client.destroy()
  })
})
