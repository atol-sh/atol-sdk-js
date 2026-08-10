/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  CLIENT_ID,
  ISSUER,
  LoginRequiredError,
  REDIRECT,
  createAtolBrowserAuth,
  makeAccessToken,
  makeClient,
  makeIDToken,
  manager,
  mockAuthorize,
  mockExchange,
  mockRevoke,
} from './browser-auth-harness'
import { currentCredentialAuthority } from '../../src/oidc/credential-generation'
import { OrdinaryAuthorizationPendingError } from '../../src/oidc/ordinary-authorization'

describe('createAtolBrowserAuth -- logout', () => {
  it('rejects login cancellation outside response-vault mode', async () => {
    const auth = makeClient()

    await expect(auth.cancelLogin()).rejects.toThrow(
      'cancelLogin requires response-vault authorization',
    )
    expect(manager.signoutRedirect).not.toHaveBeenCalled()
    auth.destroy()
  })

  it('fences an old callback while signout navigation is delayed', async () => {
    let releaseNavigation: (() => void) | undefined
    manager.signoutRedirect.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          releaseNavigation = resolve
        }),
    )
    const auth = makeClient()
    await auth.beginLogin()
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })

    const logout = auth.logout()
    await vi.waitFor(() =>
      expect(manager.signoutRedirect).toHaveBeenCalledTimes(1),
    )
    window.history.replaceState({}, '', '/cb?code=old&state=old')
    const reloaded = makeClient()

    await expect(reloaded.completeLogin()).rejects.toThrow(
      'OIDC callback failed. Please sign in again.',
    )
    expect(mockExchange).not.toHaveBeenCalled()
    expect(manager.storeUser).not.toHaveBeenCalled()

    releaseNavigation?.()
    await logout
    reloaded.destroy()
    auth.destroy()
  })

  it('single-flights concurrent logout without rotating or revoking twice', async () => {
    let releaseNavigation: (() => void) | undefined
    manager.signoutRedirect.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          releaseNavigation = resolve
        }),
    )
    const auth = makeClient()

    const first = auth.logout()
    const second = auth.logout()
    expect(second).toBe(first)
    await vi.waitFor(() =>
      expect(manager.signoutRedirect).toHaveBeenCalledTimes(1),
    )

    releaseNavigation?.()
    await first
    expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
    auth.destroy()
  })

  it('does not clear the tombstone while logout is still unresolved', async () => {
    let rejectNavigation: ((error: Error) => void) | undefined
    manager.signoutRedirect.mockImplementationOnce(
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectNavigation = reject
        }),
    )
    const auth = makeClient()

    const logout = auth.logout()
    await vi.waitFor(() =>
      expect(manager.signoutRedirect).toHaveBeenCalledTimes(1),
    )
    const login = auth.beginLogin()
    expect(manager.signinRedirect).not.toHaveBeenCalled()

    rejectNavigation?.(new Error('navigation was blocked'))
    await expect(logout).rejects.toThrow('navigation was blocked')
    await expect(login).rejects.toThrow('navigation was blocked')
    expect(manager.signinRedirect).not.toHaveBeenCalled()
    expect(
      currentCredentialAuthority({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT,
      }).signedOut,
    ).toBe(true)
    auth.destroy()
  })

  it('keeps an old callback fenced when signout navigation fails', async () => {
    manager.signoutRedirect.mockRejectedValueOnce(
      new Error('navigation was blocked'),
    )
    const auth = makeClient()
    await auth.beginLogin()
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })

    await expect(auth.logout()).rejects.toThrow('navigation was blocked')
    window.history.replaceState({}, '', '/cb?code=old&state=old')
    const reloaded = makeClient()

    await expect(reloaded.completeLogin()).rejects.toThrow(
      'OIDC callback failed. Please sign in again.',
    )
    expect(mockExchange).not.toHaveBeenCalled()
    expect(manager.storeUser).not.toHaveBeenCalled()

    reloaded.destroy()
    auth.destroy()
  })

  it('keeps the durable tombstone when revocation and navigation fail', async () => {
    const originalBroadcastChannel = globalThis.BroadcastChannel
    Object.defineProperty(globalThis, 'BroadcastChannel', {
      configurable: true,
      value: undefined,
    })
    try {
      const idToken = makeIDToken()
      window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
      manager.signinRedirectCallback.mockResolvedValue({
        access_token: makeAccessToken(),
        id_token: idToken,
        refresh_token: 'rt_retry_custody',
      })
      const auth = makeClient(false, true)
      await auth.init()
      mockRevoke.mockRejectedValueOnce(new Error('revocation unavailable'))
      manager.signoutRedirect.mockRejectedValueOnce(
        new Error('navigation was blocked'),
      )

      await expect(auth.logout()).rejects.toThrow('revocation unavailable')
      expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
      expect(
        currentCredentialAuthority({
          issuer: ISSUER,
          clientId: CLIENT_ID,
          redirectUri: REDIRECT,
        }).signedOut,
      ).toBe(true)

      // A fresh SDK instance must not consult the restored IdP SSO session,
      // even when BroadcastChannel never existed and logout navigation failed.
      mockAuthorize.mockClear()
      mockAuthorize.mockResolvedValue({
        code: 'resurrected-sso',
        state: 'state',
        codeVerifier: 'verifier',
        nonce: 'nonce',
      })
      window.history.replaceState({}, '', '/')
      const reloaded = makeClient()
      await expect(reloaded.init()).resolves.toMatchObject({
        isAuthenticated: false,
      })
      expect(mockAuthorize).not.toHaveBeenCalled()

      await expect(auth.logout()).resolves.toBeUndefined()
      expect(mockRevoke).toHaveBeenCalledTimes(2)
      expect(mockRevoke.mock.calls[1]).toEqual([
        ISSUER,
        CLIENT_ID,
        'rt_retry_custody',
      ])
      expect(manager.signoutRedirect).toHaveBeenCalledTimes(2)
      expect(manager.signoutRedirect.mock.calls[1][0]).toMatchObject({
        id_token_hint: idToken,
      })

      reloaded.destroy()
      auth.destroy()
    } finally {
      Object.defineProperty(globalThis, 'BroadcastChannel', {
        configurable: true,
        value: originalBroadcastChannel,
      })
    }
  })

  it('clears the tombstone only when the user explicitly begins login', async () => {
    manager.signoutRedirect.mockRejectedValueOnce(
      new Error('navigation was blocked'),
    )
    const auth = makeClient()
    await expect(auth.logout()).rejects.toThrow('navigation was blocked')
    const signedOut = currentCredentialAuthority({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    })
    expect(signedOut.signedOut).toBe(true)

    const reloaded = makeClient()
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    await reloaded.init()
    expect(mockAuthorize).not.toHaveBeenCalled()

    await reloaded.beginLogin()
    const active = currentCredentialAuthority({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    })
    expect(active.signedOut).toBe(false)
    expect(active.generation).not.toBe(signedOut.generation)
    expect(manager.signinRedirect).toHaveBeenCalledTimes(1)

    reloaded.destroy()
    auth.destroy()
  })

  it('consumes and validates the post-logout callback state exactly once', async () => {
    const auth = makeClient()
    await auth.logout()
    const request = manager.signoutRedirect.mock.calls[0][0] as {
      state: Record<string, unknown>
    }
    manager.signoutRedirectCallback
      .mockResolvedValueOnce({ userState: request.state })
      .mockRejectedValueOnce(new Error('No matching state found in storage'))

    window.history.replaceState({}, '', '/cb?state=one-use-state')
    const callback = makeClient()
    await expect(callback.init()).resolves.toMatchObject({
      isAuthenticated: false,
    })
    expect(manager.signoutRedirectCallback).toHaveBeenCalledWith(
      'https://app.test/cb?state=one-use-state',
    )
    expect(window.location.pathname).toBe('/cb')
    expect(window.location.search).toBe('')
    expect(mockAuthorize).not.toHaveBeenCalled()

    window.history.replaceState({}, '', '/cb?state=one-use-state')
    const replay = makeClient()
    await expect(replay.init()).rejects.toThrow(
      'No matching state found in storage',
    )
    expect(mockAuthorize).not.toHaveBeenCalled()

    replay.destroy()
    callback.destroy()
    auth.destroy()
  })

  it('rejects a post-logout callback bound to another generation', async () => {
    const auth = makeClient()
    await auth.logout()
    const authority = currentCredentialAuthority({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    })
    const foreignGeneration =
      authority.generation === 'A'.repeat(43) ? 'B'.repeat(43) : 'A'.repeat(43)
    manager.signoutRedirectCallback.mockResolvedValueOnce({
      userState: {
        atol_browser_auth_logout: {
          version: 1,
          logout_generation: foreignGeneration,
        },
      },
    })

    window.history.replaceState({}, '', '/cb?state=substituted')
    const callback = makeClient()
    await expect(callback.init()).rejects.toThrow(
      'OIDC post-logout callback was superseded',
    )
    expect(mockAuthorize).not.toHaveBeenCalled()
    expect(
      currentCredentialAuthority({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT,
      }).signedOut,
    ).toBe(true)

    callback.destroy()
    auth.destroy()
  })

  it('uses a distinct exact post-logout redirect when configured', async () => {
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    const client = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      postLogoutRedirectUri: 'https://app.test/logout',
    })
    await client.init()

    await client.logout()

    expect(manager.signoutRedirect).toHaveBeenCalledWith(
      expect.objectContaining({
        post_logout_redirect_uri: 'https://app.test/logout',
        state: {
          atol_browser_auth_logout: {
            logout_generation: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
            version: 1,
          },
        },
      }),
    )
    client.destroy()
  })

  it.each([
    'not a URL',
    'https://evil.test/logout',
    'https://app.test/logout?token=leak',
    'https://user@app.test/logout',
  ])('rejects an unsafe post-logout redirect: %s', (postLogoutRedirectUri) => {
    expect(() =>
      createAtolBrowserAuth({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT,
        postLogoutRedirectUri,
      }),
    ).toThrow(/postLogoutRedirectUri/)
  })

  it('revokes the refresh token and redirects with id_token_hint', async () => {
    const idToken = makeIDToken()
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idToken,
      refresh_token: 'rt_to_revoke',
    })
    manager.getUser.mockResolvedValue({ id_token: idToken })

    // useRefreshTokens: the RT is stored, so logout revokes it.
    const client = makeClient(false, true)
    await client.init()
    await client.logout()

    // The snapshotted refresh token is revoked before the logout redirect.
    expect(mockRevoke).toHaveBeenCalledWith(ISSUER, CLIENT_ID, 'rt_to_revoke')
    // RP-initiated end_session with id_token_hint + post_logout_redirect_uri.
    expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
    expect(manager.signoutRedirect.mock.calls[0][0]).toMatchObject({
      post_logout_redirect_uri: REDIRECT,
      id_token_hint: idToken,
    })
    client.destroy()
  })

  it('orders a delayed credential-store write before the logout clear', async () => {
    let releaseStore: (() => void) | undefined
    const storeGate = new Promise<void>((resolve) => {
      releaseStore = resolve
    })
    let persistedUser = false
    manager.storeUser.mockImplementationOnce(async () => {
      await storeGate
      persistedUser = true
    })
    manager.removeUser.mockImplementation(async () => {
      persistedUser = false
    })
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    const client = makeClient()
    const init = client.init()
    await vi.waitFor(() => expect(manager.storeUser).toHaveBeenCalledTimes(1))

    const logout = client.logout()
    expect(await client.getAccessToken()).toBeUndefined()
    expect(manager.removeUser).not.toHaveBeenCalled()

    releaseStore?.()
    await expect(init).rejects.toBeInstanceOf(
      OrdinaryAuthorizationPendingError,
    )
    await logout
    expect(manager.removeUser).toHaveBeenCalled()
    expect(persistedUser).toBe(false)
    client.destroy()
  })

  it('does not return the original authenticated init snapshot after logout', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    const client = makeClient()
    await expect(client.init()).resolves.toMatchObject({
      isAuthenticated: true,
    })

    await client.logout()

    await expect(client.init()).resolves.toMatchObject({
      isAuthenticated: false,
    })
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('omits id_token_hint gracefully when no user is loaded', async () => {
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    const client = makeClient()
    await client.init()
    manager.getUser.mockResolvedValue(null)

    await client.logout()
    expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
    const args = manager.signoutRedirect.mock.calls[0][0] as Record<
      string,
      unknown
    >
    expect(args).toMatchObject({
      post_logout_redirect_uri: REDIRECT,
      state: {
        atol_browser_auth_logout: {
          logout_generation: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
          version: 1,
        },
      },
    })
    expect(args).not.toHaveProperty('id_token_hint')
    // No refresh token -> no revocation attempted.
    expect(mockRevoke).not.toHaveBeenCalled()
    client.destroy()
  })
})
