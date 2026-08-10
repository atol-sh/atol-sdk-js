/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  CLIENT_ID,
  ISSUER,
  LoginRequiredError,
  ORG_A,
  REDIRECT,
  makeAccessToken,
  makeClient,
  makeIDToken,
  makeOrgAccessToken,
  manager,
  mockAccessVerify,
  mockAuthorize,
  mockExchange,
  mockVerify,
  ordinaryBeginSpy,
  setCallbackCredentialGeneration,
  tokenResponse,
} from './browser-auth-harness'
import {
  credentialGenerationSnapshot,
  rotateLogoutGeneration,
} from '../../src/oidc/credential-generation'
import { OrdinaryAuthorizationPendingError } from '../../src/oidc/ordinary-authorization'
import { AtolBrowserAuthCleanupError } from '../../src/client/browser-auth'

describe('createAtolBrowserAuth -- init (redirect callback)', () => {
  it('retries a partially failed browser-resource teardown without leaking its cause', async () => {
    const sentinel = 'sentinel-secret-browser-auth-cleanup'
    let closeAttempts = 0
    class RetriableCleanupChannel {
      constructor(_name: string) {}
      postMessage(_message: unknown): void {}
      addEventListener(
        _type: 'message',
        _handler: (event: { data: unknown }) => void,
      ): void {}
      removeEventListener(
        _type: 'message',
        _handler: (event: { data: unknown }) => void,
      ): void {}
      close(): void {
        closeAttempts++
        if (closeAttempts === 1) throw new Error(sentinel)
      }
    }
    vi.stubGlobal('BroadcastChannel', RetriableCleanupChannel)
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    const client = makeClient()

    try {
      await client.init()
      const error = (() => {
        try {
          client.destroy()
        } catch (caught) {
          return caught
        }
      })()

      expect(error).toBeInstanceOf(AtolBrowserAuthCleanupError)
      expect(error).toMatchObject({
        name: 'AtolBrowserAuthCleanupError',
        code: 'browser_auth_cleanup_failed',
        message: 'browser auth client cleanup failed',
      })
      expect(error).not.toHaveProperty('cause')
      expect(JSON.stringify(error)).not.toContain(sentinel)
      expect(String(error)).not.toContain(sentinel)
      if (!(error instanceof Error)) {
        throw new Error('expected a closed browser auth cleanup Error')
      }
      expect(error.stack).not.toContain(sentinel)
      expect(closeAttempts).toBe(1)

      expect(() => client.destroy()).not.toThrow()
      expect(closeAttempts).toBe(2)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('rejects an old callback before exchange after a missed logout signal and reload', async () => {
    const binding = {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    }
    const oldGeneration = credentialGenerationSnapshot(binding)
    rotateLogoutGeneration(binding)
    setCallbackCredentialGeneration(oldGeneration)
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    window.history.replaceState({}, '', '/cb?code=old&state=old')

    // A fresh client represents a reload that missed every in-memory or
    // BroadcastChannel logout signal. Persisted generation is authoritative.
    const reloaded = makeClient()
    await expect(reloaded.completeLogin()).rejects.toThrow(
      'OIDC callback failed. Please sign in again.',
    )

    expect(manager.signinRedirectCallback).toHaveBeenCalledTimes(1)
    expect(mockExchange).not.toHaveBeenCalled()
    expect(manager.storeUser).not.toHaveBeenCalled()
    reloaded.destroy()
  })

  it('completes a login redirect, establishes the session, and cleans the URL', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    const idToken = makeIDToken()
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idToken,
      refresh_token: 'rt_x',
    })

    const client = makeClient()
    const session = await client.init()

    expect(manager.signinRedirectCallback).toHaveBeenCalledTimes(1)
    expect(session.isAuthenticated).toBe(true)
    expect(session.user).toMatchObject({ id: 'user-1' })
    expect(session.user).not.toHaveProperty('orgId')
    expect(mockVerify).toHaveBeenCalledWith(idToken, {
      authority: ISSUER,
      clientId: CLIENT_ID,
      nonce: 'callback-nonce',
    })
    // URL cleaned: the code must not survive in the address bar.
    expect(window.location.search).toBe('')
    client.destroy()
  })

  it('cannot resurrect a callback grant superseded by logout', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    let releaseExchange:
      | ((tokens: ReturnType<typeof tokenResponse>) => void)
      | undefined
    mockExchange.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          releaseExchange = resolve
        }),
    )
    const client = makeClient()
    const initialization = client.init()
    await vi.waitFor(() => expect(mockExchange).toHaveBeenCalledTimes(1))

    await client.logout()
    releaseExchange?.(tokenResponse())

    await expect(initialization).rejects.toBeInstanceOf(
      OrdinaryAuthorizationPendingError,
    )
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('rejects and clears credentials when a stale callback fails', async () => {
    window.history.replaceState({}, '', '/cb?code=stale&state=old')
    manager.signinRedirectCallback.mockRejectedValue(new Error('no matching state'))

    const client = makeClient()
    await expect(client.init()).rejects.toThrow(/callback failed/i)
    expect(await client.getAccessToken()).toBeUndefined()
    expect(window.location.search).toBe('')
    client.destroy()
  })

  it('[R22] surfaces a failed callback instead of leaving the console pending forever', async () => {
    window.history.replaceState({}, '', '/cb?code=stale&state=old')
    manager.signinRedirectCallback.mockRejectedValue(new Error('no matching state'))

    const client = makeClient()
    await expect(client.init()).rejects.toThrow(/callback failed/i)
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('refuses a callback whose ID token fails signature or nonce validation', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    mockVerify.mockRejectedValue(new Error('nonce mismatch'))

    const client = makeClient()
    await expect(client.init()).rejects.toThrow(/callback failed/i)
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('[R08] sends the SDK DPoP signer through the interactive callback token exchange', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeOrgAccessToken(ORG_A),
      id_token: makeIDToken({ 'atol:org_id': ORG_A }),
      token_type: 'DPoP',
    })
    mockExchange.mockImplementation(async (...args) => {
      const signer = args[5] as unknown as { thumbprint: () => Promise<string> }
      return tokenResponse({
        access_token: makeOrgAccessToken(ORG_A, 3600, {
          cnf: { jkt: await signer.thumbprint() },
        }),
        id_token: makeIDToken({ 'atol:org_id': ORG_A }),
        token_type: 'DPoP',
      })
    })

    const client = makeClient(true)
    const session = await client.init()
    const firstRequest = await client.getAccessToken({
      dpop: { method: 'GET', url: 'https://api.atol.test/v1/me' },
    })
    const exchangeCalls = mockExchange.mock.calls.slice()
    client.destroy()

    // The interactive callback must use the same per-tab signer as silent
    // authorization so the first API request has a bound credential.
    expect(exchangeCalls).toHaveLength(1)
    expect(exchangeCalls[0]?.[5]).toBeTruthy()
    expect(session).toMatchObject({ isAuthenticated: true, organizationId: ORG_A })
    expect(firstRequest?.token).toBeTruthy()
    expect(firstRequest?.proof).toBeTruthy()
    expect(mockAuthorize).not.toHaveBeenCalled()
  })

  it('[R35] rejects a callback when the access token fails cryptographic validation', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    const accessToken = makeOrgAccessToken(ORG_A, 3600, {
      iss: 'https://attacker.test',
      aud: 'wrong-audience',
    })
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: accessToken,
      id_token: makeIDToken({ 'atol:org_id': ORG_A }),
    })
    mockAccessVerify.mockRejectedValueOnce(new Error('access token audience mismatch'))

    const client = makeClient()
    await expect(client.init()).rejects.toThrow(/callback failed/i)
    expect(mockAccessVerify).toHaveBeenCalledWith(accessToken, {
      authority: ISSUER,
      audience: ISSUER,
    })
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('[R08] refuses an unbound Bearer token returned to a DPoP callback', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeOrgAccessToken(ORG_A),
      id_token: makeIDToken({ 'atol:org_id': ORG_A }),
      token_type: 'bearer',
    })

    const client = makeClient(true)
    await expect(client.init()).rejects.toThrow(/callback failed/i)
    const token = await client.getAccessToken()
    client.destroy()

    expect(token).toBeUndefined()
  })

  it('[R08] refuses a DPoP token bound to a different tab key', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeOrgAccessToken(ORG_A, 3600, {
        cnf: { jkt: 'foreign-tab-thumbprint' },
      }),
      id_token: makeIDToken({ 'atol:org_id': ORG_A }),
      token_type: 'DPoP',
    })

    const client = makeClient(true)
    await expect(client.init()).rejects.toThrow(/callback failed/i)
    const token = await client.getAccessToken()
    client.destroy()

    expect(token).toBeUndefined()
  })
})

describe('createAtolBrowserAuth -- init (reload recovery)', () => {
  it('recovers the session via silent renew + store write-back', async () => {
    mockAuthorize.mockResolvedValue({
      code: 'silent',
      state: 's',
      codeVerifier: 'v',
      nonce: 'silent-nonce',
    })
    const response = tokenResponse()
    mockExchange.mockResolvedValue(response)

    const client = makeClient()
    const session = await client.init()

    expect(session.isAuthenticated).toBe(true)
    expect(session.user?.email).toBe('remi@example.test')
    const silentStart = ordinaryBeginSpy().mock.calls[0][0] as {
      nonce: string
    }
    expect(mockVerify).toHaveBeenCalledWith(response.id_token, {
      authority: ISSUER,
      clientId: CLIENT_ID,
      nonce: silentStart.nonce,
    })
    // The restored tokens must land in the UserManager store.
    expect(manager.storeUser).toHaveBeenCalled()
    client.destroy()
  })

  it('cannot resurrect a silent restore superseded by logout', async () => {
    let releaseAuthorization:
      | ((result: {
          code: string
          state: string
          codeVerifier: string
          nonce: string
        }) => void)
      | undefined
    mockAuthorize.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          releaseAuthorization = resolve
        }),
    )
    mockExchange.mockResolvedValueOnce(tokenResponse())
    const client = makeClient()
    const initialization = client.init()
    await vi.waitFor(() => expect(mockAuthorize).toHaveBeenCalledTimes(1))

    await client.logout()
    releaseAuthorization?.({
      code: 'silent',
      state: 'state',
      codeVerifier: 'verifier',
      nonce: 'nonce',
    })

    await expect(initialization).resolves.toMatchObject({
      isAuthenticated: false,
    })
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('settles unauthenticated when the IdP answers login_required', async () => {
    mockAuthorize.mockRejectedValue(new LoginRequiredError('login_required'))
    const client = makeClient()
    const session = await client.init()
    expect(session.isAuthenticated).toBe(false)
    client.destroy()
  })

  it('[R29] surfaces a transient cold-restore failure instead of pretending signed out', async () => {
    mockAuthorize.mockRejectedValue(new Error('authorization service unavailable'))
    const client = makeClient()

    await expect(client.init()).rejects.toThrow(/authorization service unavailable/)
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('fails init when DPoP is explicitly required but WebCrypto is unavailable', async () => {
    const savedCrypto = globalThis.crypto
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: undefined,
    })
    try {
      const client = makeClient({ required: true })
      await expect(client.init()).rejects.toThrow(/DPoP is required/)
      expect(client.isDPoPActive()).toBe(false)
      client.destroy()
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: savedCrypto,
      })
    }
  })

  it('retains the documented Bearer fallback for boolean dpop=true', async () => {
    const savedCrypto = globalThis.crypto
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: {
        getRandomValues: savedCrypto.getRandomValues.bind(savedCrypto),
      } as Crypto,
    })
    mockAuthorize.mockRejectedValue(new LoginRequiredError('login_required'))
    try {
      const client = makeClient(true)
      await expect(client.init()).resolves.toMatchObject({ isAuthenticated: false })
      expect(client.isDPoPActive()).toBe(false)
      client.destroy()
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: savedCrypto,
      })
    }
  })
})
