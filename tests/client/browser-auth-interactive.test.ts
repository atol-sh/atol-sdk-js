/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import { describe, expect, it, vi } from 'vitest'
import {
  LoginRequiredError,
  ORG_A,
  REDIRECT,
  makeAccessToken,
  makeClient,
  makeIDToken,
  makeJWT,
  makeOrgAccessToken,
  manager,
  mockAccessVerify,
  mockAuthorize,
  mockExchange,
  mockVerify,
  tokenResponse,
} from './browser-auth-harness'

describe('createAtolBrowserAuth -- beginLogin / completeLogin / signDPoPProof', () => {
  it('[R33] beginLogin creates a fresh OIDC nonce for the authorization transaction', async () => {
    const client = makeClient()
    await client.beginLogin()
    await client.beginLogin()

    const first = manager.signinRedirect.mock.calls[0][0] as { nonce?: string }
    const second = manager.signinRedirect.mock.calls[1][0] as { nonce?: string }
    expect(first.nonce).toMatch(/^[0-9a-f]{64}$/)
    expect(second.nonce).toMatch(/^[0-9a-f]{64}$/)
    expect(second.nonce).not.toBe(first.nonce)
    client.destroy()
  })

  it('binds each interactive authorization to a fresh canonical DPoP JKT', async () => {
    const client = makeClient({ required: true })
    await client.beginLogin()
    await client.beginLogin()

    const calls = manager.signinRedirect.mock.calls.map((call) => call[0] as {
      extraQueryParams: Record<string, string>
      state: { atol_browser_auth: Record<string, unknown> }
    })
    for (const call of calls) {
      expect(call.extraQueryParams.dpop_jkt).toMatch(
        /^[A-Za-z0-9_-]{43}$/,
      )
      expect(call.state.atol_browser_auth).not.toHaveProperty(
        'dpop_authorization',
      )
      expect(JSON.stringify(call)).not.toMatch(/privateKey|refresh_token|access_token|"d":/)
    }
    expect(calls[1].extraQueryParams.dpop_jkt).not.toBe(
      calls[0].extraQueryParams.dpop_jkt,
    )
    client.destroy()
  })

  it('redeems an interactive code only with its pre-navigation DPoP key', async () => {
    const client = makeClient({ required: true })
    await client.beginLogin()
    const redirect = manager.signinRedirect.mock.calls[0][0] as {
      extraQueryParams: Record<string, string>
    }
    const expectedJKT = redirect.extraQueryParams.dpop_jkt
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    mockExchange.mockImplementation(async (...args) => {
      const signer = args[5] as unknown as { thumbprint: () => Promise<string> }
      expect(await signer.thumbprint()).toBe(expectedJKT)
      return tokenResponse({
        access_token: makeJWT({
          sub: 'user-1',
          exp: Math.floor(Date.now() / 1000) + 3600,
          cnf: { jkt: expectedJKT },
        }),
        token_type: 'DPoP',
      })
    })

    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    await expect(client.completeLogin()).resolves.toMatchObject({
      isAuthenticated: true,
    })
    expect(client.isDPoPActive()).toBe(true)
    client.destroy()
  })

  it('rejects callback JKT substitution before code exchange', async () => {
    const client = makeClient({ required: true })
    await client.beginLogin()
    const redirect = manager.signinRedirect.mock.calls[0][0] as {
      extraQueryParams: Record<string, string>
    }
    const original = redirect.extraQueryParams.dpop_jkt
    redirect.extraQueryParams.dpop_jkt = original.replace(
      original[0],
      original[0] === 'A' ? 'B' : 'A',
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })

    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    await expect(client.completeLogin()).rejects.toThrow(/callback failed/i)
    expect(mockExchange).not.toHaveBeenCalled()
    client.destroy()
  })

  it('beginLogin always uses the registered redirect URI', async () => {
    const client = makeClient()
    await client.beginLogin()
    const args = manager.signinRedirect.mock.calls[0][0] as { redirect_uri: string }
    expect(args.redirect_uri).toBe(REDIRECT)
    client.destroy()
  })

  it('binds returnTo as application state without changing redirect_uri', async () => {
    const client = makeClient()
    await client.beginLogin({
      returnTo: '/organizations/../settings/security?tab=mfa#keys',
    })
    const args = manager.signinRedirect.mock.calls[0][0] as {
      redirect_uri: string
      extraQueryParams: Record<string, string>
      state: Record<string, unknown>
    }

    expect(args.redirect_uri).toBe(REDIRECT)
    expect(args.state).toEqual({
      atol_browser_auth: {
        logout_generation: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
        version: 1,
        return_to: '/settings/security?tab=mfa#keys',
        tab_owner_generation: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      },
    })
    expect(args.extraQueryParams).not.toHaveProperty('return_to')
    expect(args.extraQueryParams).not.toHaveProperty('redirect_uri')
    client.destroy()
  })

  it.each([
    'https://evil.test/steal',
    '//evil.test/steal',
    '/\\evil.test/steal',
  ])('rejects unsafe returnTo state before starting authorization: %s', async (returnTo) => {
    const client = makeClient()

    await expect(client.beginLogin({ returnTo })).rejects.toThrow(
      /same-origin absolute path/,
    )
    expect(manager.signinRedirect).not.toHaveBeenCalled()
    client.destroy()
  })

  it('applies returnTo only after the callback credentials are verified and committed', async () => {
    const client = makeClient()
    await client.beginLogin({ returnTo: '/settings/security?tab=mfa#keys' })
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    const popstate = vi.fn()
    window.addEventListener('popstate', popstate)
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')

    await expect(client.completeLogin()).resolves.toMatchObject({
      isAuthenticated: true,
    })

    expect(window.location.pathname).toBe('/settings/security')
    expect(window.location.search).toBe('?tab=mfa')
    expect(window.location.hash).toBe('#keys')
    expect(popstate).toHaveBeenCalledTimes(1)
    expect(mockAccessVerify.mock.invocationCallOrder[0]).toBeLessThan(
      popstate.mock.invocationCallOrder[0],
    )
    expect(mockVerify.mock.invocationCallOrder[0]).toBeLessThan(
      popstate.mock.invocationCallOrder[0],
    )
    expect(manager.storeUser.mock.invocationCallOrder[0]).toBeLessThan(
      popstate.mock.invocationCallOrder[0],
    )
    window.removeEventListener('popstate', popstate)
    client.destroy()
  })

  it('does not apply returnTo when callback validation fails', async () => {
    const client = makeClient()
    await client.beginLogin({ returnTo: '/settings/security' })
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    mockVerify.mockRejectedValue(new Error('nonce mismatch'))
    const popstate = vi.fn()
    window.addEventListener('popstate', popstate)
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')

    await expect(client.completeLogin()).rejects.toThrow(/callback failed/i)

    expect(window.location.pathname).toBe('/cb')
    expect(window.location.search).toBe('')
    expect(popstate).not.toHaveBeenCalled()
    window.removeEventListener('popstate', popstate)
    client.destroy()
  })

  it('beginLogin owns prompt / max_age / acr_values as dedicated authorize params', async () => {
    const client = makeClient()
    await client.beginLogin({ prompt: 'login', maxAge: 0, acrValues: 'mfa' })
    const args = manager.signinRedirect.mock.calls[0][0] as {
      extraQueryParams: Record<string, string>
      prompt: string
      max_age: number
      acr_values: string
    }
    expect(args.prompt).toBe('login')
    expect(args.max_age).toBe(0)
    expect(args.acr_values).toBe('mfa')
    expect(args.extraQueryParams).not.toHaveProperty('prompt')
    expect(args.extraQueryParams).not.toHaveProperty('max_age')
    expect(args.extraQueryParams).not.toHaveProperty('acr_values')
    client.destroy()
  })

  it('stepUp forces re-auth with prompt=login, max_age=0, acr_values=mfa by default', async () => {
    const client = makeClient()
    await client.stepUp()
    expect(manager.signinRedirect).toHaveBeenCalledTimes(1)
    const args = manager.signinRedirect.mock.calls[0][0] as {
      redirect_uri: string
      extraQueryParams: Record<string, string>
      prompt: string
      max_age: number
      acr_values: string
    }
    expect(args.redirect_uri).toBe(REDIRECT)
    expect(args.prompt).toBe('login')
    expect(args.max_age).toBe(0)
    expect(args.acr_values).toBe('mfa')
    expect(args.extraQueryParams).not.toHaveProperty('prompt')
    expect(args.extraQueryParams).not.toHaveProperty('max_age')
    expect(args.extraQueryParams).not.toHaveProperty('acr_values')
    client.destroy()
  })

  it('stepUp honors overrides for maxAge and acrValues', async () => {
    const client = makeClient()
    await client.stepUp({
      maxAge: 30,
      acrValues: 'urn:custom',
      returnTo: '/sensitive-operation',
    })
    const args = manager.signinRedirect.mock.calls[0][0] as {
      extraQueryParams: Record<string, string>
      max_age: number
      acr_values: string
      state: Record<string, unknown>
    }
    expect(args.max_age).toBe(30)
    expect(args.acr_values).toBe('urn:custom')
    expect(
      (args.state.atol_browser_auth as Record<string, unknown>).return_to,
    ).toBe('/sensitive-operation')
    client.destroy()
  })

  it('completeLogin is a no-op that returns the current session on a non-callback URL', async () => {
    const client = makeClient()
    const session = await client.completeLogin()
    expect(session.isAuthenticated).toBe(false)
    expect(manager.signinRedirectCallback).not.toHaveBeenCalled()
    client.destroy()
  })

  it('[R32] completeLogin initializes required DPoP before exchanging the code', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeOrgAccessToken(ORG_A),
      id_token: makeIDToken({ 'atol:org_id': ORG_A }),
    })
    mockExchange.mockImplementation(async (...args) => {
      const signer = args[5] as { thumbprint?: () => Promise<string> } | undefined
      if (!signer?.thumbprint) throw new Error('missing DPoP signer')
      return tokenResponse({
        access_token: makeOrgAccessToken(ORG_A, 3600, {
          cnf: { jkt: await signer.thumbprint() },
        }),
        id_token: makeIDToken({ 'atol:org_id': ORG_A }),
        token_type: 'DPoP',
      })
    })

    const client = makeClient({ required: true })
    const session = await client.completeLogin()
    const credential = await client.getAccessToken({
      dpop: { method: 'GET', url: 'https://api.atol.test/v1/me' },
    })

    expect(session).toMatchObject({ isAuthenticated: true, organizationId: ORG_A })
    expect(client.isDPoPActive()).toBe(true)
    expect(mockExchange.mock.calls[0]?.[5]).toBeTruthy()
    expect(credential?.proof).toBeTruthy()
    client.destroy()
  })

  it('[R32] completeLogin fails before exchange when required DPoP cannot initialize', async () => {
    const savedCrypto = globalThis.crypto
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined })
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    try {
      const client = makeClient({ required: true })
      await expect(client.completeLogin()).rejects.toThrow(/OIDC callback failed/)
      expect(mockExchange).not.toHaveBeenCalled()
      client.destroy()
    } finally {
      Object.defineProperty(globalThis, 'crypto', { configurable: true, value: savedCrypto })
    }
  })

  it('[R49] completeLogin owns bounded failure cleanup for direct callers', async () => {
    window.history.replaceState({}, '', '/cb?code=stale&state=old')
    manager.signinRedirectCallback.mockRejectedValue(new Error('secret upstream detail'))

    const client = makeClient()
    await expect(client.completeLogin()).rejects.toThrow(
      'OIDC callback failed. Please sign in again.',
    )
    expect(window.location.search).toBe('')
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('[R50] completeLogin is single-flight for a one-time callback state', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })

    const client = makeClient()
    const first = client.completeLogin()
    const second = client.completeLogin()

    const [firstSession, secondSession] = await Promise.all([first, second])
    expect(firstSession.isAuthenticated).toBe(true)
    expect(secondSession).toEqual(firstSession)
    expect(manager.signinRedirectCallback).toHaveBeenCalledTimes(1)
    expect(mockExchange).toHaveBeenCalledTimes(1)
    client.destroy()
  })

  it('[R51] destroy invalidates a credential transaction before it can commit', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    let releaseVerification!: () => void
    const verificationGate = new Promise<void>((resolve) => {
      releaseVerification = resolve
    })
    mockAccessVerify.mockImplementationOnce(async (token) => {
      await verificationGate
      return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString())
    })

    const client = makeClient()
    const completion = client.completeLogin()
    await vi.waitFor(() => expect(mockAccessVerify).toHaveBeenCalledTimes(1))
    client.destroy()
    releaseVerification()

    await expect(completion).rejects.toThrow(/callback failed|destroyed/i)
    expect(await client.getAccessToken()).toBeUndefined()
    expect(manager.storeUser).not.toHaveBeenCalled()
  })

  it('[R54] destroy cannot be undone by delayed DPoP initialization', async () => {
    const savedCrypto = globalThis.crypto
    let markStarted!: () => void
    let releaseGeneration!: () => void
    const generationStarted = new Promise<void>((resolve) => {
      markStarted = resolve
    })
    const generationGate = new Promise<void>((resolve) => {
      releaseGeneration = resolve
    })
    const delayedSubtle = new Proxy(savedCrypto.subtle, {
      get(target, property) {
        if (property === 'generateKey') {
          return async (...args: Parameters<SubtleCrypto['generateKey']>) => {
            markStarted()
            await generationGate
            return Reflect.apply(target.generateKey, target, args)
          }
        }
        const value = Reflect.get(target, property, target)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const delayedCrypto = {
      subtle: delayedSubtle,
      getRandomValues: savedCrypto.getRandomValues.bind(savedCrypto),
      randomUUID: savedCrypto.randomUUID.bind(savedCrypto),
    } as unknown as Crypto
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: delayedCrypto,
    })

    try {
      const client = makeClient(true)
      const initialization = client.init()
      await generationStarted
      client.destroy()
      releaseGeneration()

      await expect(initialization).rejects.toThrow()
      expect(client.isDPoPActive()).toBe(false)
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: savedCrypto,
      })
    }
  })

  it('signDPoPProof returns a bound proof when DPoP is active', async () => {
    const at = makeAccessToken(3600)
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({ access_token: at, id_token: makeIDToken() })
    const client = makeClient(true)
    await client.init()
    await vi.waitFor(() => expect(client.isDPoPActive()).toBe(true))

    const result = await client.signDPoPProof('POST', 'https://api.example.com/orders')
    expect(result?.token).toBeTruthy()
    expect(result?.token).not.toBe(at)
    expect(result?.proof).toBeTruthy()
    client.destroy()
  })

  it('does not return a token/proof snapshot superseded while signing', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(3600),
      id_token: makeIDToken(),
    })
    const client = makeClient(true)
    await client.init()

    const savedCrypto = globalThis.crypto
    let markSigning!: () => void
    let releaseSigning!: () => void
    const signingStarted = new Promise<void>((resolve) => {
      markSigning = resolve
    })
    const signingGate = new Promise<void>((resolve) => {
      releaseSigning = resolve
    })
    const delayedSubtle = new Proxy(savedCrypto.subtle, {
      get(target, property) {
        if (property === 'sign') {
          return async (...args: Parameters<SubtleCrypto['sign']>) => {
            markSigning()
            await signingGate
            return Reflect.apply(target.sign, target, args)
          }
        }
        const value = Reflect.get(target, property, target)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: {
        subtle: delayedSubtle,
        getRandomValues: savedCrypto.getRandomValues.bind(savedCrypto),
        randomUUID: savedCrypto.randomUUID.bind(savedCrypto),
      } as Crypto,
    })

    try {
      const snapshot = client.getAccessToken({
        dpop: { method: 'GET', url: 'https://api.example.com/me' },
      })
      await signingStarted
      client.destroy()
      releaseSigning()
      await expect(snapshot).rejects.toThrow(/superseded/)
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: savedCrypto,
      })
    }
  })

  it('signDPoPProof returns proof=undefined when DPoP is off (Bearer)', async () => {
    const at = makeAccessToken(3600)
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({ access_token: at, id_token: makeIDToken() })
    const client = makeClient(false)
    await client.init()
    expect(await client.signDPoPProof('GET', 'https://api.example.com/me')).toEqual({
      token: at,
      proof: undefined,
    })
    client.destroy()
  })

  it('signDPoPProof returns undefined when there is no session', async () => {
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    const client = makeClient(true)
    await client.init()
    expect(await client.signDPoPProof('GET', 'https://api.example.com/me')).toBeUndefined()
    client.destroy()
  })
})
