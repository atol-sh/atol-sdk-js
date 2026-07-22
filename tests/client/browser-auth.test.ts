/**
 * createAtolBrowserAuth: the keystone config-driven browser auth client.
 *
 * These tests exercise the full lifecycle end-to-end against a mocked
 * oidc-client-ts UserManager and stubbed token/silent-renew/verify modules:
 *   - init: redirect-callback path and reload-recovery (silent renew) path
 *   - MEMORY-ONLY tokens (nothing in localStorage; only PKCE state in
 *     sessionStorage, which the real UserManager owns)
 *   - getAccessToken (fresh fast-path + DPoP-bound result)
 *   - logout: refresh-token revocation + RP-initiated end_session with
 *     id_token_hint
 *   - onSessionChange fires on login/logout
 *   - forceRenew rotation + store write-back
 *   - cross-tab broadcast: signal-only invalidation/logout, never credential
 *     transport
 */
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'
import { webcrypto as nodeWebCrypto } from 'node:crypto'
import { makeAccessToken, makeIDToken, makeJWT } from '../helpers'

// Real WebCrypto so the DPoP effect produces a live key manager.
const originalCrypto = globalThis.crypto
beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: nodeWebCrypto })
})
afterAll(() => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: originalCrypto })
})

// ---- Mock the oidc-client-ts UserManager wrapper. ----
type ManagerSpies = {
  signinRedirect: ReturnType<typeof vi.fn>
  signinRedirectCallback: ReturnType<typeof vi.fn>
  signoutRedirect: ReturnType<typeof vi.fn>
  getUser: ReturnType<typeof vi.fn>
  storeUser: ReturnType<typeof vi.fn>
  removeUser: ReturnType<typeof vi.fn>
}

let manager: ManagerSpies
let callbackTokens: Record<string, unknown> | null = null

function freshManager(): ManagerSpies {
  return {
    signinRedirect: vi.fn().mockResolvedValue(undefined),
    signinRedirectCallback: vi.fn().mockResolvedValue(null),
    signoutRedirect: vi.fn().mockResolvedValue(undefined),
    getUser: vi.fn().mockResolvedValue(null),
    storeUser: vi.fn().mockResolvedValue(undefined),
    removeUser: vi.fn().mockResolvedValue(undefined),
  }
}

vi.mock('../../src/oidc/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/oidc/oidc')>()
  return {
    ...actual,
    createUserManager: () => manager as unknown as object,
    readAuthorizationCodeCallback: vi.fn(async () => {
      callbackTokens = await manager.signinRedirectCallback()
      return {
        code: 'authcode',
        codeVerifier: 'verifier',
        redirectUri: REDIRECT,
        nonce: 'callback-nonce',
      }
    }),
    getAccessToken: (u: { access_token?: string } | null) => u?.access_token,
    getIdToken: (u: { id_token?: string } | null) => u?.id_token,
    userFromTokenResponse: (tokens: {
      access_token: string
      id_token?: string
      refresh_token?: string
    }) => ({
      access_token: tokens.access_token,
      id_token: tokens.id_token,
      refresh_token: tokens.refresh_token,
      expired: false,
    }),
  }
})

// Silent-renew: exchange/refresh/revoke controllable per-test; keep the real
// LoginRequiredError class so instanceof holds.
vi.mock('../../src/oidc/silent-renew', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/oidc/silent-renew')>()
  return {
    ...actual,
    silentAuthorizeWithRetry: vi.fn(),
    exchangeCode: vi.fn(),
    refreshTokenGrant: vi.fn(),
    revokeToken: vi.fn().mockResolvedValue(undefined),
  }
})

const verifySpies = vi.hoisted(() => ({
  accessToken: vi.fn(),
  idToken: vi.fn(),
}))

// Token verification is stubbed so callback/renewal tests can drive both
// accepted and rejected credential paths without a live JWKS endpoint.
vi.mock('../../src/verify/verify', () => ({
  verifyAccessToken: verifySpies.accessToken,
  verifyIdToken: verifySpies.idToken,
  _resetDiscoveryCache: vi.fn(),
}))

import { createAtolBrowserAuth } from '../../src/client/browser-auth'
import {
  silentAuthorizeWithRetry,
  exchangeCode,
  refreshTokenGrant,
  revokeToken,
  LoginRequiredError,
} from '../../src/oidc/silent-renew'
import { OAuthProtocolError } from '../../src/oidc/token-recovery'

const mockAuthorize = vi.mocked(silentAuthorizeWithRetry)
const mockExchange = vi.mocked(exchangeCode)
const mockRefresh = vi.mocked(refreshTokenGrant)
const mockRevoke = vi.mocked(revokeToken)
const mockAccessVerify = verifySpies.accessToken
const mockVerify = verifySpies.idToken

const ISSUER = 'https://auth.atol.test'
const CLIENT_ID = 'atol_kid_test'
const REDIRECT = 'https://app.test/cb'
const ORG_A = '01KV4BNVVNZ4TNY0PP0CVXPZWP'
const ORG_B = '01KV4BNVMVG66Q04WGMMD6W4PB'
const ORG_C = '01KV4BNVQRYP9VKM2Q1Z8F6J5T'

function makeOrgAccessToken(
  organizationId: string,
  inSeconds = 3600,
  overrides: Record<string, unknown> = {},
): string {
  return makeJWT({
    sub: 'user-1',
    exp: Math.floor(Date.now() / 1000) + inSeconds,
    'atol:org_id': organizationId,
    ...overrides,
  })
}

function organizationClaim(token: string | undefined): unknown {
  if (!token) return undefined
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString())['atol:org_id']
}

function tokenResponse(over: Record<string, unknown> = {}) {
  return {
    access_token: makeAccessToken(),
    id_token: makeIDToken(),
    refresh_token: 'rt_initial',
    token_type: 'bearer',
    expires_in: 3600,
    ...over,
  }
}

function makeClient(
  dpop: boolean | { required?: boolean } = false,
  useRefreshTokens = false,
  useRefreshTokensFallback = false,
) {
  return createAtolBrowserAuth({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT,
    dpop,
    useRefreshTokens,
    useRefreshTokensFallback,
  })
}

type BrowserAuthClient = ReturnType<typeof makeClient>
type BrowserAuthSession = Awaited<ReturnType<BrowserAuthClient['init']>> & {
  organizationId?: string
}

beforeEach(() => {
  manager = freshManager()
  callbackTokens = null
  mockExchange.mockImplementation(async (...args) => {
    if (!callbackTokens) throw new Error('no callback token response configured')
    const source = callbackTokens
    callbackTokens = null
    let accessToken = source.access_token as string
    let tokenType = (source.token_type as string | undefined) ?? 'bearer'
    const signer = args[5] as { thumbprint?: () => Promise<string> } | undefined
    // Most pre-existing DPoP tests predate response-binding validation and
    // omit token_type/cnf. Bind only those implicit fixtures. Tests that
    // explicitly return Bearer or a foreign DPoP binding remain adversarial.
    if (signer?.thumbprint && source.token_type === undefined) {
      const payload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString())
      accessToken = makeJWT({ ...payload, cnf: { jkt: await signer.thumbprint() } })
      tokenType = 'DPoP'
    }
    return {
      access_token: accessToken,
      id_token: source.id_token as string | undefined,
      refresh_token: source.refresh_token as string | undefined,
      token_type: tokenType,
      expires_in: 3600,
    }
  })
  mockVerify.mockImplementation(async (token, options) => {
    const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString())
    if (options.nonce !== undefined) claims.nonce = options.nonce
    return claims
  })
  mockAccessVerify.mockImplementation(async (token) =>
    JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()),
  )
  sessionStorage.clear()
  globalThis.localStorage?.clear()
  window.history.replaceState({}, '', '/')
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('createAtolBrowserAuth -- init (redirect callback)', () => {
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
    expect(mockVerify).toHaveBeenCalledWith(response.id_token, {
      authority: ISSUER,
      clientId: CLIENT_ID,
      nonce: 'silent-nonce',
    })
    // The restored tokens must land in the UserManager store.
    expect(manager.storeUser).toHaveBeenCalled()
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
      value: undefined,
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

describe('createAtolBrowserAuth -- MEMORY-ONLY tokens', () => {
  it('writes nothing to localStorage and no tokens to sessionStorage', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'rt_secret_value',
    })
    const client = makeClient()
    await client.init()

    expect(globalThis.localStorage?.length ?? 0).toBe(0)
    // Nothing token-shaped in sessionStorage (the real UserManager keeps
    // only PKCE state; here the mock stores nothing).
    const dump: string[] = []
    for (let i = 0; i < sessionStorage.length; i++) {
      dump.push(sessionStorage.getItem(sessionStorage.key(i)!) ?? '')
    }
    expect(dump.join('|')).not.toContain('rt_secret_value')
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- getAccessToken', () => {
  it('returns the current token on the fresh fast-path', async () => {
    const at = makeAccessToken(3600)
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({ access_token: at, id_token: makeIDToken() })
    const client = makeClient()
    await client.init()

    const res = await client.getAccessToken()
    expect(res?.token).toBe(at)
    expect(res?.proof).toBeUndefined()
    client.destroy()
  })

  it('returns a DPoP-bound proof when dpop is active and opts.dpop is passed', async () => {
    const at = makeAccessToken(3600)
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({ access_token: at, id_token: makeIDToken() })
    const client = makeClient(true)
    await client.init()
    expect(client.isDPoPActive()).toBe(true)

    const res = await client.getAccessToken({
      dpop: { method: 'GET', url: 'https://api.example.com/me' },
    })
    expect(res?.token).toBeTruthy()
    expect(res?.token).not.toBe(at)
    expect(
      JSON.parse(Buffer.from(res!.token.split('.')[1], 'base64url').toString()).cnf?.jkt,
    ).toBeTruthy()
    expect(res?.proof).toBeTruthy()
    // Proof is a dpop+jwt.
    const header = JSON.parse(
      Buffer.from(res!.proof!.split('.')[0], 'base64url').toString(),
    )
    expect(header.typ).toBe('dpop+jwt')
    client.destroy()
  })

  it('resolves undefined when there is no session', async () => {
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    const client = makeClient()
    await client.init()
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- getIdToken', () => {
  it('returns the current ID token after login and undefined after logout', async () => {
    const idToken = makeIDToken()
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idToken,
      refresh_token: 'rt',
    })
    manager.getUser.mockResolvedValue({ id_token: idToken })

    const client = makeClient(false, true)
    await client.init()
    // The raw ID token is readable so bindings can extract issuer-specific
    // claims (e.g. an encryption-key claim) without re-implementing storage.
    expect(client.getIdToken()).toBe(idToken)

    await client.logout()
    expect(client.getIdToken()).toBeUndefined()
    client.destroy()
  })

  it('returns undefined when there is no session', async () => {
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    const client = makeClient()
    await client.init()
    expect(client.getIdToken()).toBeUndefined()
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- logout', () => {
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

    // Refresh token revoked (RFC 7009) before local clear.
    expect(mockRevoke).toHaveBeenCalledWith(ISSUER, CLIENT_ID, 'rt_to_revoke')
    // RP-initiated end_session with id_token_hint + post_logout_redirect_uri.
    expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
    expect(manager.signoutRedirect.mock.calls[0][0]).toMatchObject({
      post_logout_redirect_uri: REDIRECT,
      id_token_hint: idToken,
    })
    client.destroy()
  })

  it('omits id_token_hint gracefully when no user is loaded', async () => {
    mockAuthorize.mockRejectedValue(new LoginRequiredError())
    const client = makeClient()
    await client.init()
    manager.getUser.mockResolvedValue(null)

    await client.logout()
    expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
    const args = manager.signoutRedirect.mock.calls[0][0] as Record<string, unknown>
    expect(args).toEqual({ post_logout_redirect_uri: REDIRECT })
    // No refresh token -> no revocation attempted.
    expect(mockRevoke).not.toHaveBeenCalled()
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- onSessionChange', () => {
  it('fires immediately with the current session and again on login', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    const client = makeClient()
    const seen: boolean[] = []
    const unsub = client.onSessionChange((s) => seen.push(s.isAuthenticated))
    // Immediate fire: unauthenticated.
    expect(seen[0]).toBe(false)

    await client.init()
    // Eventually reflects authenticated.
    expect(seen[seen.length - 1]).toBe(true)
    unsub()
    client.destroy()
  })

  it('fires on logout with an unauthenticated session', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'rt',
    })
    const client = makeClient()
    await client.init()
    let latest = true
    client.onSessionChange((s) => (latest = s.isAuthenticated))
    await client.logout()
    expect(latest).toBe(false)
    client.destroy()
  })
})

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

  it('beginLogin redirects to the authorize endpoint with a returnTo override', async () => {
    const client = makeClient()
    await client.beginLogin({ returnTo: '/dashboard' })
    expect(manager.signinRedirect).toHaveBeenCalledTimes(1)
    const args = manager.signinRedirect.mock.calls[0][0] as { redirect_uri: string }
    expect(args.redirect_uri).toBe(`${window.location.origin}/dashboard`)
    client.destroy()
  })

  it('beginLogin uses the configured redirectUri without a returnTo', async () => {
    const client = makeClient()
    await client.beginLogin()
    const args = manager.signinRedirect.mock.calls[0][0] as { redirect_uri: string }
    expect(args.redirect_uri).toBe(REDIRECT)
    client.destroy()
  })

  it('beginLogin forwards prompt / max_age / acr_values as authorize params', async () => {
    const client = makeClient()
    await client.beginLogin({ prompt: 'login', maxAge: 0, acrValues: 'mfa' })
    const args = manager.signinRedirect.mock.calls[0][0] as {
      extraQueryParams: Record<string, string>
    }
    expect(args.extraQueryParams.prompt).toBe('login')
    expect(args.extraQueryParams.max_age).toBe('0')
    expect(args.extraQueryParams.acr_values).toBe('mfa')
    client.destroy()
  })

  it('stepUp forces re-auth with prompt=login, max_age=0, acr_values=mfa by default', async () => {
    const client = makeClient()
    await client.stepUp({ returnTo: '/access' })
    expect(manager.signinRedirect).toHaveBeenCalledTimes(1)
    const args = manager.signinRedirect.mock.calls[0][0] as {
      redirect_uri: string
      extraQueryParams: Record<string, string>
    }
    expect(args.redirect_uri).toBe(`${window.location.origin}/access`)
    expect(args.extraQueryParams.prompt).toBe('login')
    expect(args.extraQueryParams.max_age).toBe('0')
    expect(args.extraQueryParams.acr_values).toBe('mfa')
    client.destroy()
  })

  it('stepUp honors overrides for maxAge and acrValues', async () => {
    const client = makeClient()
    await client.stepUp({ maxAge: 30, acrValues: 'urn:custom' })
    const args = manager.signinRedirect.mock.calls[0][0] as {
      extraQueryParams: Record<string, string>
    }
    expect(args.extraQueryParams.max_age).toBe('30')
    expect(args.extraQueryParams.acr_values).toBe('urn:custom')
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
    const cfg = mockAuthorize.mock.calls[0][0] as { scope: string }
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

    const cfg = mockAuthorize.mock.calls[0][0] as { scope: string }
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
    await client.init() // restore path -> renewViaIframe -> silentAuthorize
    const cfg = mockAuthorize.mock.calls[0][0] as { deriveEncryptionKey?: boolean }
    expect(cfg.deriveEncryptionKey).toBe(true)
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
    broadcast({ type: 'session-ended', sentAt: Date.now() })
    await vi.waitFor(async () => expect(await client.getAccessToken()).toBeUndefined())
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

describe('createAtolBrowserAuth -- organization credential context', () => {
  async function loggedInForOrganization(organizationId: string) {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeOrgAccessToken(organizationId),
      id_token: makeIDToken({ 'atol:org_id': organizationId }),
    })
    const client = makeClient()
    await client.init()
    window.history.replaceState({}, '', '/')
    return client
  }

  it('[R10] rejects non-canonical organization claims from real token responses', async () => {
    const nonCanonical = ORG_A.toLowerCase()
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeOrgAccessToken(nonCanonical),
      id_token: makeIDToken({ 'atol:org_id': nonCanonical }),
    })

    const client = makeClient()
    await expect(client.completeLogin()).rejects.toThrow(/OIDC callback failed/)
    let session!: BrowserAuthSession
    const unsubscribe = client.onSessionChange((value) => {
      session = value as BrowserAuthSession
    })
    unsubscribe()

    expect(session.isAuthenticated).toBe(false)
    expect(await client.getAccessToken()).toBeUndefined()
    client.destroy()
  })

  it('[R36] rejects a ULID whose high prefix cannot encode 128 bits', async () => {
    const client = await loggedInForOrganization(ORG_A)
    mockAuthorize.mockClear()

    await expect(
      client.selectOrganization(`8${ORG_B.slice(1)}`),
    ).rejects.toThrow(/canonical ULID/)
    expect(mockAuthorize).not.toHaveBeenCalled()
    client.destroy()
  })

  it('[R10] does not let a generic renewal silently scope an unscoped session', async () => {
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
    })
    const client = makeClient()
    await client.init()
    window.history.replaceState({}, '', '/')

    mockAuthorize.mockResolvedValue({ code: 'generic', state: 's', codeVerifier: 'v', nonce: 'nonce-v' })
    mockExchange.mockResolvedValue(
      tokenResponse({
        access_token: makeOrgAccessToken(ORG_A),
        id_token: makeIDToken({ 'atol:org_id': ORG_A }),
      }),
    )

    await expect(client.forceRenew()).rejects.toThrow(/requested organization/)
    expect(organizationClaim((await client.getAccessToken())?.token)).toBeUndefined()
    expect(organizationClaim(client.getIdToken())).toBeUndefined()
    client.destroy()
  })

  it('[R10] starts a distinct organization grant and ignores an older generic renewal result', async () => {
    const client = await loggedInForOrganization(ORG_A)
    let resolveGenericAuthorize:
      | ((result: { code: string; state: string; codeVerifier: string; nonce: string }) => void)
      | undefined
    mockAuthorize
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveGenericAuthorize = resolve
          }),
      )
      .mockResolvedValueOnce({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    mockExchange.mockImplementation(async (_authority, _clientId, code) =>
      tokenResponse(
        code === 'organization-b'
          ? {
              access_token: makeOrgAccessToken(ORG_B),
              id_token: makeIDToken({ 'atol:org_id': ORG_B }),
            }
          : {
              access_token: makeOrgAccessToken(ORG_A),
              id_token: makeIDToken({ 'atol:org_id': ORG_A }),
            },
      ),
    )

    const genericRenewal = client.forceRenew()
    await vi.waitFor(() => expect(mockAuthorize).toHaveBeenCalledTimes(1))
    const selection = client.selectOrganization(ORG_B)
    await new Promise((resolve) => setTimeout(resolve, 0))
    const authorizeCallsBeforeGenericCompletes = mockAuthorize.mock.calls.length

    resolveGenericAuthorize!({ code: 'generic-a', state: 's-a', codeVerifier: 'v-a', nonce: 'nonce-v-a' })
    const [, selectionResult] = await Promise.allSettled([genericRenewal, selection])
    let finalSession!: BrowserAuthSession
    const unsubscribe = client.onSessionChange((value) => {
      finalSession = value as BrowserAuthSession
    })
    unsubscribe()
    const finalAccessToken = (await client.getAccessToken())?.token
    const finalIdToken = client.getIdToken()
    client.destroy()

    expect(authorizeCallsBeforeGenericCompletes).toBe(2)
    expect(selectionResult.status).toBe('fulfilled')
    expect(
      selectionResult.status === 'fulfilled' ? selectionResult.value.organizationId : undefined,
    ).toBe(ORG_B)
    expect(finalSession.organizationId).toBe(ORG_B)
    expect(organizationClaim(finalAccessToken)).toBe(ORG_B)
    expect(organizationClaim(finalIdToken)).toBe(ORG_B)
  })

  it('[R10] commits only the latest of two organization selections completed out of order', async () => {
    const client = await loggedInForOrganization(ORG_A)
    let resolveFirstAuthorize:
      | ((result: { code: string; state: string; codeVerifier: string; nonce: string }) => void)
      | undefined
    mockAuthorize
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveFirstAuthorize = resolve
          }),
      )
      .mockResolvedValueOnce({ code: 'organization-c', state: 's-c', codeVerifier: 'v-c', nonce: 'nonce-v-c' })
    mockExchange.mockImplementation(async (_authority, _clientId, code) => {
      const organizationId = code === 'organization-c' ? ORG_C : ORG_B
      return tokenResponse({
        access_token: makeOrgAccessToken(organizationId),
        id_token: makeIDToken({ 'atol:org_id': organizationId }),
      })
    })

    const firstSelection = client.selectOrganization(ORG_B)
    await vi.waitFor(() => expect(mockAuthorize).toHaveBeenCalledTimes(1))
    const latestSelection = client.selectOrganization(ORG_C)
    const latestSession = await latestSelection
    resolveFirstAuthorize!({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    const firstResult = await Promise.allSettled([firstSelection])

    let finalSession!: BrowserAuthSession
    const unsubscribe = client.onSessionChange((value) => {
      finalSession = value as BrowserAuthSession
    })
    unsubscribe()
    const finalAccessToken = (await client.getAccessToken())?.token
    const finalIdToken = client.getIdToken()
    client.destroy()

    expect(firstResult[0]?.status).toBe('rejected')
    expect(latestSession.organizationId).toBe(ORG_C)
    expect(finalSession.organizationId).toBe(ORG_C)
    expect(organizationClaim(finalAccessToken)).toBe(ORG_C)
    expect(organizationClaim(finalIdToken)).toBe(ORG_C)
  })

  it('[R10] rejects mismatched access and ID token organizations without a partial update', async () => {
    const client = await loggedInForOrganization(ORG_A)
    mockAuthorize.mockResolvedValue({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    mockExchange.mockResolvedValue(
      tokenResponse({
        access_token: makeOrgAccessToken(ORG_B),
        id_token: makeIDToken({ 'atol:org_id': ORG_A }),
      }),
    )

    let selectionError: unknown
    try {
      await client.selectOrganization(ORG_B)
    } catch (error) {
      selectionError = error
    }
    const finalAccessToken = (await client.getAccessToken())?.token
    const finalIdToken = client.getIdToken()
    client.destroy()

    expect(selectionError).toBeInstanceOf(Error)
    expect((selectionError as Error | undefined)?.message).toMatch(/organization.*mismatch/i)
    expect(organizationClaim(finalAccessToken)).toBe(ORG_A)
    expect(organizationClaim(finalIdToken)).toBe(ORG_A)
  })

  it('[R10] exposes the selected organization once as credential context, not user identity', async () => {
    const client = await loggedInForOrganization(ORG_A)
    mockAuthorize.mockResolvedValue({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    mockExchange.mockResolvedValue(
      tokenResponse({
        access_token: makeOrgAccessToken(ORG_B),
        id_token: makeIDToken({ 'atol:org_id': ORG_B }),
      }),
    )

    const selected = await client.selectOrganization(ORG_B)
    const authorizeOptions = mockAuthorize.mock.calls.at(-1)?.[0] as
      | { organizationId?: string }
      | undefined
    const accessToken = (await client.getAccessToken())?.token
    const idToken = client.getIdToken()
    const user = selected.user as unknown as Record<string, unknown>
    client.destroy()

    expect(authorizeOptions?.organizationId).toBe(ORG_B)
    expect(selected.organizationId).toBe(ORG_B)
    expect(organizationClaim(accessToken)).toBe(ORG_B)
    expect(organizationClaim(idToken)).toBe(ORG_B)
    expect(user.orgId).toBeUndefined()
    expect(user.roles).toBeUndefined()
    expect(user.plan).toBeUndefined()
  })

  it('[R31] rejects an organization grant that changes the authenticated subject', async () => {
    const client = await loggedInForOrganization(ORG_A)
    mockAuthorize.mockResolvedValue({ code: 'organization-b', state: 's-b', codeVerifier: 'v-b', nonce: 'nonce-v-b' })
    mockExchange.mockResolvedValue(
      tokenResponse({
        access_token: makeOrgAccessToken(ORG_B, 3600, { sub: 'user-2' }),
        id_token: makeIDToken({ sub: 'user-2', 'atol:org_id': ORG_B }),
      }),
    )

    await expect(client.selectOrganization(ORG_B)).rejects.toThrow(/subject/i)
    let finalSession!: BrowserAuthSession
    const unsubscribe = client.onSessionChange((value) => {
      finalSession = value as BrowserAuthSession
    })
    unsubscribe()
    const finalAccessToken = (await client.getAccessToken())?.token
    client.destroy()

    expect(finalSession.user?.id).toBe('user-1')
    expect(finalSession.organizationId).toBe(ORG_A)
    expect(organizationClaim(finalAccessToken)).toBe(ORG_A)
  })
})
