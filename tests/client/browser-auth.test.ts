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
 *   - cross-tab broadcast: adopt only after signature+sub verification;
 *     forged / cross-user broadcasts are rejected
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
import { makeAccessToken, makeIDToken } from '../helpers'

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

// verify: broadcast authentication is stubbed so we can drive both the
// accept (sub matches) and reject (verify throws / sub mismatch) paths.
vi.mock('../../src/verify/verify', () => ({
  verifyIdToken: vi.fn(),
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
import { verifyIdToken } from '../../src/verify/verify'
import { OAuthProtocolError } from '../../src/oidc/token-recovery'

const mockAuthorize = vi.mocked(silentAuthorizeWithRetry)
const mockExchange = vi.mocked(exchangeCode)
const mockRefresh = vi.mocked(refreshTokenGrant)
const mockRevoke = vi.mocked(revokeToken)
const mockVerify = vi.mocked(verifyIdToken)

const ISSUER = 'https://auth.atol.test'
const CLIENT_ID = 'atol_kid_test'
const REDIRECT = 'https://app.test/cb'

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

beforeEach(() => {
  manager = freshManager()
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
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: makeIDToken(),
      refresh_token: 'rt_x',
    })

    const client = makeClient()
    const session = await client.init()

    expect(manager.signinRedirectCallback).toHaveBeenCalledTimes(1)
    expect(session.isAuthenticated).toBe(true)
    expect(session.user).toMatchObject({ id: 'user-1', orgId: 'org-1', roles: ['admin'] })
    // URL cleaned: the code must not survive in the address bar.
    expect(window.location.search).toBe('')
    client.destroy()
  })

  it('settles unauthenticated when a stale callback fails', async () => {
    window.history.replaceState({}, '', '/cb?code=stale&state=old')
    manager.signinRedirectCallback.mockRejectedValue(new Error('no matching state'))

    const client = makeClient()
    const session = await client.init()
    expect(session.isAuthenticated).toBe(false)
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- init (reload recovery)', () => {
  it('recovers the session via silent renew + store write-back', async () => {
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
    mockExchange.mockResolvedValue(tokenResponse())

    const client = makeClient()
    const session = await client.init()

    expect(session.isAuthenticated).toBe(true)
    expect(session.user?.email).toBe('remi@example.test')
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
    expect(res?.token).toBe(at)
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

  it('signDPoPProof returns a bound proof when DPoP is active', async () => {
    const at = makeAccessToken(3600)
    window.history.replaceState({}, '', '/cb?code=authcode&state=xyz')
    manager.signinRedirectCallback.mockResolvedValue({ access_token: at, id_token: makeIDToken() })
    const client = makeClient(true)
    await client.init()
    await vi.waitFor(() => expect(client.isDPoPActive()).toBe(true))

    const result = await client.signDPoPProof('POST', 'https://api.example.com/orders')
    expect(result?.token).toBe(at)
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
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
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
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
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
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
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
    // Any rotation broadcast omits the refresh token.
    const rotated = heard.filter((m) => m.type === 'token-rotated')
    expect(rotated.length).toBeGreaterThan(0)
    for (const m of rotated) {
      expect(m.refreshToken).toBeUndefined()
    }
    listener.close()
    client.destroy()
  })

  it('default: getAccessToken still returns a token and DPoP proof attaches', async () => {
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
    const at = makeAccessToken(3600)
    mockExchange.mockResolvedValue(tokenResponse({ access_token: at, refresh_token: undefined }))
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
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
    mockExchange.mockResolvedValue(tokenResponse())
    const client = makeClient(false, true)
    await client.init()

    const cfg = mockAuthorize.mock.calls[0][0] as { scope: string }
    expect(cfg.scope.split(' ')).toContain('offline_access')
    client.destroy()
  })

  it('useRefreshTokens: renewal uses the refresh grant and stores + broadcasts the RT', async () => {
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
    // Rotated RT stored back and broadcast to other tabs.
    const lastStore = manager.storeUser.mock.calls.at(-1)![0] as { refresh_token?: string }
    expect(lastStore.refresh_token).toBe('rt_two')
    const rotated = heard.filter((m) => m.type === 'token-rotated')
    expect(rotated.some((m) => m.refreshToken === 'rt_two')).toBe(true)
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
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
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
    mockAuthorize.mockResolvedValueOnce({ code: 'silent', state: 's', codeVerifier: 'v' })
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
    mockAuthorize.mockResolvedValueOnce({ code: 'silent2', state: 's', codeVerifier: 'v' })
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
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
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

  it('adopts rotated tokens after ID token verification + subject pinning', async () => {
    mockVerify.mockResolvedValue({ sub: 'user-1' } as never)
    // Refresh-token model: the shared RT rides the broadcast and is adopted.
    const client = await loggedInClient(false, true)
    manager.storeUser.mockClear()

    broadcast({
      type: 'token-rotated',
      accessToken: makeAccessToken(7200),
      idToken: makeIDToken(),
      refreshToken: 'rt_leader_shared',
      expiresAt: Date.now() + 7200_000,
      sentAt: Date.now(),
    })

    await vi.waitFor(() => {
      expect(manager.storeUser.mock.calls.length).toBeGreaterThan(0)
    })
    const stored = manager.storeUser.mock.calls.at(-1)![0] as { refresh_token?: string }
    // Non-DPoP: the shared refresh token IS adopted.
    expect(stored.refresh_token).toBe('rt_leader_shared')
    client.destroy()
  })

  it('rejects a broadcast whose ID token fails verification (forged channel)', async () => {
    mockVerify.mockRejectedValue(new Error('signature invalid'))
    const client = await loggedInClient(false)
    manager.storeUser.mockClear()

    broadcast({
      type: 'token-rotated',
      accessToken: makeAccessToken(7200),
      idToken: makeIDToken(),
      refreshToken: 'rt_forged',
      expiresAt: Date.now() + 7200_000,
      sentAt: Date.now(),
    })

    await new Promise((r) => setTimeout(r, 30))
    // The unverifiable token must NEVER be adopted.
    expect(manager.storeUser).not.toHaveBeenCalled()
    client.destroy()
  })

  it('rejects a broadcast for a different subject (identity pinning)', async () => {
    mockVerify.mockResolvedValue({ sub: 'attacker' } as never)
    const client = await loggedInClient(false)
    manager.storeUser.mockClear()

    broadcast({
      type: 'token-rotated',
      accessToken: makeAccessToken(7200),
      idToken: makeIDToken({ sub: 'attacker' }),
      refreshToken: 'rt_evil',
      expiresAt: Date.now() + 7200_000,
      sentAt: Date.now(),
    })

    await new Promise((r) => setTimeout(r, 30))
    expect(manager.storeUser).not.toHaveBeenCalled()
    client.destroy()
  })

  it('under DPoP, adopts the access token but DROPS the leader refresh token', async () => {
    mockVerify.mockResolvedValue({ sub: 'user-1' } as never)
    // Refresh-token model + DPoP: the RT would ride the broadcast, but the
    // DPoP branch drops it so the follower keeps its own key-bound token.
    const client = await loggedInClient(true, true)
    // Ensure DPoP is actually active before broadcasting.
    await vi.waitFor(() => expect(client.isDPoPActive()).toBe(true))
    manager.storeUser.mockClear()

    broadcast({
      type: 'token-rotated',
      accessToken: makeAccessToken(7200),
      idToken: makeIDToken(),
      refreshToken: 'rt_leader_bound',
      expiresAt: Date.now() + 7200_000,
      sentAt: Date.now(),
    })

    await vi.waitFor(() => {
      expect(manager.storeUser.mock.calls.length).toBeGreaterThan(0)
    })
    const stored = manager.storeUser.mock.calls.at(-1)![0] as { refresh_token?: string }
    // The leader's key-bound RT is dropped -- the follower keeps its own key.
    expect(stored.refresh_token).toBeUndefined()
    client.destroy()
  })
})
