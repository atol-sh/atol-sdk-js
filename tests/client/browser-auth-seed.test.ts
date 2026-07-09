/**
 * seedTestSession: the test-only session bootstrap seam.
 *
 * These tests pin the security contract and the observable behavior of
 * `AtolBrowserAuth.seedTestSession`:
 *   - it is DENY-BY-DEFAULT: without `allowTestSessions:true` it throws, so an
 *     XSS payload in a production build cannot use it to forge a session
 *   - enabling it logs a one-time console.warn (accidental-enablement guard)
 *   - when enabled it adopts a raw token response through the real apply path:
 *     the session flips authenticated, the user is parsed from the id token,
 *     subscribers are notified, the token is retrievable, and the seeded
 *     session honors the memory-only refresh-token policy (RT dropped unless
 *     useRefreshTokens is set)
 *
 * Only the oidc-client-ts UserManager is stubbed (as in browser-auth.test.ts);
 * everything else -- userFromTokenResponse, claim parsing, applyTokens -- runs
 * for real. seedTestSession never calls init(), so no silent-renew / iframe
 * machinery is involved.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { makeAccessToken, makeIDToken, makeJWT } from '../helpers'

// Stub the oidc-client-ts UserManager wrapper only; keep the rest of the
// module (userFromTokenResponse, getAccessToken, getIdToken) real. The
// manager is rebuilt per test (freshManager in beforeEach) because the
// afterEach mock restore wipes vi.fn implementations -- same pattern as
// browser-auth.test.ts.
function freshManager() {
  return {
    signinRedirect: vi.fn().mockResolvedValue(undefined),
    signinRedirectCallback: vi.fn().mockResolvedValue(null),
    signoutRedirect: vi.fn().mockResolvedValue(undefined),
    getUser: vi.fn().mockResolvedValue(null),
    storeUser: vi.fn().mockResolvedValue(undefined),
    removeUser: vi.fn().mockResolvedValue(undefined),
  }
}

let manager: ReturnType<typeof freshManager>

vi.mock('../../src/oidc/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/oidc/oidc')>()
  return {
    ...actual,
    createUserManager: () => manager as unknown as object,
  }
})

// Stub the silent-renew iframe path (keep LoginRequiredError real for
// instanceof) so the init() tests below can drive the restore path without a
// real 60s-per-attempt hidden iframe, and assert it is SKIPPED when an
// initialTestSession is supplied.
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

import { createAtolBrowserAuth, type AtolSession } from '../../src/client/browser-auth'
import {
  silentAuthorizeWithRetry,
  LoginRequiredError,
  type TokenResponse,
} from '../../src/oidc/silent-renew'

const mockAuthorize = vi.mocked(silentAuthorizeWithRetry)

const ISSUER = 'https://auth.atol.test'
const CLIENT_ID = 'atol_kid_test'
const REDIRECT = 'https://app.test/cb'

function seedTokens(overrides: Partial<TokenResponse> = {}): TokenResponse {
  return {
    access_token: makeAccessToken(3600),
    id_token: makeIDToken(),
    refresh_token: 'rt-seed',
    token_type: 'Bearer',
    scope: 'openid profile email offline_access',
    expires_in: 3600,
    ...overrides,
  }
}

beforeEach(() => {
  manager = freshManager()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('seedTestSession security gate', () => {
  it('throws when allowTestSessions is unset (deny by default)', async () => {
    const auth = createAtolBrowserAuth({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT })
    await expect(auth.seedTestSession(seedTokens())).rejects.toThrow(/allowTestSessions/)
    auth.destroy()
  })

  it('throws when allowTestSessions is explicitly false', async () => {
    const auth = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      allowTestSessions: false,
    })
    await expect(auth.seedTestSession(seedTokens())).rejects.toThrow(/never be enabled in production/)
    auth.destroy()
  })

  it('does not warn on construction when disabled', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const auth = createAtolBrowserAuth({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT })
    expect(warn).not.toHaveBeenCalled()
    auth.destroy()
  })

  it('warns once on construction when enabled', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const auth = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      allowTestSessions: true,
    })
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]?.[0]).toMatch(/allowTestSessions is ENABLED/)
    auth.destroy()
  })
})

describe('seedTestSession when enabled', () => {
  function enabledClient() {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    return createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      allowTestSessions: true,
    })
  }

  it('flips to an authenticated session with the user parsed from the id token', async () => {
    const auth = enabledClient()
    const session = await auth.seedTestSession(seedTokens())
    expect(session.isAuthenticated).toBe(true)
    expect(session.user?.id).toBe('user-1')
    expect(session.user?.orgId).toBe('org-1')
    auth.destroy()
  })

  it('notifies onSessionChange subscribers of the authenticated session', async () => {
    const auth = enabledClient()
    const seen: AtolSession[] = []
    auth.onSessionChange((s) => seen.push(s)) // immediate fire: unauthenticated
    expect(seen.at(-1)?.isAuthenticated).toBe(false)

    await auth.seedTestSession(seedTokens())
    expect(seen.at(-1)?.isAuthenticated).toBe(true)
    expect(seen.at(-1)?.user?.id).toBe('user-1')
    auth.destroy()
  })

  it('makes the seeded access token retrievable via getAccessToken', async () => {
    const auth = enabledClient()
    const at = makeAccessToken(3600)
    await auth.seedTestSession(seedTokens({ access_token: at }))
    const res = await auth.getAccessToken()
    expect(res?.token).toBe(at)
    auth.destroy()
  })

  it('stores the seeded user in the (in-memory) token store', async () => {
    const auth = enabledClient()
    await auth.seedTestSession(seedTokens())
    expect(manager.storeUser).toHaveBeenCalledTimes(1)
    auth.destroy()
  })

  it('drops the refresh token in the default (iframe) renewal model', async () => {
    const auth = enabledClient()
    await auth.seedTestSession(seedTokens({ refresh_token: 'rt-should-be-dropped' }))
    const stored = manager.storeUser.mock.calls[0]?.[0] as { refresh_token?: string }
    expect(stored.refresh_token).toBeUndefined()
    auth.destroy()
  })

  it('retains the refresh token when useRefreshTokens is enabled', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const auth = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      allowTestSessions: true,
      useRefreshTokens: true,
    })
    await auth.seedTestSession(seedTokens({ refresh_token: 'rt-keep' }))
    const stored = manager.storeUser.mock.calls[0]?.[0] as { refresh_token?: string }
    expect(stored.refresh_token).toBe('rt-keep')
    auth.destroy()
  })

  it('stays unauthenticated when the token response carries no id token', async () => {
    const auth = enabledClient()
    const session = await auth.seedTestSession(seedTokens({ id_token: undefined }))
    expect(session.isAuthenticated).toBe(false)
    expect(session.user).toBeNull()
    auth.destroy()
  })

  it('warns when the seeded access token has no future exp', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const auth = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      allowTestSessions: true,
    })
    warn.mockClear() // drop the construction warn; assert only the seed warn
    // Access token with NO exp claim: scheduleRenew arms nothing, but the
    // client cannot confirm freshness, so a binding's getAccessToken would
    // drive an immediate renewal -- warn about it.
    const session = await auth.seedTestSession(seedTokens({ access_token: makeJWT({ sub: 'user-1' }) }))
    expect(session.isAuthenticated).toBe(true)
    expect(warn.mock.calls.some((c) => /future `exp`/.test(String(c[0])))).toBe(true)
    auth.destroy()
  })
})

describe('initialTestSession (adopt during init)', () => {
  it('settles init() authenticated and never touches the restore iframe', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const auth = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      allowTestSessions: true,
      initialTestSession: seedTokens(),
    })
    const session = await auth.init()
    expect(session.isAuthenticated).toBe(true)
    expect(session.user?.id).toBe('user-1')
    // The whole point: restore (the hidden-iframe silent authorize) is skipped.
    expect(mockAuthorize).not.toHaveBeenCalled()
    auth.destroy()
  })

  it('is ignored without allowTestSessions -- init runs the normal restore', async () => {
    // With the flag off, initialTestSession must NOT establish a session; init
    // falls through to restore, which here resolves login_required -> unauth.
    mockAuthorize.mockRejectedValueOnce(new LoginRequiredError('no idp session'))
    const auth = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      allowTestSessions: false,
      initialTestSession: seedTokens(),
    })
    const session = await auth.init()
    expect(session.isAuthenticated).toBe(false)
    expect(mockAuthorize).toHaveBeenCalledTimes(1)
    auth.destroy()
  })

  it('warns when the initial session access token has no future exp', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const auth = createAtolBrowserAuth({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      allowTestSessions: true,
      initialTestSession: seedTokens({ access_token: makeJWT({ sub: 'user-1' }) }),
    })
    warn.mockClear() // drop the construction warn
    await auth.init()
    expect(warn.mock.calls.some((c) => /future `exp`/.test(String(c[0])))).toBe(true)
    auth.destroy()
  })
})
