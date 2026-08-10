/**
 * Shared browser-auth test harness.
 *
 * Keeps UserManager, token endpoint, verification, storage, and WebCrypto
 * behavior identical across the lifecycle-focused regression suites.
 */

import 'fake-indexeddb/auto'
import {
  afterEach,
  beforeEach,
  vi,
} from 'vitest'
import { webcrypto as nodeWebCrypto } from 'node:crypto'
import {
  makeAccessToken as makeAccessTokenFixture,
  makeIDToken as makeIDTokenFixture,
  makeJWT as makeJWTFixture,
} from '../helpers'

const ordinaryBeginSpies = vi.hoisted(() => ({
  begin: vi.fn(),
}))

export function ordinaryBeginSpy(): ReturnType<typeof vi.fn> {
  return ordinaryBeginSpies.begin
}

// ---- Mock the oidc-client-ts UserManager wrapper. ----
type ManagerSpies = {
  signinRedirect: ReturnType<typeof vi.fn>
  signinRedirectCallback: ReturnType<typeof vi.fn>
  signoutRedirect: ReturnType<typeof vi.fn>
  signoutRedirectCallback: ReturnType<typeof vi.fn>
  getUser: ReturnType<typeof vi.fn>
  storeUser: ReturnType<typeof vi.fn>
  removeUser: ReturnType<typeof vi.fn>
}

export let manager: ManagerSpies
let callbackTokens: Record<string, unknown> | null = null
let callbackDPoPEnabled = false
type TestDPoPKeyManager = Awaited<
  ReturnType<
    typeof import('../../src/dpop/dpop')['createDPoPKeyManager']
  >
>
let callbackOrdinaryDPoP: TestDPoPKeyManager | null = null
let callbackClaimedDPoP: TestDPoPKeyManager | null = null
let callbackCompensationRequired = false
let callbackNonce = 'callback-nonce'
let callbackCredentialGeneration:
  | { logout: string; tabOwner: string }
  | undefined
let callbackRedirectUri = 'https://app.test/cb'
export const mockInvalidateOrdinarySignedOut = vi.fn<
  () => Promise<void>
>()

export function setCallbackCredentialGeneration(
  value: { logout: string; tabOwner: string } | undefined,
): void {
  callbackCredentialGeneration = value
}

function freshManager(): ManagerSpies {
  return {
    signinRedirect: vi.fn().mockResolvedValue(undefined),
    signinRedirectCallback: vi.fn().mockResolvedValue(null),
    signoutRedirect: vi.fn().mockResolvedValue(undefined),
    signoutRedirectCallback: vi.fn().mockResolvedValue({
      userState: undefined,
    }),
    getUser: vi.fn().mockResolvedValue(null),
    storeUser: vi.fn().mockResolvedValue(undefined),
    removeUser: vi.fn().mockResolvedValue(undefined),
  }
}

vi.mock('../../src/oidc/ordinary-authorization', async (importOriginal) => {
  const actual =
    await importOriginal<
      typeof import('../../src/oidc/ordinary-authorization')
    >()
  return {
    ...actual,
    OrdinaryBrowserAuthorization: class {
      private readonly binding: {
        scope: string
      }

      constructor(
        _manager: unknown,
        binding: { scope: string },
      ) {
        this.binding = binding
      }

      async begin(start: {
        intent: {
          extraQueryParams?: Record<string, string>
          prompt?: string
          maxAge?: number
          acrValues?: string
          dpopEnabled: boolean
          dpopRequired: boolean
        }
        nonce: string
        state: Record<string, unknown>
        createDPoPKey: () => Promise<
          Awaited<
            ReturnType<
              typeof import('../../src/dpop/dpop')['createDPoPKeyManager']
            >
          >
        >
      }, navigateAuthorization?: (url: string) => void) {
        ordinaryBeginSpies.begin(start, this.binding)
        callbackCompensationRequired = false
        callbackNonce = start.nonce
        callbackOrdinaryDPoP = start.intent.dpopEnabled
          ? await start.createDPoPKey()
          : null
        if (start.intent.dpopRequired && !callbackOrdinaryDPoP) {
          throw new Error(
            'DPoP is required but WebCrypto could not create an authorization key',
          )
        }
        const extraQueryParams = {
          ...(start.intent.extraQueryParams ?? {}),
          ...(callbackOrdinaryDPoP
            ? { dpop_jkt: await callbackOrdinaryDPoP.thumbprint() }
            : {}),
        }
        await manager.signinRedirect({
          redirect_uri: callbackRedirectUri,
          extraQueryParams,
          nonce: start.nonce,
          state: start.state,
          prompt: start.intent.prompt,
          max_age: start.intent.maxAge,
          acr_values: start.intent.acrValues,
        })
        navigateAuthorization?.(
          `${ISSUER}/auth/authorize?client_id=${CLIENT_ID}` +
            '&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A' +
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        )
      }

      async claimCallback() {
        if (
          !callbackOrdinaryDPoP &&
          callbackDPoPEnabled &&
          globalThis.crypto?.subtle
        ) {
          const { createDPoPKeyManager } = await import(
            '../../src/dpop/dpop'
          )
          callbackOrdinaryDPoP = await createDPoPKeyManager()
        }
        const dpopKey = callbackOrdinaryDPoP
        callbackOrdinaryDPoP = null
        callbackClaimedDPoP = dpopKey
        if (dpopKey) {
          const redirect = manager.signinRedirect.mock.calls.at(-1)?.[0] as
            | { extraQueryParams?: Record<string, string> }
            | undefined
          if (
            redirect &&
            redirect?.extraQueryParams?.dpop_jkt !==
            (await dpopKey.thumbprint())
          ) {
            throw new Error(
              'ordinary browser authorization: callback custody mismatch',
            )
          }
        }
        let settled = false
        const settle = vi.fn(async () => {
          settled = true
          callbackClaimedDPoP = null
          callbackCompensationRequired = false
        })
        return {
          dpopKey,
          compensationRequired: callbackCompensationRequired,
          markCodeIssued: vi.fn(async () => {
            callbackCompensationRequired = true
          }),
          complete: settle,
          discard: settle,
          release: vi.fn(async () => {
            if (settled) throw new Error('already settled')
            callbackOrdinaryDPoP = callbackClaimedDPoP
            callbackClaimedDPoP = null
            settled = true
          }),
        }
      }

      async finishPendingCleanup() {
        return false
      }

      async claimPendingCallback() {
        return null
      }

      async discardCallback() {
        callbackOrdinaryDPoP = null
        callbackClaimedDPoP = null
        callbackCompensationRequired = false
      }

      invalidateCurrent() {
        callbackOrdinaryDPoP = null
        callbackClaimedDPoP = null
        callbackCompensationRequired = false
        return Promise.resolve()
      }

      invalidateSignedOutLifecycle() {
        callbackOrdinaryDPoP = null
        callbackClaimedDPoP = null
        callbackCompensationRequired = false
        return mockInvalidateOrdinarySignedOut()
      }
    },
  }
})

vi.mock(
  '../../src/oidc/ordinary-authorization-exchange',
  async (importOriginal) => {
    const actual =
      await importOriginal<
        typeof import('../../src/oidc/ordinary-authorization-exchange')
      >()
    return {
      ...actual,
      compensateOrdinaryAuthorizationCode: vi.fn(
        async (
          _binding: unknown,
          custody: { discard(): Promise<void> },
        ) => custody.discard(),
      ),
    }
  },
)

vi.mock('../../src/oidc/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/oidc/oidc')>()
  return {
    ...actual,
    createUserManager: () => manager as unknown as object,
    readAuthorizationCodeResponseState: vi.fn(async (
      _manager: unknown,
      url: string,
    ) => {
      callbackTokens = await manager.signinRedirectCallback()
      const response = new URL(url)
      const lastRedirect = manager.signinRedirect.mock.calls.at(-1)?.[0] as
        | {
          state?: {
              atol_browser_auth?: {
                logout_generation?: string
                return_to?: string
                tab_owner_generation?: string
              }
            }
          }
        | undefined
      const browserState = lastRedirect?.state?.atol_browser_auth
      const credentialGeneration =
        callbackCredentialGeneration ??
        (typeof browserState?.logout_generation === 'string' &&
        typeof browserState.tab_owner_generation === 'string'
          ? {
              logout: browserState.logout_generation,
              tabOwner: browserState.tab_owner_generation,
            }
          : (
              await import('../../src/oidc/credential-generation')
            ).credentialGenerationSnapshot({
              issuer: ISSUER,
              clientId: CLIENT_ID,
              redirectUri: callbackRedirectUri,
            }))
      return {
        stateId:
          response.searchParams.get('state') ??
          '0123456789abcdef0123456789abcdef',
        stateStorage: '{"state":"test"}',
        stateCreatedAt: Math.floor(Date.now() / 1000),
        code: response.searchParams.get('code') ?? 'authcode',
        codeVerifier: 'verifier',
        codeChallenge: 'A'.repeat(43),
        credentialGeneration,
        redirectUri: callbackRedirectUri,
        nonce: callbackNonce,
        returnTo: lastRedirect?.state?.atol_browser_auth?.return_to,
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
    silentAuthorizeURL: vi.fn(),
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

import { createAtolBrowserAuth as createBrowserAuth } from '../../src/client/browser-auth'
import {
  silentAuthorizeURL,
  exchangeCode,
  refreshTokenGrant,
  revokeToken,
  LoginRequiredError as ActualLoginRequiredError,
} from '../../src/oidc/silent-renew'
import {
  compensateOrdinaryAuthorizationCode,
} from '../../src/oidc/ordinary-authorization-exchange'
import {
  OrdinaryAuthorizationPendingError as ActualOrdinaryAuthorizationPendingError,
} from '../../src/oidc/ordinary-authorization'
import { OAuthProtocolError as ActualOAuthProtocolError } from '../../src/oidc/token-recovery'

export const createAtolBrowserAuth = createBrowserAuth
export const LoginRequiredError = ActualLoginRequiredError
export const OAuthProtocolError = ActualOAuthProtocolError

export function makeAccessToken(inSeconds = 3600): string {
  return makeAccessTokenFixture(inSeconds)
}

export function makeIDToken(
  overrides: Record<string, unknown> = {},
): string {
  return makeIDTokenFixture(overrides)
}

export function makeJWT(payload: Record<string, unknown>): string {
  return makeJWTFixture(payload)
}

export const mockAuthorize = vi.mocked(silentAuthorizeURL)
export const mockExchange = vi.mocked(exchangeCode)
export const mockRefresh = vi.mocked(refreshTokenGrant)
export const mockRevoke = vi.mocked(revokeToken)
export const mockCompensate = vi.mocked(
  compensateOrdinaryAuthorizationCode,
)
export const mockAccessVerify = verifySpies.accessToken
export const mockVerify = verifySpies.idToken

export const ISSUER = 'https://auth.atol.test'
export const CLIENT_ID = 'atol_kid_test'
export const REDIRECT = 'https://app.test/cb'
export const ORG_A = '01KV4BNVVNZ4TNY0PP0CVXPZWP'
export const ORG_B = '01KV4BNVMVG66Q04WGMMD6W4PB'
export const ORG_C = '01KV4BNVQRYP9VKM2Q1Z8F6J5T'

export function makeOrgAccessToken(
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

export function organizationClaim(token: string | undefined): unknown {
  if (!token) return undefined
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString())['atol:org_id']
}

export function tokenResponse(over: Record<string, unknown> = {}) {
  return {
    access_token: makeAccessToken(),
    id_token: makeIDToken(),
    refresh_token: 'rt_initial',
    token_type: 'bearer',
    expires_in: 3600,
    ...over,
  }
}

export function makeClient(
  dpop: boolean | { required?: boolean } = false,
  useRefreshTokens = false,
  useRefreshTokensFallback = false,
  redirectUri = REDIRECT,
) {
  callbackRedirectUri = redirectUri
  callbackDPoPEnabled =
    dpop === true || (typeof dpop === 'object' && dpop.required === true)
  return createAtolBrowserAuth({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    redirectUri,
    dpop,
    useRefreshTokens,
    useRefreshTokensFallback,
  })
}

type BrowserAuthClient = ReturnType<typeof makeClient>
export type BrowserAuthSession = Awaited<ReturnType<BrowserAuthClient['init']>> & {
  organizationId?: string
}

beforeEach(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: nodeWebCrypto,
  })
  manager = freshManager()
  callbackTokens = null
  callbackOrdinaryDPoP = null
  callbackClaimedDPoP = null
  callbackCompensationRequired = false
  callbackNonce = 'callback-nonce'
  callbackCredentialGeneration = undefined
  callbackRedirectUri = REDIRECT
  mockInvalidateOrdinarySignedOut
    .mockReset()
    .mockResolvedValue(undefined)
  mockCompensate.mockImplementation(
    async (binding, custody, callback, dpop) => {
      try {
        await mockExchange(
          binding.issuer,
          binding.clientId,
          callback.code,
          callback.redirectUri,
          callback.codeVerifier,
          dpop ?? undefined,
        )
      } catch (error) {
        if (
          error instanceof ActualOAuthProtocolError &&
          error.code === 'invalid_grant'
        ) {
          await custody.discard()
          return
        }
        await custody.release()
        throw new ActualOrdinaryAuthorizationPendingError()
      }
      await custody.release()
      throw new ActualOrdinaryAuthorizationPendingError()
    },
  )
  ordinaryBeginSpies.begin.mockReset()
  mockExchange.mockImplementation(async (...args) => {
    if (!callbackTokens) {
      if (callbackCompensationRequired) {
        throw new ActualOAuthProtocolError('invalid_grant')
      }
      throw new Error('no callback token response configured')
    }
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
