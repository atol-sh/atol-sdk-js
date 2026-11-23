/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.test/"}
 */

import 'fake-indexeddb/auto'
import { webcrypto as nodeWebCrypto } from 'node:crypto'
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
import { bytesToBase64Url } from '../../src/crypto/base64url'
import { createDPoPKeyManager } from '../../src/dpop/dpop'
import {
  OrdinaryAuthorizationIntentConflictError,
  OrdinaryAuthorizationPendingError,
  createAtolBrowserAuth,
} from '../../src/index'
import {
  credentialGenerationForLogin,
  rotateLogoutGeneration,
  type CredentialGenerationSnapshot,
} from '../../src/oidc/credential-generation'
import {
  OrdinaryBrowserAuthorization,
  type OrdinaryAuthorizationStart,
} from '../../src/oidc/ordinary-authorization'
import {
  authorizationState,
  createUserManager,
  readAuthorizationCodeResponseState,
} from '../../src/oidc/oidc'
import { generateAuthorizationNonce } from '../../src/oidc/silent-renew'
import {
  browserVisibleOrdinaryResponse,
  installOrdinaryAuthorizationLocks,
  ordinaryAttemptChallenge,
} from './ordinary-authorization-test-support'

const ISSUER = 'https://auth.atol.test'
const CLIENT_ID = 'atol_kid_test'
const REDIRECT_URI = 'https://app.test/cb'
const SCOPE = 'openid profile email'
const REQUEST_URI = `urn:ietf:params:oauth:request_uri:${bytesToBase64Url(
  new Uint8Array(32).fill(7),
)}`
const originalCrypto = globalThis.crypto
const originalFetch = globalThis.fetch

function terminalProof(rootExpiresAtMs: number): string {
  const raw = new Uint8Array(58)
  raw[0] = 1
  raw[1] = 1
  let deadline = BigInt(rootExpiresAtMs) * 1_000_000n
  for (let index = 25; index >= 18; index--) {
    raw[index] = Number(deadline & 0xffn)
    deadline >>= 8n
  }
  return bytesToBase64Url(raw)
}

interface Harness {
  manager: ReturnType<typeof createUserManager>
  authorization: OrdinaryBrowserAuthorization
  navigations: string[]
  generation: CredentialGenerationSnapshot
}

function deleteDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase('atol-sdk-browser-auth')
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () =>
      reject(new Error('ordinary authorization test database is blocked'))
  })
}

function discovery(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/auth/authorize`,
    token_endpoint: `${ISSUER}/auth/token`,
    pushed_authorization_request_endpoint: `${ISSUER}/auth/par`,
    require_pushed_authorization_requests: true,
    atol_browser_authorization: {
      version: 2,
      ceremony_lifetime_seconds: 900,
      authorization_code_lifetime_seconds: 600,
      pre_navigation_cancellation_endpoint:
        `${ISSUER}/auth/par/pre-navigation-cancellation`,
      settlement_endpoint: `${ISSUER}/auth/par/settlement`,
    },
    ...overrides,
  }
}

function admittedResponse(
  rootExpiresAtMs: number,
  overrides: Record<string, unknown> = {},
): Response {
  return new Response(
    JSON.stringify({
      request_uri: REQUEST_URI,
      expires_in: 900,
      authorization_code_expires_in: 600,
      atol_browser_authorization_version: 2,
      atol_browser_authorization_expires_at: new Date(
        rootExpiresAtMs,
      ).toISOString(),
      terminal_proof: terminalProof(rootExpiresAtMs),
      ...overrides,
    }),
    {
      status: 201,
      headers: {
        'Access-Control-Allow-Origin': 'https://app.test',
        'Access-Control-Expose-Headers':
          'Atol-Browser-Authorization',
        'Atol-Browser-Authorization': 'v2',
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json',
        Vary: 'Origin',
      },
    },
  )
}

function installTransport(
  par: Array<Response | Error>,
  metadata: Record<string, unknown> = discovery(),
  cancellationResponses: Response[] = [],
): ReturnType<typeof vi.fn> {
  let parIndex = 0
  const transport = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/.well-known/openid-configuration')) {
        return new Response(JSON.stringify(metadata), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (url === `${ISSUER}/auth/par`) {
        const result = par[parIndex++]
        if (result instanceof Error) throw result
        if (!result) throw new Error('unexpected PAR request')
        return browserVisibleOrdinaryResponse(result)
      }
      if (
        url ===
        `${ISSUER}/auth/par/pre-navigation-cancellation`
      ) {
        return browserVisibleOrdinaryResponse(
          cancellationResponses.shift() ?? new Response(null, {
            status: 204,
            headers: {
              'Access-Control-Allow-Origin': 'https://app.test',
              'Access-Control-Expose-Headers':
                'Atol-Browser-Authorization',
              'Atol-Browser-Authorization': 'v2',
              'Cache-Control': 'no-store',
              Vary: 'Origin',
            },
          }),
        )
      }
      if (url === `${ISSUER}/auth/par/settlement`) {
        const body = JSON.parse(String(init?.body)) as {
          mode?: unknown
        }
        if (body.mode === 'reject') {
          return browserVisibleOrdinaryResponse(
            new Response(null, {
              status: 204,
              headers: {
                'Access-Control-Allow-Origin':
                  'https://app.test',
                'Access-Control-Expose-Headers':
                  'Atol-Browser-Authorization',
                'Atol-Browser-Authorization': 'v2',
                'Cache-Control': 'no-store',
                Vary: 'Origin',
              },
            }),
          )
        }
        return browserVisibleOrdinaryResponse(
          new Response(
            JSON.stringify({ error: 'authorization_terminal' }),
            {
              status: 410,
              headers: {
                'Access-Control-Allow-Origin':
                  'https://app.test',
                'Access-Control-Expose-Headers':
                  'Atol-Browser-Authorization',
                'Atol-Browser-Authorization': 'v2',
                'Cache-Control': 'no-store',
                'Content-Type': 'application/json',
                Vary: 'Origin',
              },
            },
          ),
        )
      }
      throw new Error(`unexpected request: ${url} ${init?.method ?? 'GET'}`)
    },
  )
  vi.stubGlobal('fetch', transport)
  return transport
}

function harness(scope = SCOPE): Harness {
  const manager = createUserManager(
    ISSUER,
    CLIENT_ID,
    REDIRECT_URI,
    scope,
    'https://api.atol.test',
  )
  const navigations: string[] = []
  const authorization = new OrdinaryBrowserAuthorization(
    manager,
    {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      scope,
    },
    (url) => navigations.push(url),
  )
  const generation = credentialGenerationForLogin({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
  })
  return { manager, authorization, navigations, generation }
}

function start(
  generation: CredentialGenerationSnapshot,
  overrides: Partial<OrdinaryAuthorizationStart['intent']> = {},
): OrdinaryAuthorizationStart {
  const returnTo = overrides.returnTo ?? '/settings/security'
  return {
    intent: {
      returnTo,
      extraQueryParams: { audience: 'https://api.atol.test' },
      dpopEnabled: true,
      dpopRequired: true,
      ...overrides,
    },
    credentialGeneration: generation,
    nonce: generateAuthorizationNonce(),
    state: authorizationState(returnTo, generation),
    createDPoPKey: createDPoPKeyManager,
  }
}

function parCalls(
  transport: ReturnType<typeof vi.fn>,
): Array<[RequestInfo | URL, RequestInit]> {
  return transport.mock.calls.filter(
    (call) => String(call[0]) === `${ISSUER}/auth/par`,
  ) as Array<[RequestInfo | URL, RequestInit]>
}

function pointerValue(): Record<string, unknown> {
  for (let index = 0; index < sessionStorage.length; index++) {
    const key = sessionStorage.key(index)
    if (key?.includes('ordinary-authorization')) {
      return JSON.parse(sessionStorage.getItem(key) as string) as Record<
        string,
        unknown
      >
    }
  }
  throw new Error('ordinary authorization pointer is missing')
}

function createPublicOrdinaryClient() {
  return createAtolBrowserAuth({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scopes: SCOPE,
  })
}

beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: nodeWebCrypto,
  })
})

beforeEach(async () => {
  installOrdinaryAuthorizationLocks()
  await deleteDatabase()
  localStorage.clear()
  sessionStorage.clear()
  window.history.replaceState({}, '', '/')
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

afterAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: originalCrypto,
  })
  Object.defineProperty(globalThis, 'fetch', {
    configurable: true,
    value: originalFetch,
  })
})

describe('ordinary browser PAR authorization custody', () => {
  it('persists exact OIDC/PKCE/DPoP custody before PAR and navigates with only server authority', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const rootExpiresAt = now + 15 * 60 * 1000
    const transport = installTransport([
      ordinaryAttemptChallenge(rootExpiresAt),
      admittedResponse(rootExpiresAt),
    ])
    const flow = harness()

    await flow.authorization.begin(start(flow.generation))

    const calls = parCalls(transport)
    expect(calls).toHaveLength(2)
    expect(calls[0][1]).toMatchObject({
      method: 'POST',
      body: expect.any(String),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    })
    expect(calls[0][1].headers).toEqual({
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    })
    const form = new URLSearchParams(calls[0][1].body as string)
    expect(Object.fromEntries(form)).toMatchObject({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      state: expect.stringMatching(/^[0-9a-f]{32}$/),
      nonce: expect.stringMatching(/^[0-9a-f]{64}$/),
      code_challenge: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      code_challenge_method: 'S256',
      dpop_jkt: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      audience: 'https://api.atol.test',
    })
    expect(flow.navigations).toHaveLength(1)
    const navigation = new URL(flow.navigations[0])
    expect(navigation.origin + navigation.pathname).toBe(
      `${ISSUER}/auth/authorize`,
    )
    expect(Array.from(navigation.searchParams.keys())).toEqual([
      'client_id',
      'request_uri',
    ])
    expect(navigation.searchParams.get('client_id')).toBe(CLIENT_ID)
    expect(navigation.searchParams.get('request_uri')).toBe(REQUEST_URI)

    const pointer = pointerValue()
    expect(pointer).toEqual({
      version: 1,
      stateId: form.get('state'),
      tabOwnerGeneration: flow.generation.tabOwner,
    })
    expect(JSON.stringify(pointer)).not.toContain(form.get('nonce'))
    expect(JSON.stringify(pointer)).not.toContain(form.get('code_challenge'))
    expect(JSON.stringify(pointer)).not.toContain(form.get('dpop_jkt'))

    const callback = await readAuthorizationCodeResponseState(
      flow.manager,
      `${REDIRECT_URI}?code=auth-code&state=${form.get('state')}`,
    )
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    expect(await custody.dpopKey?.thumbprint()).toBe(form.get('dpop_jkt'))
    await custody.complete()
  })

  it('replays an ambiguous POST with the exact state, PKCE, nonce, form, and key after reload', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installTransport([
      new TypeError('lost response'),
      ordinaryAttemptChallenge(now + 14 * 60 * 1000),
      admittedResponse(now + 14 * 60 * 1000),
    ])
    const first = harness()
    const firstStart = start(first.generation)

    await expect(
      first.authorization.begin(firstStart),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    expect(first.navigations).toEqual([])
    const firstBody = parCalls(transport)[0][1].body

    const reloaded = harness()
    await reloaded.authorization.begin(start(reloaded.generation))

    const calls = parCalls(transport)
    expect(calls).toHaveLength(3)
    expect(calls[1][1].body).toBe(firstBody)
    const retried = new URLSearchParams(
      String(calls[2][1].body),
    )
    expect(retried.has('atol_attempt_capability')).toBe(true)
    retried.delete('atol_attempt_capability')
    expect(retried.toString()).toBe(firstBody)
    expect(reloaded.navigations).toHaveLength(1)
  })

  it('preserves uncertain authority and rejects changed intent or registration instead of minting a fresh grant', async () => {
    const transport = installTransport([new TypeError('lost response')])
    const flow = harness()
    await expect(
      flow.authorization.begin(start(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    const originalBody = parCalls(transport)[0][1].body

    await expect(
      flow.authorization.begin(
        start(flow.generation, { returnTo: '/different' }),
      ),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationIntentConflictError)
    const changedRegistration = harness('openid email')
    await expect(
      changedRegistration.authorization.begin(
        start(changedRegistration.generation),
      ),
    ).rejects.toThrow(/custody binding mismatch/)

    expect(parCalls(transport)).toHaveLength(1)
    expect(parCalls(transport)[0][1].body).toBe(originalBody)
  })

  it.each(['silent', 'interactive'] as const)(
    'reports a pending %s sign-in when startup and interactive intents conflict',
    async (pendingMode) => {
      const now = 1_800_000_000_000
      vi.spyOn(Date, 'now').mockReturnValue(now)
      const transport = installTransport([
        new TypeError('lost response'),
        ordinaryAttemptChallenge(now + 14 * 60 * 1000),
        admittedResponse(now + 14 * 60 * 1000),
      ])
      const first = harness()
      const interactive = {
        returnTo: '/',
        dpopEnabled: false,
        dpopRequired: false,
      }
      const silent = { ...interactive, prompt: 'none' }
      const original = pendingMode === 'silent' ? silent : interactive
      const replacement = pendingMode === 'silent' ? interactive : silent

      await expect(
        first.authorization.begin(start(first.generation, original)),
      ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
      const reloaded = harness()
      await expect(
        reloaded.authorization.begin(start(reloaded.generation, replacement)),
      ).rejects.toMatchObject({
        name: 'OrdinaryAuthorizationIntentConflictError',
        pendingMode,
      })
      expect(parCalls(transport)).toHaveLength(1)
      expect(reloaded.navigations).toHaveLength(0)

      await reloaded.authorization.begin(start(reloaded.generation, original))
      const calls = parCalls(transport)
      expect(calls).toHaveLength(3)
      expect(calls[1][1].body).toBe(calls[0][1].body)
      expect(reloaded.navigations).toHaveLength(1)
    },
  )

  it.each(['first', 'second'] as const)(
    'cancels exact custody after the %s PAR response is lost before changing intent',
    async (stage) => {
      const now = 1_800_000_000_000
      vi.spyOn(Date, 'now').mockReturnValue(now)
      const deadline = now + 14 * 60 * 1000
      const challenge = ordinaryAttemptChallenge(deadline)
      const lostResponse = new TypeError('lost response')
      const transport = installTransport([
        ...(stage === 'first' ? [lostResponse, challenge] : [challenge, lostResponse]),
        ordinaryAttemptChallenge(deadline),
        admittedResponse(deadline),
      ])
      const flow = harness()
      const client = createPublicOrdinaryClient()
      const original = { prompt: 'none', returnTo: '/' }
      const replacement = { returnTo: '/' }
      const startingURL = window.location.href

      await expect(flow.authorization.begin(start(flow.generation, original)))
        .rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
      await expect(flow.authorization.begin(start(flow.generation, replacement)))
        .rejects.toBeInstanceOf(OrdinaryAuthorizationIntentConflictError)
      await client.cancelLogin()
      expect(window.location.href).toBe(startingURL)
      expect(flow.navigations).toHaveLength(0)
      const beforeReplacement = parCalls(transport)
      const cancellationCalls = transport.mock.calls.filter(
        ([url]) => url === `${ISSUER}/auth/par/pre-navigation-cancellation`,
      )
      expect(cancellationCalls).toHaveLength(1)
      expect(beforeReplacement).toHaveLength(2)
      const cancelBody = String(cancellationCalls[0][1].body)
      const cancelled = new URLSearchParams(cancelBody)
      expect(cancelled.has('atol_attempt_capability')).toBe(true)
      if (stage === 'first') {
        expect(beforeReplacement[1][1].body).toBe(beforeReplacement[0][1].body)
        cancelled.delete('atol_attempt_capability')
        expect(cancelled.toString()).toBe(beforeReplacement[0][1].body)
      } else {
        expect(cancelBody).toBe(beforeReplacement[1][1].body)
      }

      await flow.authorization.begin(start(flow.generation, replacement))
      const newForm = new URLSearchParams(String(parCalls(transport)[2][1].body))
      expect(newForm.get('state')).not.toBe(cancelled.get('state'))
      expect(newForm.has('prompt')).toBe(false)
      expect(flow.navigations).toHaveLength(1)
      client.destroy()
    },
  )

  it('keeps the exact record until a browser-visible authenticated cancellation succeeds', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const deadline = now + 14 * 60 * 1000
    const transport = installTransport([
      new TypeError('lost challenge response'),
      ordinaryAttemptChallenge(deadline),
    ], discovery(), [new Response(null, {
      status: 204,
      headers: {
        'Atol-Browser-Authorization': 'v2',
        'Cache-Control': 'no-store',
      },
    })])
    const flow = harness()
    const client = createPublicOrdinaryClient()
    await expect(flow.authorization.begin(start(flow.generation, { prompt: 'none' })))
      .rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    const pointer = pointerValue()

    await expect(client.cancelLogin()).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    expect(pointerValue()).toEqual(pointer)
    await expect(flow.authorization.begin(start(flow.generation)))
      .rejects.toBeInstanceOf(OrdinaryAuthorizationIntentConflictError)
    expect(parCalls(transport)).toHaveLength(2)
    expect(flow.navigations).toHaveLength(0)

    await client.cancelLogin()
    expect(pointerValue).toThrow(/pointer is missing/)
    const cancellationCalls = transport.mock.calls.filter(
      ([url]) => url === `${ISSUER}/auth/par/pre-navigation-cancellation`,
    )
    expect(cancellationCalls).toHaveLength(2)
    expect(cancellationCalls[1][1].body).toBe(cancellationCalls[0][1].body)
    expect(parCalls(transport)).toHaveLength(2)
    client.destroy()
  })

  it('leaves prior custody alone after the browser credential generation is signed out', async () => {
    const transport = installTransport([new TypeError('lost response')])
    const flow = harness()
    await expect(flow.authorization.begin(start(flow.generation)))
      .rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    const pointer = pointerValue()
    const requestsBeforeCancel = transport.mock.calls.length
    rotateLogoutGeneration({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI })

    const client = createPublicOrdinaryClient()
    await expect(client.cancelLogin()).rejects.toMatchObject({
      code: 'credential_generation_invalidated',
    })
    expect(transport.mock.calls).toHaveLength(requestsBeforeCancel)
    expect(pointerValue()).toEqual(pointer)
    client.destroy()
  })

  it('rejects a malformed admitted root before creating a fresh request', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const malformed = admittedResponse(now + 900_000, {
      atol_browser_authorization_version: 1,
    })
    const transport = installTransport([
      ordinaryAttemptChallenge(now + 900_000),
      malformed,
      ordinaryAttemptChallenge(now + 850_000),
      admittedResponse(now + 850_000),
    ])
    const flow = harness()

    await expect(
      flow.authorization.begin(start(flow.generation)),
    ).rejects.toThrow(/request was rejected/)
    const firstBody = parCalls(transport)[0][1].body
    await flow.authorization.begin(start(flow.generation))

    expect(parCalls(transport)).toHaveLength(4)
    expect(parCalls(transport)[2][1].body).not.toBe(firstBody)
    expect(flow.navigations).toHaveLength(1)
  })

  it.each([
    [
      'foreign PAR endpoint',
      discovery({
        pushed_authorization_request_endpoint:
          'https://attacker.test/auth/par',
      }),
    ],
    [
      'unsupported protocol version',
      discovery({
        atol_browser_authorization: {
          version: 1,
          ceremony_lifetime_seconds: 900,
          authorization_code_lifetime_seconds: 600,
          pre_navigation_cancellation_endpoint:
            `${ISSUER}/auth/par/pre-navigation-cancellation`,
          settlement_endpoint: `${ISSUER}/auth/par/settlement`,
        },
      }),
    ],
    [
      'inflated ceremony lifetime',
      discovery({
        atol_browser_authorization: {
          version: 2,
          ceremony_lifetime_seconds: 901,
          authorization_code_lifetime_seconds: 600,
          pre_navigation_cancellation_endpoint:
            `${ISSUER}/auth/par/pre-navigation-cancellation`,
          settlement_endpoint: `${ISSUER}/auth/par/settlement`,
        },
      }),
    ],
    [
      'optional pushed authorization',
      discovery({ require_pushed_authorization_requests: false }),
    ],
  ])('rejects %s before PAR or navigation', async (_name, metadata) => {
    const transport = installTransport([], metadata)
    const flow = harness()

    await expect(
      flow.authorization.begin(start(flow.generation)),
    ).rejects.toThrow(
      /discovery|endpoint|pushed authorization/,
    )
    expect(parCalls(transport)).toHaveLength(0)
    expect(flow.navigations).toEqual([])
    expect(
      await flow.manager.settings.stateStore.getAllKeys(),
    ).toEqual([])
  })

  it('does not treat an admitted deadline hint as callback deletion authority', async () => {
    const now = 1_800_000_000_000
    const rootExpiresAt = now + 1_000
    const custodyExpiresAt = rootExpiresAt + 600_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installTransport([
      ordinaryAttemptChallenge(rootExpiresAt),
      admittedResponse(rootExpiresAt, { expires_in: 1 }),
    ])
    const flow = harness()
    await flow.authorization.begin(start(flow.generation))
    const form = new URLSearchParams(
      parCalls(transport)[0][1].body as string,
    )
    const callback = await readAuthorizationCodeResponseState(
      flow.manager,
      `${REDIRECT_URI}?code=auth-code&state=${form.get('state')}`,
    )

    vi.mocked(Date.now).mockReturnValue(custodyExpiresAt)
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await custody.release()
  })

  it('keeps exact callback custody across forward and backward clock jumps', async () => {
    const now = 1_800_000_000_000
    const rootExpiresAt = now + 1_000
    const custodyExpiresAt = rootExpiresAt + 600_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installTransport([
      ordinaryAttemptChallenge(rootExpiresAt),
      admittedResponse(rootExpiresAt, { expires_in: 1 }),
    ])
    const flow = harness()
    await flow.authorization.begin(start(flow.generation))
    const form = new URLSearchParams(
      parCalls(transport)[0][1].body as string,
    )
    const callback = await readAuthorizationCodeResponseState(
      flow.manager,
      `${REDIRECT_URI}?code=auth-code&state=${form.get('state')}`,
    )

    vi.mocked(Date.now).mockReturnValue(custodyExpiresAt + 86_400_000)
    const forward = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await forward.release()

    vi.mocked(Date.now).mockReturnValue(now - 86_400_000)
    const backward = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await backward.complete()
  })

  it('rejects substituted callback nonce or PKCE without consuming custody', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installTransport([
      ordinaryAttemptChallenge(now + 900_000),
      admittedResponse(now + 900_000),
    ])
    const flow = harness()
    await flow.authorization.begin(start(flow.generation))
    const form = new URLSearchParams(
      parCalls(transport)[0][1].body as string,
    )
    const callback = await readAuthorizationCodeResponseState(
      flow.manager,
      `${REDIRECT_URI}?code=auth-code&state=${form.get('state')}`,
    )

    await expect(
      flow.authorization.claimCallback(
        { ...callback, nonce: `${callback.nonce}0` },
        flow.generation,
      ),
    ).rejects.toThrow(/callback custody mismatch/)
    const exact = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await expect(exact.complete()).resolves.toBeUndefined()
  })
})
