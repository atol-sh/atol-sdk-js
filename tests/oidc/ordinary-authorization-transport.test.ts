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
import {
  OrdinaryAuthorizationPendingError,
} from '../../src/oidc/ordinary-authorization'
import {
  ORDINARY_ISSUER,
  installOrdinaryTransport,
  installOrdinaryAuthorizationLocks,
  ordinaryAdmittedResponse,
  ordinaryAttemptChallenge,
  ordinaryDiscovery,
  ordinaryHarness,
  ordinaryParCalls,
  ordinaryPreNavigationCalls,
  ordinaryStart,
  readOrdinaryAuthorizationRecords,
  resetOrdinaryAuthorizationDatabase,
} from './ordinary-authorization-test-support'

const originalCrypto = globalThis.crypto
const originalFetch = globalThis.fetch

beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: nodeWebCrypto,
  })
})

beforeEach(async () => {
  installOrdinaryAuthorizationLocks()
  await resetOrdinaryAuthorizationDatabase()
  localStorage.clear()
  sessionStorage.clear()
  window.history.replaceState({}, '', '/')
})

afterEach(() => {
  vi.useRealTimers()
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

describe('ordinary PAR transport boundaries', () => {
  it.each([
    [
      'pre-navigation cancellation',
      'https://attacker.test/auth/par/pre-navigation-cancellation',
      `${ORDINARY_ISSUER}/auth/par/settlement`,
    ],
    [
      'settlement',
      `${ORDINARY_ISSUER}/auth/par/pre-navigation-cancellation`,
      'https://attacker.test/auth/par/settlement',
    ],
  ])(
    'rejects a foreign %s endpoint before PAR',
    async (_name, preNavigationEndpoint, settlementEndpoint) => {
      const metadata = ordinaryDiscovery({
        atol_browser_authorization: {
          version: 2,
          ceremony_lifetime_seconds: 900,
          authorization_code_lifetime_seconds: 600,
          pre_navigation_cancellation_endpoint:
            preNavigationEndpoint,
          settlement_endpoint: settlementEndpoint,
        },
      })
      const transport = installOrdinaryTransport([], metadata)
      const flow = ordinaryHarness()

      await expect(
        flow.authorization.begin(ordinaryStart(flow.generation)),
      ).rejects.toThrow(/endpoint is invalid/)

      expect(ordinaryParCalls(transport)).toHaveLength(0)
      expect(flow.navigations).toEqual([])
      expect(
        await flow.manager.settings.stateStore.getAllKeys(),
      ).toEqual([])
    },
  )

  it('fences and cleans custody after an oversized 201 response', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installOrdinaryTransport([
      ordinaryAttemptChallenge(now + 800_000),
      new Response('x'.repeat(16 * 1024 + 1), {
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
      }),
      ordinaryAttemptChallenge(now + 800_000),
      ordinaryAdmittedResponse(now + 800_000),
    ])
    const flow = ordinaryHarness()

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toThrow(
      'ordinary browser authorization request was rejected',
    )
    const firstCalls = ordinaryParCalls(transport)
    expect(firstCalls).toHaveLength(2)
    const firstBody = firstCalls[0][1].body
    expect(ordinaryPreNavigationCalls(transport)[0][1].body).toBe(
      firstCalls[1][1].body,
    )
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(
      await flow.manager.settings.stateStore.getAllKeys(),
    ).toEqual([])

    await flow.authorization.begin(ordinaryStart(flow.generation))
    const calls = ordinaryParCalls(transport)
    expect(calls).toHaveLength(4)
    expect(calls[2][1].body).not.toBe(
      firstBody,
    )
    expect(flow.navigations).toHaveLength(1)
  })

  it('bounds, fences, and cleans a stalled 201 response body', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const realSetTimeout = globalThis.setTimeout
    let fireParTimeout: (() => void) | undefined
    vi.spyOn(globalThis, 'setTimeout').mockImplementation(
      ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => {
        if (timeout === 15_000) {
          fireParTimeout = () => {
            if (typeof handler === 'function') handler(...args)
          }
          return 1
        }
        return realSetTimeout(handler, timeout, ...args)
      }) as typeof setTimeout,
    )
    const stalled = new Response(
      new ReadableStream<Uint8Array>({ start() {} }),
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
    const transport = installOrdinaryTransport([
      ordinaryAttemptChallenge(now + 800_000),
      stalled,
      ordinaryAttemptChallenge(now + 800_000),
      ordinaryAdmittedResponse(now + 800_000),
    ])
    const flow = ordinaryHarness()
    const pending = flow.authorization.begin(
      ordinaryStart(flow.generation),
    )
    await vi.waitFor(() => {
      expect(ordinaryParCalls(transport)).toHaveLength(2)
      expect(fireParTimeout).toBeTypeOf('function')
    })

    fireParTimeout?.()
    await expect(pending).rejects.toThrow(
      'ordinary browser authorization request was rejected',
    )
    const firstCalls = ordinaryParCalls(transport)
    expect(firstCalls).toHaveLength(2)
    const firstBody = firstCalls[0][1].body
    expect(ordinaryPreNavigationCalls(transport)[0][1].body).toBe(
      firstCalls[1][1].body,
    )
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(
      await flow.manager.settings.stateStore.getAllKeys(),
    ).toEqual([])

    await flow.authorization.begin(ordinaryStart(flow.generation))
    const calls = ordinaryParCalls(transport)
    expect(calls).toHaveLength(4)
    expect(calls[2][1].body).not.toBe(
      firstBody,
    )
    expect(flow.navigations).toHaveLength(1)
  })

  it('retains a generic 400 and replays the exact submitted request', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installOrdinaryTransport([
      new Response(
        JSON.stringify({
          error: 'invalid_request',
          error_description: 'rejected',
        }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        },
      ),
      ordinaryAttemptChallenge(now + 800_000),
      ordinaryAdmittedResponse(now + 800_000),
    ])
    const flow = ordinaryHarness()

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    const first = new URLSearchParams(
      ordinaryParCalls(transport)[0][1].body as string,
    )
    expect(await flow.manager.settings.stateStore.getAllKeys()).toHaveLength(1)
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      { parPhase: 'submitted', cleanupStarted: false },
    ])

    await flow.authorization.begin(ordinaryStart(flow.generation))
    expect(ordinaryParCalls(transport)).toHaveLength(3)
    const second = new URLSearchParams(
      ordinaryParCalls(transport)[1][1].body as string,
    )
    expect(second.get('state')).toBe(first.get('state'))
    expect(second.get('atol_cancellation_secret')).toBe(
      first.get('atol_cancellation_secret'),
    )
  })

  it.each([
    'client_id',
    'redirect_uri',
    'state',
    'nonce',
    'code_challenge',
    'prompt',
    'max_age',
    'acr_values',
  ])('rejects caller ownership of protocol field %s', async (field) => {
    const transport = installOrdinaryTransport([])
    const flow = ordinaryHarness()
    await expect(
      flow.authorization.begin(
        ordinaryStart(flow.generation, {
          extraQueryParams: { [field]: 'substitution' },
        }),
      ),
    ).rejects.toThrow(/extra parameter is invalid/)
    expect(ordinaryParCalls(transport)).toHaveLength(0)
    expect(await flow.manager.settings.stateStore.getAllKeys()).toEqual([])
  })

  it('emits one dedicated prompt/max_age/acr_values value', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installOrdinaryTransport([
      ordinaryAttemptChallenge(now + 800_000),
      ordinaryAdmittedResponse(now + 800_000),
    ])
    const flow = ordinaryHarness()
    await flow.authorization.begin(
      ordinaryStart(flow.generation, {
        prompt: 'login',
        maxAge: 0,
        acrValues: 'mfa',
      }),
    )
    const form = new URLSearchParams(
      ordinaryParCalls(transport)[0][1].body as string,
    )
    expect(form.getAll('prompt')).toEqual(['login'])
    expect(form.getAll('max_age')).toEqual(['0'])
    expect(form.getAll('acr_values')).toEqual(['mfa'])
  })

  it('rejects a 201 deadline substituted after the bound attempt challenge', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installOrdinaryTransport([
      ordinaryAttemptChallenge(now + 800_000),
      ordinaryAdmittedResponse(now + 365 * 24 * 60 * 60 * 1000),
    ])
    const flow = ordinaryHarness()

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toThrow(
      'ordinary browser authorization request was rejected',
    )

    const calls = ordinaryParCalls(transport)
    expect(calls).toHaveLength(2)
    expect(ordinaryPreNavigationCalls(transport)[0][1].body).toBe(
      calls[1][1].body,
    )
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(flow.navigations).toEqual([])
  })
})
