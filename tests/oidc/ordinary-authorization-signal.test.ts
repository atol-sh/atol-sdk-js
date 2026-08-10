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
import { hasAuthenticatedOrdinaryAuthorizationSignal } from '../../src/oidc/ordinary-authorization-settlement'
import {
  browserVisibleOrdinaryResponse,
  installOrdinaryAuthorizationLocks,
  installOrdinaryTransport,
  ordinaryAdmittedResponse,
  ordinaryHarness,
  ordinaryParCalls,
  ordinaryPreNavigationCalls,
  ordinaryStart,
  readOrdinaryAuthorizationRecords,
  resetOrdinaryAuthorizationDatabase,
} from './ordinary-authorization-test-support'

const originalCrypto = globalThis.crypto
const originalFetch = globalThis.fetch
const now = 1_800_000_000_000

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
  vi.spyOn(Date, 'now').mockReturnValue(now)
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

async function admittedBody(): Promise<string> {
  return ordinaryAdmittedResponse(now + 800_000).text()
}

function attemptCapability(
  expiresAt: number,
  kind = 2,
): string {
  const raw = new Uint8Array(58)
  raw[0] = 1
  raw[1] = kind
  let deadline = BigInt(expiresAt) * 1_000_000n
  for (let index = 25; index >= 18; index--) {
    raw[index] = Number(deadline & 0xffn)
    deadline >>= 8n
  }
  return bytesToBase64Url(raw)
}

function attemptChallenge(
  expiresAt: number,
  kind = 2,
): Response {
  return new Response(
    JSON.stringify({
      error: 'attempt_capability_required',
      attempt_capability: attemptCapability(expiresAt, kind),
      expires_in: 800,
      attempt_expires_at: new Date(expiresAt).toISOString(),
    }),
    {
      status: 428,
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

describe('ordinary browser authorization authenticated signal', () => {
  it('uses only the exact browser-visible custom response signal', () => {
    const hiddenCORS = new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': 'https://app.test',
        'Access-Control-Allow-Credentials': 'true',
        Vary: 'Origin',
      },
    })
    const hiddenVisible =
      browserVisibleOrdinaryResponse(hiddenCORS)
    expect(
      hasAuthenticatedOrdinaryAuthorizationSignal(hiddenVisible),
    ).toBe(false)
    expect(
      hiddenVisible.headers.get('Access-Control-Allow-Origin'),
    ).toBeNull()
    expect(
      hiddenVisible.headers.get(
        'Access-Control-Allow-Credentials',
      ),
    ).toBeNull()
    expect(hiddenVisible.headers.get('Vary')).toBeNull()
    expect(
      hasAuthenticatedOrdinaryAuthorizationSignal(
        browserVisibleOrdinaryResponse(
          new Response(null, {
            headers: {
              'Access-Control-Allow-Origin':
                'https://app.test',
              'Access-Control-Allow-Credentials': 'true',
              'Access-Control-Expose-Headers':
                'Atol-Browser-Authorization',
              'Atol-Browser-Authorization': 'v2',
              Vary: 'Origin',
            },
          }),
        ),
      ),
    ).toBe(true)
    expect(
      hasAuthenticatedOrdinaryAuthorizationSignal(
        browserVisibleOrdinaryResponse(
          new Response(null, {
            headers: {
              'Access-Control-Allow-Origin':
                'https://app.test',
              'Access-Control-Expose-Headers':
                'Atol-Browser-Authorization',
              'Atol-Browser-Authorization': 'v1',
            },
          }),
        ),
      ),
    ).toBe(false)
    const repeated = new Headers({
      'Access-Control-Allow-Origin': 'https://app.test',
      'Access-Control-Expose-Headers':
        'Atol-Browser-Authorization',
    })
    repeated.append('Atol-Browser-Authorization', 'v2')
    repeated.append('Atol-Browser-Authorization', 'v2')
    expect(
      hasAuthenticatedOrdinaryAuthorizationSignal(
        browserVisibleOrdinaryResponse(
          new Response(null, { headers: repeated }),
        ),
      ),
    ).toBe(false)
  })

  it.each([
    ['missing signal', 'application/json', null],
    ['wrong signal', 'application/json', 'v1'],
    ['multiple signal values', 'application/json', 'v2, v2'],
    [
      'parameterized JSON media type',
      'application/json; charset=utf-8',
      'v2',
    ],
  ])(
    'fences a submitted PAR response with %s',
    async (_name, contentType, signal) => {
      const headers = new Headers({
        'Cache-Control': 'no-store',
        'Content-Type': contentType,
      })
      if (signal === null) {
        headers.set(
          'Access-Control-Allow-Origin',
          'https://app.test',
        )
        headers.set('Vary', 'Origin')
      } else {
        headers.set(
          'Access-Control-Allow-Origin',
          'https://app.test',
        )
        headers.set(
          'Access-Control-Expose-Headers',
          'Atol-Browser-Authorization',
        )
        headers.set('Atol-Browser-Authorization', signal)
      }
      const transport = installOrdinaryTransport([
        new Response(await admittedBody(), {
          status: 201,
          headers,
        }),
      ])
      const flow = ordinaryHarness()

      await expect(
        flow.authorization.begin(ordinaryStart(flow.generation)),
      ).rejects.toThrow(
        'ordinary browser authorization request was rejected',
      )

      const par = ordinaryParCalls(transport)
      const cancellation = ordinaryPreNavigationCalls(transport)
      expect(par).toHaveLength(1)
      expect(cancellation).toHaveLength(1)
      expect(cancellation[0][1].body).toBe(par[0][1].body)
      expect(await readOrdinaryAuthorizationRecords()).toEqual([])
      expect(flow.navigations).toEqual([])
    },
  )

  it('rejects an authenticated 201 before the mandatory attempt challenge', async () => {
    const transport = installOrdinaryTransport([
      ordinaryAdmittedResponse(now + 800_000),
    ])
    const flow = ordinaryHarness()

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toThrow(
      'ordinary browser authorization request was rejected',
    )

    expect(ordinaryParCalls(transport)).toHaveLength(1)
    expect(ordinaryPreNavigationCalls(transport)).toHaveLength(1)
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(flow.navigations).toEqual([])
  })

  it('rejects a kind-1 terminal proof as an attempt capability', async () => {
    const transport = installOrdinaryTransport([
      attemptChallenge(now + 800_000, 1),
    ])
    const flow = ordinaryHarness()

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toThrow(
      'ordinary browser authorization: attempt capability is invalid',
    )

    const calls = ordinaryParCalls(transport)
    expect(calls).toHaveLength(1)
    expect(ordinaryPreNavigationCalls(transport)).toHaveLength(0)
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      {
        parPhase: 'submitted',
        attemptExpiresAtMs: null,
      },
    ])
    expect(flow.navigations).toEqual([])
  })

  it.each([
    ['ahead', now + 365 * 24 * 60 * 60 * 1000],
    ['behind', now - 365 * 24 * 60 * 60 * 1000],
  ])(
    'binds kind-2 capability and derives local custody with server clock %s',
    async (_skew, serverRootExpiresAt) => {
      const capability = attemptCapability(serverRootExpiresAt)
      const transport = installOrdinaryTransport([
        attemptChallenge(serverRootExpiresAt),
        ordinaryAdmittedResponse(serverRootExpiresAt),
      ])
      const flow = ordinaryHarness()

      await flow.authorization.begin(ordinaryStart(flow.generation))

      const calls = ordinaryParCalls(transport)
      expect(calls).toHaveLength(2)
      const first = new URLSearchParams(String(calls[0][1].body))
      const second = new URLSearchParams(String(calls[1][1].body))
      expect(first.has('atol_attempt_capability')).toBe(false)
      expect(second.get('atol_attempt_capability')).toBe(capability)
      second.delete('atol_attempt_capability')
      expect(second.toString()).toBe(first.toString())
      expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
        {
          parPhase: 'admitted',
          provisionalExpiresAt: now + 1_500_000,
          attemptExpiresAtMs: now + 799_000,
          rootExpiresAtMs: serverRootExpiresAt,
          custodyExpiresAtMs: now + 1_399_000,
        },
      ])
      expect(flow.navigations).toHaveLength(1)
    },
  )
})
