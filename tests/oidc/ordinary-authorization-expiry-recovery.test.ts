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
import { OrdinaryAuthorizationPendingError } from '../../src/oidc/ordinary-authorization'
import {
  installOrdinaryAuthorizationLocks,
  installOrdinaryTransport,
  ordinaryAdmittedResponse,
  ordinaryAttemptChallenge,
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

describe('ordinary submitted-expiry recovery', () => {
  it('fences expired submitted custody before admitting a fresh request', async () => {
    const now = 1_800_000_000_000
    const resumedAt = now + 26 * 60 * 1000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installOrdinaryTransport([
      new TypeError('PAR response lost'),
      ordinaryAttemptChallenge(resumedAt + 800_000),
      ordinaryAdmittedResponse(resumedAt + 800_000),
    ])
    const flow = ordinaryHarness()

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    const submittedBody = ordinaryParCalls(transport)[0][1].body
    const submittedState = new URLSearchParams(
      String(submittedBody),
    ).get('state')
    expect(submittedState).not.toBeNull()
    vi.mocked(Date.now).mockReturnValue(resumedAt)

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toThrow(
      'ordinary browser authorization request was rejected',
    )

    expect(ordinaryParCalls(transport)).toHaveLength(1)
    expect(ordinaryPreNavigationCalls(transport)[0][1].body).toBe(
      submittedBody,
    )
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(
      await flow.manager.settings.stateStore.getAllKeys(),
    ).toEqual([])

    await flow.authorization.begin(ordinaryStart(flow.generation))

    expect(ordinaryParCalls(transport)).toHaveLength(3)
    const freshBody = ordinaryParCalls(transport)[1][1].body
    expect(freshBody).not.toBe(submittedBody)
    expect(
      new URLSearchParams(String(freshBody)).get('state'),
    ).not.toBe(
      submittedState,
    )
    expect(flow.navigations).toHaveLength(1)
  })

  it('retains expired submitted custody without authenticated fencing', async () => {
    const now = 1_800_000_000_000
    vi.spyOn(Date, 'now').mockReturnValue(now)
    const transport = installOrdinaryTransport(
      [new TypeError('PAR response lost')],
      undefined,
      [],
      [new TypeError('cancellation response lost')],
    )
    const flow = ordinaryHarness()

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    vi.mocked(Date.now).mockReturnValue(
      now + 26 * 60 * 1000,
    )

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)

    expect(ordinaryParCalls(transport)).toHaveLength(1)
    expect(ordinaryPreNavigationCalls(transport)).toHaveLength(1)
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      {
        parPhase: 'submitted',
        cleanupStarted: false,
      },
    ])
    expect(
      await flow.manager.settings.stateStore.getAllKeys(),
    ).toHaveLength(1)
  })
})
