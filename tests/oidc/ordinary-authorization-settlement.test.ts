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
  credentialGenerationForLogin,
} from '../../src/oidc/credential-generation'
import { bytesToBase64Url } from '../../src/crypto/base64url'
import {
  OrdinaryAuthorizationPendingError,
  OrdinaryBrowserAuthorization,
} from '../../src/oidc/ordinary-authorization'
import {
  createUserManager,
  readAuthorizationCodeResponseState,
} from '../../src/oidc/oidc'
import {
  ORDINARY_CLIENT_ID,
  ORDINARY_ISSUER,
  ORDINARY_REDIRECT_URI,
  ORDINARY_SCOPE,
  installOrdinaryAuthorizationLocks,
  installOrdinaryTransport,
  ordinaryAdmittedResponse,
  ordinaryAttemptChallenge,
  ordinaryHarness,
  ordinaryParCalls,
  ordinaryPreNavigationCalls,
  ordinaryPointerKey,
  ordinarySettlementCalls,
  ordinaryStart,
  putOrdinaryAuthorizationRecord,
  readOrdinaryAuthorizationRecords,
  resetOrdinaryAuthorizationDatabase,
} from './ordinary-authorization-test-support'

const originalCrypto = globalThis.crypto
const originalFetch = globalThis.fetch
const now = 1_800_000_000_000

function authenticatedJSON(
  status: number,
  error: string,
): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: {
      'Access-Control-Allow-Origin': 'https://app.test',
      'Access-Control-Expose-Headers':
        'Atol-Browser-Authorization',
      'Atol-Browser-Authorization': 'v2',
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json',
      Vary: 'Origin',
    },
  })
}

function authenticatedNoContent(
  headers: Record<string, string> = {},
): Response {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': 'https://app.test',
      'Access-Control-Expose-Headers':
        'Atol-Browser-Authorization',
      'Atol-Browser-Authorization': 'v2',
      'Cache-Control': 'no-store',
      Vary: 'Origin',
      ...headers,
    },
  })
}

async function admittedCode(
  settlement: Array<Response | Error> = [],
) {
  const transport = installOrdinaryTransport(
    [
      ordinaryAttemptChallenge(now + 800_000),
      ordinaryAdmittedResponse(now + 800_000),
    ],
    undefined,
    settlement,
  )
  const flow = ordinaryHarness()
  await flow.authorization.begin(ordinaryStart(flow.generation))
  const form = new URLSearchParams(
    ordinaryParCalls(transport)[0][1].body as string,
  )
  const callback = await readAuthorizationCodeResponseState(
    flow.manager,
    `${ORDINARY_REDIRECT_URI}?code=auth-code&state=${form.get('state')}`,
  )
  return { flow, transport, form, callback }
}

async function expectRetainedCode(): Promise<void> {
  expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
    {
      parPhase: 'admitted',
      rejectionRequired: true,
      callbackClaimId: null,
      callbackCode: 'auth-code',
      cleanupStarted: false,
    },
  ])
}

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

describe('ordinary authorization settlement', () => {
  it('persists rejection intent and sends the exact capability before cleanup', async () => {
    const { flow, transport, form, callback } =
      await admittedCode([authenticatedNoContent()])
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )

    await custody.discard()

    const calls = ordinarySettlementCalls(transport)
    expect(calls).toHaveLength(1)
    expect(calls[0][1]).toMatchObject({
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    })
    expect(calls[0][1].headers).toEqual({
      Accept: 'application/json',
      'Content-Type': 'application/json',
    })
    const body = JSON.parse(String(calls[0][1].body)) as Record<
      string,
      unknown
    >
    expect(body).toEqual({
      version: 2,
      mode: 'reject',
      client_id: ORDINARY_CLIENT_ID,
      request_uri: expect.stringMatching(
        /^urn:ietf:params:oauth:request_uri:/,
      ),
      cancellation_secret: form.get('atol_cancellation_secret'),
      terminal_proof: expect.stringMatching(
        /^[A-Za-z0-9_-]{78}$/,
      ),
    })
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
  })

  it.each([
    [
      '400 invalid_request',
      () =>
        new Response(JSON.stringify({ error: 'invalid_request' }), {
          status: 400,
          headers: {
            'Cache-Control': 'no-store',
            'Content-Type': 'application/json',
          },
        }),
    ],
    [
      '503 unavailable',
      () => authenticatedJSON(503, 'unavailable'),
    ],
    ['network loss', () => new TypeError('response lost')],
    [
      '204 missing no-store',
      () =>
        authenticatedNoContent({
          'Cache-Control': 'private',
        }),
    ],
    [
      '204 hidden CORS without authenticated signal',
      () =>
        new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': 'https://app.test',
            'Cache-Control': 'no-store',
            Vary: 'Origin',
          },
        }),
    ],
  ])('retains exact code custody on %s', async (_name, response) => {
    const { flow, callback } = await admittedCode([response()])
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )

    await expect(custody.discard()).rejects.toThrow()
    await expectRetainedCode()
    expect(
      await flow.manager.settings.stateStore.get(callback.stateId),
    ).not.toBeNull()
    expect(sessionStorage.getItem(ordinaryPointerKey())).not.toBeNull()
  })

  it('retries the same rejection capability after an unavailable response', async () => {
    const { flow, transport, callback } = await admittedCode([
      authenticatedJSON(503, 'unavailable'),
      authenticatedNoContent(),
    ])
    const custody = await flow.authorization.claimCallback(
      callback,
      flow.generation,
    )
    await expect(custody.discard()).rejects.toBeInstanceOf(
      OrdinaryAuthorizationPendingError,
    )
    await expectRetainedCode()

    await flow.authorization.invalidateCurrent(flow.generation)

    const calls = ordinarySettlementCalls(transport)
    expect(calls).toHaveLength(2)
    expect(calls[1][1].body).toBe(calls[0][1].body)
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
  })

  it('retains terminal-only custody on 409 and cleans only after authenticated 410', async () => {
    const transport = installOrdinaryTransport(
      [
        ordinaryAttemptChallenge(now + 800_000),
        ordinaryAdmittedResponse(now + 800_000),
      ],
      undefined,
      [
        authenticatedJSON(409, 'authorization_nonterminal'),
        authenticatedJSON(410, 'authorization_terminal'),
      ],
    )
    const flow = ordinaryHarness()
    await flow.authorization.begin(ordinaryStart(flow.generation))
    const form = new URLSearchParams(
      ordinaryParCalls(transport)[0][1].body as string,
    )
    const callback = await readAuthorizationCodeResponseState(
      flow.manager,
      `${ORDINARY_REDIRECT_URI}?error=access_denied&state=${form.get('state')}`,
    )

    await expect(
      flow.authorization.discardCallback(
        callback,
        flow.generation,
      ),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      {
        rejectionRequired: false,
        callbackCode: null,
        cleanupStarted: false,
      },
    ])

    await flow.authorization.discardCallback(
      callback,
      flow.generation,
    )
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(
      ordinarySettlementCalls(transport).map((call) =>
        JSON.parse(String(call[1].body)),
      ),
    ).toMatchObject([
      { mode: 'terminal_only' },
      { mode: 'terminal_only' },
    ])
  })

  it('fences submitted PAR custody before signed-out cleanup', async () => {
    const transport = installOrdinaryTransport([
      new TypeError('PAR response lost'),
    ])
    const flow = ordinaryHarness()
    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      { parPhase: 'submitted' },
    ])

    await flow.authorization.invalidateSignedOutLifecycle()

    const par = ordinaryParCalls(transport)
    const cancellation = ordinaryPreNavigationCalls(transport)
    expect(par).toHaveLength(1)
    expect(cancellation).toHaveLength(1)
    expect(cancellation[0][1].body).toBe(par[0][1].body)
    expect(cancellation[0][1]).toMatchObject({
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    })
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
  })

  it.each([
    [
      '400 invalid_request',
      () =>
        new Response(JSON.stringify({ error: 'invalid_request' }), {
          status: 400,
          headers: {
            'Cache-Control': 'no-store',
            'Content-Type': 'application/json',
          },
        }),
    ],
    ['503 unavailable', () => authenticatedJSON(503, 'unavailable')],
    ['network loss', () => new TypeError('cancellation lost')],
    [
      '204 missing no-store',
      () => authenticatedNoContent({ 'Cache-Control': 'private' }),
    ],
    [
      '204 hidden CORS without authenticated signal',
      () =>
        new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': 'https://app.test',
            'Cache-Control': 'no-store',
            Vary: 'Origin',
          },
        }),
    ],
  ])('retains submitted custody on pre-navigation %s', async (_name, result) => {
    const transport = installOrdinaryTransport(
      [new TypeError('PAR response lost')],
      undefined,
      [],
      [result()],
    )
    const flow = ordinaryHarness()
    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)

    await expect(
      flow.authorization.invalidateSignedOutLifecycle(),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)

    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      { parPhase: 'submitted', cleanupStarted: false },
    ])
    expect(ordinarySettlementCalls(transport)).toHaveLength(0)
    expect(ordinaryPreNavigationCalls(transport)).toHaveLength(1)
  })

  it('uses DB-authenticated cancellation after local submitted expiry', async () => {
    const transport = installOrdinaryTransport([
      new TypeError('PAR response lost'),
    ])
    const flow = ordinaryHarness()
    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    vi.mocked(Date.now).mockReturnValue(
      now + 26 * 60 * 1000,
    )

    await flow.authorization.invalidateSignedOutLifecycle()

    expect(ordinaryPreNavigationCalls(transport)).toHaveLength(1)
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
  })

  it('does not treat a lost rejection response as terminal admission proof', async () => {
    const malformed = ordinaryAdmittedResponse(now + 800_000, {
      terminal_proof: 'invalid',
    })
    const transport = installOrdinaryTransport(
      [
        ordinaryAttemptChallenge(now + 800_000),
        malformed,
        ordinaryAdmittedResponse(now + 800_000),
      ],
      undefined,
      [],
      [new TypeError('cancellation response lost')],
    )
    const flow = ordinaryHarness()

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      { parPhase: 'submitted', cleanupStarted: false },
    ])
    const firstBody = ordinaryParCalls(transport)[1][1].body

    await flow.authorization.begin(ordinaryStart(flow.generation))

    expect(ordinaryParCalls(transport)[2][1].body).toBe(firstBody)
    expect(flow.navigations).toHaveLength(1)
  })

  it('durably resumes cleanup after terminal admission rejection', async () => {
    const transport = installOrdinaryTransport(
      [
        ordinaryAttemptChallenge(now + 800_000),
        ordinaryAdmittedResponse(now + 800_000, {
          terminal_proof: 'invalid',
        }),
      ],
      undefined,
      [],
      [authenticatedNoContent()],
    )
    const flow = ordinaryHarness()
    const remove = vi
      .spyOn(flow.manager.settings.stateStore, 'remove')
      .mockRejectedValueOnce(
        new Error('injected OIDC state removal failure'),
      )

    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toThrow(/injected OIDC state removal failure/)
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      { parPhase: 'submitted', cleanupStarted: true },
    ])
    remove.mockRestore()

    await flow.authorization.invalidateSignedOutLifecycle()

    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(ordinaryPreNavigationCalls(transport)).toHaveLength(1)
  })

  it('reconciles same-application custody across redirect and scope drift', async () => {
    const transport = installOrdinaryTransport([
      new TypeError('PAR response lost'),
    ])
    const old = ordinaryHarness()
    await expect(
      old.authorization.begin(ordinaryStart(old.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    const oldPointer = ordinaryPointerKey()

    const redirect = 'https://app.test/new-callback'
    const scope = 'openid email'
    const manager = createUserManager(
      ORDINARY_ISSUER,
      ORDINARY_CLIENT_ID,
      redirect,
      scope,
      'https://api.atol.test',
    )
    const current = new OrdinaryBrowserAuthorization(manager, {
      issuer: ORDINARY_ISSUER,
      clientId: ORDINARY_CLIENT_ID,
      redirectUri: redirect,
      scope,
    })

    await current.invalidateSignedOutLifecycle()

    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(sessionStorage.getItem(oldPointer)).toBeNull()
    expect(await manager.settings.stateStore.getAllKeys()).toEqual([])
    expect(ordinaryPreNavigationCalls(transport)).toHaveLength(1)
  })

  it('preserves cross-client isolation during signed-out scanning', async () => {
    installOrdinaryTransport([new TypeError('PAR response lost')])
    const old = ordinaryHarness()
    await expect(
      old.authorization.begin(ordinaryStart(old.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)

    const otherClient = 'atol_kid_other'
    const manager = createUserManager(
      ORDINARY_ISSUER,
      otherClient,
      ORDINARY_REDIRECT_URI,
      ORDINARY_SCOPE,
      'https://api.atol.test',
    )
    const current = new OrdinaryBrowserAuthorization(manager, {
      issuer: ORDINARY_ISSUER,
      clientId: otherClient,
      redirectUri: ORDINARY_REDIRECT_URI,
      scope: ORDINARY_SCOPE,
    })
    credentialGenerationForLogin({
      issuer: ORDINARY_ISSUER,
      clientId: otherClient,
      redirectUri: ORDINARY_REDIRECT_URI,
    })

    await current.invalidateSignedOutLifecycle()

    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      { clientId: ORDINARY_CLIENT_ID, parPhase: 'submitted' },
    ])
  })

  it('preserves a newer same-binding pointer while rejecting old callback custody', async () => {
    const { flow, callback } = await admittedCode([
      authenticatedNoContent(),
    ])
    const pointerKey = ordinaryPointerKey()
    const newerPointer = JSON.stringify({
      version: 1,
      stateId: 'f'.repeat(32),
      tabOwnerGeneration: bytesToBase64Url(
        new Uint8Array(32).fill(9),
      ),
    })
    sessionStorage.setItem(pointerKey, newerPointer)

    await flow.authorization.discardCallback(
      callback,
      flow.generation,
    )

    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(sessionStorage.getItem(pointerKey)).toBe(newerPointer)
  })

  it('validates the entire inventory before signed-out mutation', async () => {
    const transport = installOrdinaryTransport([
      new TypeError('PAR response lost'),
    ])
    const flow = ordinaryHarness()
    await expect(
      flow.authorization.begin(ordinaryStart(flow.generation)),
    ).rejects.toBeInstanceOf(OrdinaryAuthorizationPendingError)
    const [record] = await readOrdinaryAuthorizationRecords()
    await putOrdinaryAuthorizationRecord({
      ...record,
      unknown: true,
    })

    await expect(
      flow.authorization.invalidateSignedOutLifecycle(),
    ).rejects.toThrow(/unrecognized custody/)

    expect(await readOrdinaryAuthorizationRecords()).toHaveLength(1)
    expect(ordinaryParCalls(transport)).toHaveLength(1)
    expect(ordinarySettlementCalls(transport)).toHaveLength(0)
  })
})
