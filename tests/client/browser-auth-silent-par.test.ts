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
import { BrowserAuthRuntime } from '../../src/client/browser-auth-context'
import { createBrowserAuthCredentialOperations } from '../../src/client/browser-auth-credentials'
import { createBrowserAuthRenewalOperations } from '../../src/client/browser-auth-renewal'
import { createBrowserAuthSessionOperations } from '../../src/client/browser-auth-session'
import {
  credentialGenerationForLogin,
  type CredentialGenerationSnapshot,
} from '../../src/oidc/credential-generation'
import { LoginRequiredError } from '../../src/oidc/token-recovery'
import { makeJWT } from '../helpers'
import {
  ORDINARY_CLIENT_ID,
  ORDINARY_ISSUER,
  ORDINARY_REDIRECT_URI,
  ORDINARY_REQUEST_URI,
  installOrdinaryAuthorizationLocks,
  installOrdinaryTransport,
  ordinaryAdmittedResponse,
  ordinaryAttemptChallenge,
  ordinarySettlementCalls,
  readOrdinaryAuthorizationRecords,
  resetOrdinaryAuthorizationDatabase,
} from '../oidc/ordinary-authorization-test-support'

vi.mock('../../src/verify/verify', () => ({
  verifyAccessToken: vi.fn(async (token: string) =>
    JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString(),
    ),
  ),
  verifyIdToken: vi.fn(async (token: string) =>
    JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString(),
    ),
  ),
  _resetDiscoveryCache: vi.fn(),
}))

const originalCrypto = globalThis.crypto
const originalFetch = globalThis.fetch

function postAuthorizationResponse(
  iframe: HTMLIFrameElement,
  state: string,
  response: { code?: string; error?: string } = {
    code: 'authorization-code',
  },
): void {
  window.dispatchEvent(
    new MessageEvent('message', {
      data: {
        type: 'authorization_response',
        response: {
          ...response,
          state,
        },
      },
      origin: ORDINARY_ISSUER,
      source: iframe.contentWindow,
    }),
  )
}

function silentRuntime(): {
  runtime: BrowserAuthRuntime
  generation: CredentialGenerationSnapshot
} {
  const runtime = new BrowserAuthRuntime({
    issuer: ORDINARY_ISSUER,
    clientId: ORDINARY_CLIENT_ID,
    redirectUri: ORDINARY_REDIRECT_URI,
  })
  runtime.sessionOps = createBrowserAuthSessionOperations(runtime)
  runtime.credentialOps =
    createBrowserAuthCredentialOperations(runtime)
  runtime.renewalOps =
    createBrowserAuthRenewalOperations(runtime)
  return {
    runtime,
    generation: credentialGenerationForLogin(
      runtime.credentialGenerationBinding,
    ),
  }
}

function successfulTokenResponse(
  accessToken: string,
  idToken: string,
): Response {
  return new Response(
    JSON.stringify({
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: 3600,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function invalidGrantResponse(): Response {
  return new Response(
    JSON.stringify({ error: 'invalid_grant' }),
    {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function installSilentTransport(
  tokenResponses: Array<Response | Error>,
  settlement: Array<Response | Error> = [],
): ReturnType<typeof vi.fn> {
  const rootExpiresAt = Date.now() + 15 * 60_000
  const ordinaryTransport = installOrdinaryTransport(
    [
      ordinaryAttemptChallenge(rootExpiresAt),
      ordinaryAdmittedResponse(rootExpiresAt),
    ],
    undefined,
    settlement,
  )
  let tokenIndex = 0
  const transport = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === `${ORDINARY_ISSUER}/auth/token`) {
        const result = tokenResponses[tokenIndex++]
        if (result instanceof Error) throw result
        if (!result) throw new Error('unexpected token request')
        return result
      }
      return ordinaryTransport(input, init)
    },
  )
  vi.stubGlobal('fetch', transport)
  return transport
}

async function pendingSilentAuthorization(
  runtime: BrowserAuthRuntime,
  generation: CredentialGenerationSnapshot,
  transport: ReturnType<typeof vi.fn>,
): Promise<{
  iframe: HTMLIFrameElement
  pending: ReturnType<
    BrowserAuthRuntime['renewalOps']['renewViaIframe']
  >
  state: string
}> {
  const pending = runtime.renewalOps.renewViaIframe(
    undefined,
    generation,
  )
  await vi.waitFor(() => {
    expect(document.querySelector('iframe')).not.toBeNull()
  })
  const iframe = document.querySelector(
    'iframe',
  ) as HTMLIFrameElement
  const parCall = transport.mock.calls.find(
    (call) =>
      String(call[0]) === `${ORDINARY_ISSUER}/auth/par`,
  )
  if (!parCall) throw new Error('silent PAR request is missing')
  const state = new URLSearchParams(
    String((parCall[1] as RequestInit).body),
  ).get('state')
  if (!state) throw new Error('silent PAR state is missing')
  return { iframe, pending, state }
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
  document.body.innerHTML = ''
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

describe('ordinary silent PAR renewal', () => {
  it('admits prompt=none by PAR and retains custody through publication', async () => {
    const rootExpiresAt = Date.now() + 15 * 60_000
    const ordinaryTransport = installOrdinaryTransport([
      ordinaryAttemptChallenge(rootExpiresAt),
      ordinaryAdmittedResponse(rootExpiresAt),
    ])
    const accessToken = makeJWT({
      sub: 'user-1',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
    const idToken = makeJWT({
      sub: 'user-1',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
    const transport = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input) === `${ORDINARY_ISSUER}/auth/token`) {
          return new Response(
            JSON.stringify({
              access_token: accessToken,
              id_token: idToken,
              token_type: 'Bearer',
              expires_in: 3600,
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            },
          )
        }
        return ordinaryTransport(input, init)
      },
    )
    vi.stubGlobal('fetch', transport)

    const runtime = new BrowserAuthRuntime({
      issuer: ORDINARY_ISSUER,
      clientId: ORDINARY_CLIENT_ID,
      redirectUri: ORDINARY_REDIRECT_URI,
    })
    runtime.sessionOps = createBrowserAuthSessionOperations(runtime)
    runtime.credentialOps =
      createBrowserAuthCredentialOperations(runtime)
    runtime.renewalOps =
      createBrowserAuthRenewalOperations(runtime)
    const generation = credentialGenerationForLogin(
      runtime.credentialGenerationBinding,
    )

    const pending = runtime.renewalOps.renewViaIframe(
      undefined,
      generation,
    )
    await vi.waitFor(() => {
      expect(document.querySelector('iframe')).not.toBeNull()
    })
    const iframe = document.querySelector('iframe') as HTMLIFrameElement
    const parCall = transport.mock.calls.find(
      (call) => String(call[0]) === `${ORDINARY_ISSUER}/auth/par`,
    )
    expect(parCall).toBeDefined()
    const par = new URLSearchParams(
      String((parCall?.[1] as RequestInit).body),
    )
    expect(par.getAll('prompt')).toEqual(['none'])
    expect(par.getAll('response_mode')).toEqual(['web_message'])
    expect(par.get('redirect_uri')).toBe(ORDINARY_REDIRECT_URI)
    expect(par.get('state')).toMatch(/^[0-9a-f]{32}$/)
    expect(par.get('nonce')).toMatch(/^[0-9a-f]{64}$/)
    expect(par.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const navigation = new URL(iframe.src)
    expect(navigation.origin + navigation.pathname).toBe(
      `${ORDINARY_ISSUER}/auth/authorize`,
    )
    expect(Array.from(navigation.searchParams.keys())).toEqual([
      'client_id',
      'request_uri',
    ])
    expect(navigation.searchParams.get('client_id')).toBe(
      ORDINARY_CLIENT_ID,
    )
    expect(navigation.searchParams.get('request_uri')).toBe(
      ORDINARY_REQUEST_URI,
    )
    expect(
      transport.mock.calls.filter(
        (call) =>
          String(call[0]).startsWith(
            `${ORDINARY_ISSUER}/auth/authorize`,
          ),
      ),
    ).toEqual([])

    postAuthorizationResponse(iframe, par.get('state') as string)
    const grant = await pending
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      {
        callbackCode: 'authorization-code',
        compensationRequired: true,
        cleanupStarted: false,
      },
    ])

    let releaseStore!: () => void
    vi.spyOn(runtime.manager, 'storeUser').mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          releaseStore = resolve
        }),
    )
    const publication =
      runtime.credentialOps.applyAuthorizationGrant(grant, {
        expectedNonce: grant.nonce,
        dpopKey: grant.dpopKey,
        replaceDPoPKey: true,
        credentialGeneration: generation,
      })
    await vi.waitFor(() => {
      expect(releaseStore).toBeTypeOf('function')
    })
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      {
        callbackCode: 'authorization-code',
        compensationRequired: true,
        cleanupStarted: false,
      },
    ])

    releaseStore()
    await publication
    expect(runtime.accessToken).toBe(accessToken)
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(
      await runtime.manager.settings.stateStore.getAllKeys(),
    ).toEqual([])
    runtime.sessionOps.clearRenewTimer()
  })

  it('cleans terminal login_required custody without a retry delay', async () => {
    const transport = installSilentTransport([])
    const { runtime, generation } = silentRuntime()
    const { iframe, pending, state } =
      await pendingSilentAuthorization(
        runtime,
        generation,
        transport,
      )
    const timeout = vi.spyOn(globalThis, 'setTimeout')

    postAuthorizationResponse(iframe, state, {
      error: 'login_required',
    })
    await expect(pending).rejects.toBeInstanceOf(
      LoginRequiredError,
    )

    expect(
      timeout.mock.calls
        .map((call) => call[1])
        .filter((delay) => delay === 200 || delay === 400),
    ).toEqual([])
    expect(
      transport.mock.calls.filter(
        (call) =>
          String(call[0]) === `${ORDINARY_ISSUER}/auth/par`,
      ),
    ).toHaveLength(2)
    const settlement = ordinarySettlementCalls(transport)
    expect(settlement).toHaveLength(1)
    expect(JSON.parse(String(settlement[0][1].body))).toMatchObject({
      mode: 'terminal_only',
      client_id: ORDINARY_CLIENT_ID,
      request_uri: ORDINARY_REQUEST_URI,
    })
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(
      await runtime.manager.settings.stateStore.getAllKeys(),
    ).toEqual([])
  })

  it('compensates the exact code when local publication fails', async () => {
    const accessToken = makeJWT({
      sub: 'user-1',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
    const idToken = makeJWT({
      sub: 'user-1',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
    const transport = installSilentTransport([
      successfulTokenResponse(accessToken, idToken),
      invalidGrantResponse(),
    ])
    const { runtime, generation } = silentRuntime()
    const { iframe, pending, state } =
      await pendingSilentAuthorization(
        runtime,
        generation,
        transport,
      )
    postAuthorizationResponse(iframe, state)
    const grant = await pending
    vi.spyOn(runtime.manager, 'storeUser').mockRejectedValueOnce(
      new Error('local publication failed'),
    )

    await expect(
      runtime.credentialOps.applyAuthorizationGrant(grant, {
        expectedNonce: grant.nonce,
        dpopKey: grant.dpopKey,
        replaceDPoPKey: true,
        credentialGeneration: generation,
      }),
    ).rejects.toThrow('local publication failed')

    const exchanges = transport.mock.calls.filter(
      (call) =>
        String(call[0]) === `${ORDINARY_ISSUER}/auth/token`,
    )
    expect(exchanges).toHaveLength(2)
    expect(String((exchanges[0][1] as RequestInit).body)).toBe(
      String((exchanges[1][1] as RequestInit).body),
    )
    expect(
      new URLSearchParams(
        String((exchanges[1][1] as RequestInit).body),
      ).get('code'),
    ).toBe('authorization-code')
    const settlement = ordinarySettlementCalls(transport)
    expect(settlement).toHaveLength(1)
    expect(JSON.parse(String(settlement[0][1].body))).toMatchObject({
      mode: 'reject',
      client_id: ORDINARY_CLIENT_ID,
      request_uri: ORDINARY_REQUEST_URI,
    })
    expect(runtime.accessToken).toBeUndefined()
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(
      await runtime.manager.settings.stateStore.getAllKeys(),
    ).toEqual([])
  })

  it('retains resumable custody when post-publication cleanup fails', async () => {
    const accessToken = makeJWT({
      sub: 'user-1',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
    const idToken = makeJWT({
      sub: 'user-1',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
    const transport = installSilentTransport([
      successfulTokenResponse(accessToken, idToken),
    ])
    const { runtime, generation } = silentRuntime()
    const { iframe, pending, state } =
      await pendingSilentAuthorization(
        runtime,
        generation,
        transport,
      )
    postAuthorizationResponse(iframe, state)
    const grant = await pending
    const remove = vi
      .spyOn(runtime.manager.settings.stateStore, 'remove')
      .mockRejectedValueOnce(
        new Error('injected terminal cleanup failure'),
      )

    await expect(
      runtime.credentialOps.applyAuthorizationGrant(grant, {
        expectedNonce: grant.nonce,
        dpopKey: grant.dpopKey,
        replaceDPoPKey: true,
        credentialGeneration: generation,
      }),
    ).rejects.toThrow('injected terminal cleanup failure')

    expect(runtime.accessToken).toBeUndefined()
    expect(await readOrdinaryAuthorizationRecords()).toMatchObject([
      {
        callbackCode: 'authorization-code',
        compensationRequired: true,
        cleanupStarted: true,
      },
    ])
    expect(
      transport.mock.calls.filter(
        (call) =>
          String(call[0]) === `${ORDINARY_ISSUER}/auth/token`,
      ),
    ).toHaveLength(1)

    remove.mockRestore()
    await expect(
      runtime.ordinaryAuthorization!.finishPendingCleanup(
        generation,
      ),
    ).resolves.toBe(true)
    expect(await readOrdinaryAuthorizationRecords()).toEqual([])
    expect(
      await runtime.manager.settings.stateStore.getAllKeys(),
    ).toEqual([])
  })
})
