/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
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
import { makeJWT } from '../helpers'

const originalCrypto = globalThis.crypto
const ISSUER = 'https://id.example.com'
const CLIENT_ORIGIN = 'https://app.example.com'
const REDIRECT = `${CLIENT_ORIGIN}/callback`
const POST_LOGOUT_REDIRECT = `${CLIENT_ORIGIN}/logout`
const OPAQUE_A = 'A'.repeat(43)
const OPAQUE_B = 'B'.repeat(43)
const OPAQUE_C = 'C'.repeat(43)
const OPAQUE_D = 'D'.repeat(43)
const BOOTSTRAP_TERMINAL_PROOF =
  'oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoQ'
const TERMINAL_PROOF =
  'srKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysg'
const REQUEST_URI = `urn:ietf:params:oauth:request_uri:${OPAQUE_B}`

const manager = vi.hoisted(() => ({
  getUser: vi.fn().mockResolvedValue(null),
  storeUser: vi.fn().mockResolvedValue(undefined),
  removeUser: vi.fn().mockResolvedValue(undefined),
  signinRedirect: vi.fn().mockResolvedValue(undefined),
  signoutRedirect: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('../../src/oidc/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/oidc/oidc')>()
  return {
    ...actual,
    createUserManager: () => manager,
    userFromTokenResponse: (tokens: Record<string, unknown>) => tokens,
  }
})

const verification = vi.hoisted(() => ({
  access: vi.fn(),
  id: vi.fn(),
}))

vi.mock('../../src/verify/verify', () => ({
  verifyAccessToken: verification.access,
  verifyIdToken: verification.id,
  _resetDiscoveryCache: vi.fn(),
}))

vi.mock('../../src/token/token-broadcast', () => ({
  createTokenBroadcast: () => ({
    publish: vi.fn(),
    subscribe: vi.fn(() => () => undefined),
    close: vi.fn(),
  }),
}))

import { createAtolBrowserAuth } from '../../src/client/browser-auth'
import { ResponseVaultSettlementPendingError } from '../../src/oidc/response-vault'
import { installResponseVaultLockManager } from '../oidc/response-vault-lock-test-support'
import { readAuthorizationRecord } from '../oidc/response-vault-regression-helpers'
import { mutateDatabase } from '../oidc/response-vault-adversarial-test-support'

interface RequestCapture {
  url: string
  body: Record<string, unknown>
  init: RequestInit
}

function jsonResponse(
  body: Record<string, unknown>,
  status: number,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function bootstrap(csrf: string): Response {
  return jsonResponse(
    {
      version: 1,
      csrf_token: csrf,
      expires_in: 60,
      bootstrap_terminal_proof: BOOTSTRAP_TERMINAL_PROOF,
    },
    201,
  )
}

function bootstrapAttemptChallenge(): Response {
  const deadline = Date.now() + 59_000
  const raw = Buffer.alloc(58, 0x5a)
  raw[0] = 1
  raw[1] = 3
  raw.writeBigUInt64BE(BigInt(deadline) * 1_000_000n, 18)
  return jsonResponse(
    {
      error: 'attempt_capability_required',
      attempt_capability: raw.toString('base64url'),
      expires_in: 60,
      attempt_expires_at: new Date(deadline).toISOString(),
    },
    428,
  )
}

function issuerBootstrap(csrf: string): Response {
  return jsonResponse({ version: 1, csrf_token: csrf, expires_in: 60 }, 201)
}

function noContent(): Response {
  return new Response(null, { status: 204 })
}

function discovery(): Response {
  return jsonResponse(
    {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/auth/authorize`,
      token_endpoint: `${ISSUER}/auth/token`,
      response_modes_supported: ['query', 'atol_console_vault'],
      atol_console_browser_authorization: {
        version: 1,
        response_mode: 'atol_console_vault',
        client_id: 'example-spa',
        redirect_uri: REDIRECT,
        audience: 'https://api.example.com',
        console_origin: CLIENT_ORIGIN,
        bootstrap_endpoint: `${CLIENT_ORIGIN}/auth/browser/v1/bootstrap`,
        pushed_authorization_request_endpoint:
          `${CLIENT_ORIGIN}/auth/browser/v1/pushed-authorization-requests`,
        issuer_bootstrap_endpoint:
          `${ISSUER}/auth/browser/v1/issuer-bootstrap`,
        authorization_init_endpoint:
          `${ISSUER}/auth/browser/v1/authorization-init`,
        authorization_endpoint: `${ISSUER}/auth/authorize`,
        relay_endpoint: `${CLIENT_ORIGIN}/auth/browser/v1/relay`,
        acknowledgement_endpoint:
          `${CLIENT_ORIGIN}/auth/browser/v1/acknowledge`,
        finalization_endpoint:
          `${CLIENT_ORIGIN}/auth/browser/v1/finalize`,
        rejection_endpoint: `${CLIENT_ORIGIN}/auth/browser/v1/reject`,
      },
    },
    200,
  )
}

function deleteDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error('browser-auth vault database remained blocked')),
      2_000,
    )
    const request = indexedDB.deleteDatabase('atol-sdk-response-vault')
    request.onsuccess = () => {
      clearTimeout(timeout)
      resolve()
    }
    request.onerror = () => {
      clearTimeout(timeout)
      reject(request.error)
    }
    // A just-destroyed client may still be closing its final transaction.
    // The request remains live and succeeds when that connection closes; the
    // timeout still catches a real leak.
    request.onblocked = () => undefined
  })
}

function expectNoActiveReference(): void {
  expect(
    sessionStorage.getItem('atol:response-vault:v1:active'),
  ).toBeNull()
}

async function inUnownedCallbackFrame<T>(
  operation: () => Promise<T>,
): Promise<T> {
  const selfDescriptor = Object.getOwnPropertyDescriptor(window, 'self')
  const frameDescriptor = Object.getOwnPropertyDescriptor(
    window,
    'frameElement',
  )
  const frame = document.createElement('iframe')
  Object.defineProperty(window, 'self', {
    configurable: true,
    value: {},
  })
  Object.defineProperty(window, 'frameElement', {
    configurable: true,
    value: frame,
  })
  try {
    return await operation()
  } finally {
    if (selfDescriptor) {
      Object.defineProperty(window, 'self', selfDescriptor)
    }
    if (frameDescriptor) {
      Object.defineProperty(window, 'frameElement', frameDescriptor)
    }
  }
}

function client() {
  return createAtolBrowserAuth({
    issuer: ISSUER,
    clientId: 'example-spa',
    redirectUri: REDIRECT,
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT,
    audience: 'https://api.example.com',
    scopes: 'openid profile email',
    dpop: { required: true },
    responseVault: true,
  })
}

function installAuthorizationFetch(
  accessJKT: () => string,
  onAck?: () => Promise<Response>,
  onRelay?: (
    request: RequestCapture,
    attempt: number,
  ) => Response | Promise<Response>,
  onReject?: (
    request: RequestCapture,
  ) => Response | Promise<Response>,
  onDiscovery?: () => Response | Promise<Response>,
): RequestCapture[] {
  const captured: RequestCapture[] = []
  let relayAttempt = 0
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const request = {
        url: String(input),
        body: JSON.parse(typeof init?.body === 'string' ? init.body : '{}') as Record<
          string,
          unknown
        >,
        init: init ?? {},
      }
      captured.push(request)
      switch (request.url) {
        case `${ISSUER}/.well-known/openid-configuration`:
          return onDiscovery ? onDiscovery() : discovery()
        case `${CLIENT_ORIGIN}/auth/browser/v1/bootstrap`:
          return request.body.attempt_capability
            ? bootstrap(OPAQUE_A)
            : bootstrapAttemptChallenge()
        case `${CLIENT_ORIGIN}/auth/browser/v1/pushed-authorization-requests`:
          return jsonResponse(
            {
              version: 1,
              transaction_id: OPAQUE_A,
              request_uri: REQUEST_URI,
              expires_in: 60,
              transaction_expires_in: 600,
              csrf_token: OPAQUE_B,
              terminal_proof: TERMINAL_PROOF,
            },
            201,
          )
        case `${ISSUER}/auth/browser/v1/issuer-bootstrap`:
          return issuerBootstrap(OPAQUE_C)
        case `${ISSUER}/auth/browser/v1/authorization-init`:
          return noContent()
        case `${CLIENT_ORIGIN}/auth/browser/v1/relay`: {
          relayAttempt++
          if (onRelay) return onRelay(request, relayAttempt)
          const accessToken = makeJWT({
            sub: 'user-1',
            exp: Math.floor(Date.now() / 1000) + 3600,
            cnf: { jkt: accessJKT() },
          })
          return jsonResponse(
            {
              version: 1,
              access_token: accessToken,
              token_type: 'DPoP',
              expires_in: 3600,
              id_token: makeJWT({
                sub: 'user-1',
                exp: Math.floor(Date.now() / 1000) + 3600,
              }),
              scope: 'openid profile email',
              csrf_token: OPAQUE_D,
            },
            200,
          )
        }
        case `${CLIENT_ORIGIN}/auth/browser/v1/acknowledge`:
          return onAck ? onAck() : noContent()
        case `${CLIENT_ORIGIN}/auth/browser/v1/finalize`:
          return noContent()
        case `${CLIENT_ORIGIN}/auth/browser/v1/reject`:
          return onReject ? onReject(request) : noContent()
        default:
          throw new Error(`unexpected fetch ${request.url}`)
      }
    }),
  )
  return captured
}

beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: nodeWebCrypto,
  })
})

beforeEach(() => {
  installResponseVaultLockManager()
  localStorage.clear()
  sessionStorage.clear()
  window.history.replaceState({}, '', '/callback')
  manager.getUser.mockResolvedValue(null)
  manager.storeUser.mockResolvedValue(undefined)
  manager.removeUser.mockResolvedValue(undefined)
  manager.signoutRedirect.mockResolvedValue(undefined)
  verification.access.mockImplementation(async (token: string) =>
    JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()),
  )
  verification.id.mockImplementation(async (token: string, options: { nonce?: string }) => ({
    ...JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()),
    nonce: options.nonce,
  }))
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
})

afterEach(async () => {
  await new Promise((resolve) => setTimeout(resolve, 10))
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  await deleteDatabase()
})

afterAll(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: originalCrypto,
  })
})

describe('createAtolBrowserAuth public response-vault integration', () => {
  it('cancels an abandoned login without RP logout navigation', async () => {
    let jkt = ''
    const captured = installAuthorizationFetch(() => jkt)
    const auth = client()
    await auth.beginLogin()
    jkt = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )?.body.dpop_jkt as string

    const first = auth.cancelLogin()
    const second = auth.cancelLogin()
    expect(second).toBe(first)
    await expect(first).resolves.toBeUndefined()

    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
    expect(manager.signoutRedirect).not.toHaveBeenCalled()
    expectNoActiveReference()
    auth.destroy()
  })

  it('cancels interactive server authority when grant keys are damaged', async () => {
    const captured = installAuthorizationFetch(() => '')
    const auth = client()
    await auth.beginLogin()
    const reference = sessionStorage.getItem(
      'atol:response-vault:v1:active',
    )
    expect(reference).toMatch(/^[A-Za-z0-9_-]{43}$/)
    await mutateDatabase('authorizations', (transaction) => {
      const store = transaction.objectStore('authorizations')
      const request = store.get(reference as string)
      request.onsuccess = () => {
        const record = {
          ...(request.result as Record<string, unknown>),
        }
        delete record.keys
        store.put(record)
      }
    })

    await expect(auth.cancelLogin()).resolves.toBeUndefined()

    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
    expectNoActiveReference()
    auth.destroy()
  })

  it('serializes cancellation behind a yielding interactive login', async () => {
    let releaseDiscovery: ((response: Response) => void) | undefined
    let cancellationSettled = false
    const discoveryGate = new Promise<Response>((resolve) => {
      releaseDiscovery = resolve
    })
    const captured = installAuthorizationFetch(
      () => '',
      undefined,
      undefined,
      undefined,
      () => discoveryGate,
    )
    const auth = client()

    const login = auth.beginLogin()
    await vi.waitFor(() =>
      expect(
        captured.filter((request) =>
          request.url.endsWith('/.well-known/openid-configuration'),
        ),
      ).toHaveLength(1),
    )
    const cancellation = auth.cancelLogin().then(() => {
      cancellationSettled = true
    })
    await Promise.resolve()
    expect(cancellationSettled).toBe(false)
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(0)

    releaseDiscovery?.(discovery())
    await login
    await cancellation

    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
    expectNoActiveReference()
    auth.destroy()
  })

  it('resumes only durable rejection custody after cancellation fails', async () => {
    let jkt = ''
    let rejectionAvailable = false
    const captured = installAuthorizationFetch(
      () => jkt,
      undefined,
      undefined,
      () => {
        if (!rejectionAvailable) {
          throw new Error('rejection transport unavailable')
        }
        return noContent()
      },
    )
    const auth = client()
    await auth.beginLogin()
    jkt = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )?.body.dpop_jkt as string
    const reference = sessionStorage.getItem(
      'atol:response-vault:v1:active',
    )
    expect(reference).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const cancellation = auth.cancelLogin()
    const blockedLogin = auth.beginLogin()
    await expect(cancellation).rejects.toThrow(
      'response vault: local settlement cleanup remains pending',
    )
    await expect(blockedLogin).rejects.toThrow(
      'response vault: local settlement cleanup remains pending',
    )
    expect(manager.signoutRedirect).not.toHaveBeenCalled()
    await expect(readAuthorizationRecord(reference as string)).resolves.toMatchObject({
      custody: 'cancellation',
      rejectionProvenance: 'interactive_cancel',
      status: 'reject_retry',
    })

    rejectionAvailable = true
    await expect(auth.cancelLogin()).resolves.toBeUndefined()
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(4)
    expect(manager.signoutRedirect).not.toHaveBeenCalled()
    expectNoActiveReference()
    auth.destroy()
  })

  it('re-arms destroy cleanup only after a new login navigates', async () => {
    const captured = installAuthorizationFetch(() => '')
    const auth = client()
    await auth.beginLogin()
    await auth.cancelLogin()

    await auth.beginLogin()
    auth.destroy()

    await vi.waitFor(() =>
      expect(
        captured.filter((request) => request.url.endsWith('/reject')),
      ).toHaveLength(2),
    )
    expectNoActiveReference()
  })

  it('returns an existing cancellation flight after logout starts', async () => {
    let releaseRejection: ((response: Response) => void) | undefined
    const rejectionGate = new Promise<Response>((resolve) => {
      releaseRejection = resolve
    })
    const captured = installAuthorizationFetch(
      () => '',
      undefined,
      undefined,
      () => rejectionGate,
    )
    const auth = client()
    await auth.beginLogin()

    const first = auth.cancelLogin()
    await vi.waitFor(() =>
      expect(
        captured.filter((request) => request.url.endsWith('/reject')),
      ).toHaveLength(1),
    )
    const logout = auth.logout()
    const second = auth.cancelLogin()

    expect(second).toBe(first)
    releaseRejection?.(noContent())
    await expect(first).resolves.toBeUndefined()
    await expect(logout).resolves.toBeUndefined()
    expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
    auth.destroy()
  })

  it('finishes queued login and cancellation before same-tick logout', async () => {
    const captured = installAuthorizationFetch(() => '')
    const auth = client()

    const login = auth.beginLogin()
    const cancellation = auth.cancelLogin()
    const logout = auth.logout()
    const duplicateCancellation = auth.cancelLogin()

    expect(duplicateCancellation).toBe(cancellation)
    await expect(login).resolves.toBeUndefined()
    await expect(cancellation).resolves.toBeUndefined()
    await expect(logout).resolves.toBeUndefined()
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
    expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
    expectNoActiveReference()
    auth.destroy()
  })

  it('rejects a new cancellation admitted after logout starts', async () => {
    const auth = client()

    const logout = auth.logout()
    const cancellation = auth.cancelLogin()

    await expect(cancellation).rejects.toThrow(
      'cancelLogin is unavailable while logout is in progress',
    )
    await expect(logout).resolves.toBeUndefined()
    expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
    auth.destroy()
  })

  it('rejects cancellation after client initialization begins', async () => {
    const auth = client()
    const initialization = auth.init()

    await expect(auth.cancelLogin()).rejects.toThrow(
      'cancelLogin requires an uninitialized signed-out client',
    )
    await expect(initialization).rejects.toThrow(
      'OIDC callback failed. Please sign in again.',
    )
    expect(manager.signoutRedirect).not.toHaveBeenCalled()
    auth.destroy()
  })

  it('fails a clean callback without local custody before starting recovery', async () => {
    const fetch = vi.fn(async (input: string | URL | Request) => {
      if (
        String(input) ===
        `${ISSUER}/.well-known/openid-configuration`
      ) {
        return discovery()
      }
      throw new Error(`unexpected recovery fetch ${String(input)}`)
    })
    vi.stubGlobal('fetch', fetch)
    const auth = client()

    await expect(auth.init()).rejects.toThrow(
      'OIDC callback failed. Please sign in again.',
    )

    expect(fetch).not.toHaveBeenCalled()
    expect(await auth.getAccessToken()).toBeUndefined()
    expectNoActiveReference()
    auth.destroy()
  })

  it('completes an interactive callback in an unowned browser frame', async () => {
    let jkt = ''
    const captured = installAuthorizationFetch(() => jkt)
    const auth = client()

    await auth.beginLogin({ returnTo: '/' })
    jkt = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )?.body.dpop_jkt as string

    const session = await inUnownedCallbackFrame(() => auth.init())

    expect(session.isAuthenticated).toBe(true)
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/acknowledge')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/finalize')),
    ).toHaveLength(1)
    expectNoActiveReference()
    auth.destroy()
  })

  it('validates tokens before acknowledgement and adopts only after confirmed ack', async () => {
    let jkt = ''
    let resolveAck: ((response: Response) => void) | undefined
    const ack = new Promise<Response>((resolve) => {
      resolveAck = resolve
    })
    const captured = installAuthorizationFetch(() => jkt, () => ack)
    const auth = client()
    const popstate = vi.fn()
    window.addEventListener('popstate', popstate)
    await auth.beginLogin({
      returnTo: '/organizations?tab=active#member',
    })
    jkt = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )?.body.dpop_jkt as string
    const pushed = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )?.body
    expect(pushed).not.toHaveProperty('return_to')
    expect(pushed).not.toHaveProperty('returnTo')
    expect(pushed).toMatchObject({
      par_idempotency_key: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      cancellation_secret: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    })

    const completion = auth.completeLogin()
    await vi.waitFor(() => {
      expect(
        captured.some((request) => request.url.endsWith('/acknowledge')),
      ).toBe(true)
    })
    expect(verification.access).toHaveBeenCalledTimes(1)
    expect(verification.id).toHaveBeenCalledTimes(1)
    expect(await auth.getAccessToken()).toBeUndefined()
    expect(
      captured.some((request) => request.url.endsWith('/finalize')),
    ).toBe(false)
    expect(window.location.pathname).toBe('/callback')
    expect(popstate).not.toHaveBeenCalled()

    resolveAck?.(noContent())
    await expect(completion).resolves.toMatchObject({ isAuthenticated: true })
    expect((await auth.getAccessToken())?.token).toContain('.')
    expect(window.location.pathname).toBe('/organizations')
    expect(window.location.search).toBe('?tab=active')
    expect(window.location.hash).toBe('#member')
    expect(popstate).toHaveBeenCalledTimes(1)
    const acknowledgement = captured.find((request) =>
      request.url.endsWith('/acknowledge'),
    )
    expect(acknowledgement?.body).toEqual({
      version: 1,
      transaction_id: OPAQUE_A,
      tab_secret: pushed?.tab_secret,
      cancellation_secret: pushed?.cancellation_secret,
    })
    const finalization = captured.find((request) =>
      request.url.endsWith('/finalize'),
    )
    expect(finalization?.body).toEqual({
      version: 1,
      transaction_id: OPAQUE_A,
      tab_secret: pushed?.tab_secret,
      cancellation_secret: pushed?.cancellation_secret,
    })
    expect(finalization?.init.headers).not.toHaveProperty('X-Atol-CSRF')
    window.removeEventListener('popstate', popstate)
    auth.destroy()
  })

  it('does not acknowledge or adopt a token bound to another DPoP key', async () => {
    const captured = installAuthorizationFetch(() => 'Z'.repeat(43))
    const auth = client()
    await auth.beginLogin()
    await expect(auth.completeLogin()).rejects.toThrow(/OIDC callback failed/)
    expect(
      captured.some((request) => request.url.endsWith('/acknowledge')),
    ).toBe(false)
    expect(
      captured.some((request) => request.url.endsWith('/reject')),
    ).toBe(true)
    expect(await auth.getAccessToken()).toBeUndefined()
    expectNoActiveReference()
    auth.destroy()
  })

  it('cancels the exact family when local user storage fails before finalization', async () => {
    let jkt = ''
    const captured = installAuthorizationFetch(() => jkt)
    const auth = client()
    await auth.beginLogin()
    const pushed = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )?.body
    jkt = pushed?.dpop_jkt as string
    manager.storeUser.mockRejectedValueOnce(
      new Error('local user store failed'),
    )

    await expect(auth.completeLogin()).rejects.toThrow(
      'OIDC callback failed. Please sign in again.',
    )

    expect(
      captured.filter((request) => request.url.endsWith('/acknowledge')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/finalize')),
    ).toHaveLength(0)
    const rejection = captured.find((request) =>
      request.url.endsWith('/reject'),
    )
    expect(rejection?.body).toEqual({
      version: 1,
      mode: 'reject',
      transaction_id: OPAQUE_A,
      tab_secret: pushed?.tab_secret,
      cancellation_secret: pushed?.cancellation_secret,
    })
    expect(rejection?.init.headers).not.toHaveProperty('X-Atol-CSRF')
    expect(await auth.getAccessToken()).toBeUndefined()
    expectNoActiveReference()
    auth.destroy()
  })

  it('rejects ambiguous acknowledgement custody before one fresh silent grant', async () => {
    let jkt = ''
    let acknowledgementAttempt = 0
    const captured = installAuthorizationFetch(
      () => jkt,
      async () => {
        acknowledgementAttempt++
        if (acknowledgementAttempt <= 3) {
          throw new TypeError('lost acknowledgement response')
        }
        return noContent()
      },
    )
    const firstClient = client()
    await firstClient.beginLogin({
      returnTo: '/organizations?tab=active#member',
    })
    jkt = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )?.body.dpop_jkt as string
    await expect(firstClient.completeLogin()).rejects.toBeInstanceOf(
      ResponseVaultSettlementPendingError,
    )
    expect(await firstClient.getAccessToken()).toBeUndefined()

    const nativeCreateElement = document.createElement.bind(document)
    const iframe = nativeCreateElement('iframe')
    Object.defineProperty(iframe, 'contentWindow', {
      configurable: true,
      value: { location: { href: REDIRECT } },
    })
    vi.spyOn(document, 'createElement').mockImplementation(
      ((tagName: string) =>
        tagName.toLowerCase() === 'iframe'
          ? iframe
          : nativeCreateElement(tagName)) as typeof document.createElement,
    )

    const reloadedClient = client()
    const recovered = reloadedClient.completeLogin()
    await vi.waitFor(() => expect(iframe.parentNode).toBe(document.body))
    const pars = captured.filter((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )
    expect(pars).toHaveLength(2)
    jkt = pars[1].body.dpop_jkt as string
    iframe.dispatchEvent(new Event('load'))

    await expect(recovered).resolves.toMatchObject({ isAuthenticated: true })
    expect(
      captured.filter((request) => request.url.endsWith('/relay')),
    ).toHaveLength(2)
    expect(
      captured.filter((request) => request.url.endsWith('/reject')),
    ).toHaveLength(1)
    expect(
      captured.filter((request) => request.url.endsWith('/finalize')),
    ).toHaveLength(1)
    const rejection = captured.find((request) =>
      request.url.endsWith('/reject'),
    )
    expect(rejection?.body).toEqual({
      version: 1,
      mode: 'reject',
      transaction_id: OPAQUE_A,
      tab_secret: pars[0].body.tab_secret,
      cancellation_secret: pars[0].body.cancellation_secret,
    })
    const finalization = captured.find((request) =>
      request.url.endsWith('/finalize'),
    )
    expect(finalization?.body).toEqual({
      version: 1,
      transaction_id: OPAQUE_A,
      tab_secret: pars[1].body.tab_secret,
      cancellation_secret: pars[1].body.cancellation_secret,
    })
    expect(await reloadedClient.getAccessToken()).toBeDefined()
    expect(window.location.pathname).toBe('/organizations')
    expect(window.location.search).toBe('?tab=active')
    expect(window.location.hash).toBe('#member')
    firstClient.destroy()
    reloadedClient.destroy()
  })

  it('fails a callback invalidated before logout can redirect', async () => {
    let jkt = ''
    const captured = installAuthorizationFetch(() => jkt)
    const auth = client()
    await auth.beginLogin()
    jkt = captured.find((request) =>
      request.url.endsWith('/pushed-authorization-requests'),
    )?.body.dpop_jkt as string
    await auth.logout()

    await expect(auth.completeLogin()).rejects.toThrow(
      'OIDC callback failed. Please sign in again.',
    )
    expect(
      captured.some((request) => request.url.endsWith('/relay')),
    ).toBe(false)
    expect(manager.signoutRedirect).toHaveBeenCalledTimes(1)
    auth.destroy()
  })

})
