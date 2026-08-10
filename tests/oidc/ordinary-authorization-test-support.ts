import { bytesToBase64Url } from '../../src/crypto/base64url'
import { createDPoPKeyManager } from '../../src/dpop/dpop'
import {
  credentialGenerationForLogin,
  type CredentialGenerationSnapshot,
} from '../../src/oidc/credential-generation'
import {
  OrdinaryBrowserAuthorization,
  type OrdinaryAuthorizationStart,
} from '../../src/oidc/ordinary-authorization'
import {
  authorizationState,
  createUserManager,
} from '../../src/oidc/oidc'
import { generateAuthorizationNonce } from '../../src/oidc/silent-renew'
import { vi } from 'vitest'

export const ORDINARY_ISSUER = 'https://auth.atol.test'
export const ORDINARY_CLIENT_ID = 'atol_kid_test'
export const ORDINARY_REDIRECT_URI = 'https://app.test/cb'
export const ORDINARY_SCOPE = 'openid profile email'
export const ORDINARY_REQUEST_URI =
  `urn:ietf:params:oauth:request_uri:${bytesToBase64Url(
    new Uint8Array(32).fill(7),
  )}`

export function ordinaryTerminalProof(
  rootExpiresAtMs: number,
): string {
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

export interface OrdinaryAuthorizationHarness {
  manager: ReturnType<typeof createUserManager>
  authorization: OrdinaryBrowserAuthorization
  navigations: string[]
  generation: CredentialGenerationSnapshot
}

export function installOrdinaryAuthorizationLocks(): void {
  const held = new Set<string>()
  Object.defineProperty(navigator, 'locks', {
    configurable: true,
    value: {
      async request<T>(
        name: string,
        options: { ifAvailable?: boolean },
        callback: (lock: Lock | null) => Promise<T> | T,
      ): Promise<T> {
        if (held.has(name)) {
          if (options.ifAvailable) return callback(null)
          throw new Error('test lock manager only supports ifAvailable')
        }
        held.add(name)
        try {
          return await callback({ name, mode: 'exclusive' } as Lock)
        } finally {
          held.delete(name)
        }
      },
    },
  })
}

export function ordinaryDiscovery(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    issuer: ORDINARY_ISSUER,
    authorization_endpoint: `${ORDINARY_ISSUER}/auth/authorize`,
    token_endpoint: `${ORDINARY_ISSUER}/auth/token`,
    pushed_authorization_request_endpoint:
      `${ORDINARY_ISSUER}/auth/par`,
    require_pushed_authorization_requests: true,
    atol_browser_authorization: {
      version: 2,
      ceremony_lifetime_seconds: 900,
      authorization_code_lifetime_seconds: 600,
      pre_navigation_cancellation_endpoint:
        `${ORDINARY_ISSUER}/auth/par/pre-navigation-cancellation`,
      settlement_endpoint:
        `${ORDINARY_ISSUER}/auth/par/settlement`,
    },
    ...overrides,
  }
}

export function ordinaryAdmittedResponse(
  rootExpiresAtMs: number,
  overrides: Record<string, unknown> = {},
): Response {
  return new Response(
    JSON.stringify({
      request_uri: ORDINARY_REQUEST_URI,
      expires_in: 900,
      authorization_code_expires_in: 600,
      atol_browser_authorization_version: 2,
      atol_browser_authorization_expires_at:
        new Date(rootExpiresAtMs).toISOString(),
      terminal_proof: ordinaryTerminalProof(rootExpiresAtMs),
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

export function ordinaryAttemptChallenge(
  rootExpiresAtMs: number,
  expiresIn = 800,
): Response {
  const raw = new Uint8Array(58)
  raw[0] = 1
  raw[1] = 2
  let deadline = BigInt(rootExpiresAtMs) * 1_000_000n
  for (let index = 25; index >= 18; index--) {
    raw[index] = Number(deadline & 0xffn)
    deadline >>= 8n
  }
  return new Response(
    JSON.stringify({
      error: 'attempt_capability_required',
      attempt_capability: bytesToBase64Url(raw),
      expires_in: expiresIn,
      attempt_expires_at:
        new Date(rootExpiresAtMs).toISOString(),
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

export function browserVisibleOrdinaryResponse(
  response: Response,
): Response {
  const visible = new Headers()
  for (const name of ['Cache-Control', 'Content-Type']) {
    const value = response.headers.get(name)
    if (value !== null) visible.set(name, value)
  }
  if (
    response.headers.get('Access-Control-Allow-Origin') ===
      window.location.origin &&
    response.headers.get('Access-Control-Expose-Headers') ===
      'Atol-Browser-Authorization'
  ) {
    const signal = response.headers.get(
      'Atol-Browser-Authorization',
    )
    if (signal !== null) {
      visible.set('Atol-Browser-Authorization', signal)
    }
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: visible,
  })
}

export function installOrdinaryTransport(
  par: Array<Response | Error>,
  metadata: Record<string, unknown> = ordinaryDiscovery(),
  settlement: Array<Response | Error> = [],
  preNavigation: Array<Response | Error> = [],
): ReturnType<typeof vi.fn> {
  let parIndex = 0
  let settlementIndex = 0
  let preNavigationIndex = 0
  const transport = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/.well-known/openid-configuration')) {
        return new Response(JSON.stringify(metadata), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (url === `${ORDINARY_ISSUER}/auth/par`) {
        const result = par[parIndex++]
        if (result instanceof Error) throw result
        if (!result) throw new Error('unexpected PAR request')
        return browserVisibleOrdinaryResponse(result)
      }
      if (
        url ===
        `${ORDINARY_ISSUER}/auth/par/pre-navigation-cancellation`
      ) {
        const result = preNavigation[preNavigationIndex++]
        if (result instanceof Error) throw result
        if (result) return browserVisibleOrdinaryResponse(result)
        return browserVisibleOrdinaryResponse(
          new Response(null, {
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
      if (url === `${ORDINARY_ISSUER}/auth/par/settlement`) {
        const result = settlement[settlementIndex++]
        if (result instanceof Error) throw result
        if (result) return browserVisibleOrdinaryResponse(result)
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
      throw new Error(
        `unexpected request: ${url} ${init?.method ?? 'GET'}`,
      )
    },
  )
  vi.stubGlobal('fetch', transport)
  return transport
}

export function ordinaryHarness(
  scope = ORDINARY_SCOPE,
): OrdinaryAuthorizationHarness {
  const manager = createUserManager(
    ORDINARY_ISSUER,
    ORDINARY_CLIENT_ID,
    ORDINARY_REDIRECT_URI,
    scope,
    'https://api.atol.test',
  )
  const navigations: string[] = []
  const authorization = new OrdinaryBrowserAuthorization(
    manager,
    {
      issuer: ORDINARY_ISSUER,
      clientId: ORDINARY_CLIENT_ID,
      redirectUri: ORDINARY_REDIRECT_URI,
      scope,
    },
    (url) => navigations.push(url),
  )
  const generation = credentialGenerationForLogin({
    issuer: ORDINARY_ISSUER,
    clientId: ORDINARY_CLIENT_ID,
    redirectUri: ORDINARY_REDIRECT_URI,
  })
  return { manager, authorization, navigations, generation }
}

export function ordinaryStart(
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

export function ordinaryParCalls(
  transport: ReturnType<typeof vi.fn>,
): Array<[RequestInfo | URL, RequestInit]> {
  return transport.mock.calls.filter(
    (call) =>
      String(call[0]) === `${ORDINARY_ISSUER}/auth/par`,
  ) as Array<[RequestInfo | URL, RequestInit]>
}

export function ordinarySettlementCalls(
  transport: ReturnType<typeof vi.fn>,
): Array<[RequestInfo | URL, RequestInit]> {
  return transport.mock.calls.filter(
    (call) =>
      String(call[0]) ===
      `${ORDINARY_ISSUER}/auth/par/settlement`,
  ) as Array<[RequestInfo | URL, RequestInit]>
}

export function ordinaryPreNavigationCalls(
  transport: ReturnType<typeof vi.fn>,
): Array<[RequestInfo | URL, RequestInit]> {
  return transport.mock.calls.filter(
    (call) =>
      String(call[0]) ===
      `${ORDINARY_ISSUER}/auth/par/pre-navigation-cancellation`,
  ) as Array<[RequestInfo | URL, RequestInit]>
}

export function ordinaryPointerKey(): string {
  for (let index = 0; index < sessionStorage.length; index++) {
    const key = sessionStorage.key(index)
    if (key?.includes('ordinary-authorization')) return key
  }
  throw new Error('ordinary authorization pointer is missing')
}

export function resetOrdinaryAuthorizationDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase('atol-sdk-browser-auth')
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () =>
      reject(
        new Error('ordinary authorization test database is blocked'),
      )
  })
}

function openTestDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('atol-sdk-browser-auth', 2)
    request.onupgradeneeded = () => {
      if (
        !request.result.objectStoreNames.contains(
          'ordinary-authorizations',
        )
      ) {
        request.result.createObjectStore(
          'ordinary-authorizations',
          { keyPath: 'slotKey' },
        )
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

export async function readOrdinaryAuthorizationRecords(): Promise<
  Array<Record<string, unknown>>
> {
  const db = await openTestDatabase()
  try {
    const transaction = db.transaction(
      'ordinary-authorizations',
      'readonly',
    )
    const request = transaction
      .objectStore('ordinary-authorizations')
      .getAll()
    return await new Promise((resolve, reject) => {
      request.onsuccess = () =>
        resolve(request.result as Array<Record<string, unknown>>)
      request.onerror = () => reject(request.error)
    })
  } finally {
    db.close()
  }
}

export async function putOrdinaryAuthorizationRecord(
  record: Record<string, unknown>,
): Promise<void> {
  const db = await openTestDatabase()
  try {
    const transaction = db.transaction(
      'ordinary-authorizations',
      'readwrite',
    )
    transaction
      .objectStore('ordinary-authorizations')
      .put(record)
    await new Promise<void>((resolve, reject) => {
      transaction.oncomplete = () => resolve()
      transaction.onerror = () => reject(transaction.error)
      transaction.onabort = () => reject(transaction.error)
    })
  } finally {
    db.close()
  }
}
