import 'fake-indexeddb/auto'
import { webcrypto as nodeWebCrypto } from 'node:crypto'
import { afterAll, afterEach, beforeAll, beforeEach, vi } from 'vitest'
import {
  ResponseVault,
  type ResponseVaultConfig,
} from '../../src/oidc/response-vault'
import { installResponseVaultLockManager } from './response-vault-lock-test-support'
import {
  CLIENT_ORIGIN,
  DISCOVERY_URL,
  ISSUER,
  OPAQUE_A,
  OPAQUE_B,
  OPAQUE_C,
  OPAQUE_D,
  REDIRECT,
  REQUEST_URI,
  activeReference,
  bootstrapAttemptChallenge,
  completeGrantPublication,
  discoveryDocument,
  expectNoActiveReference,
  noContent,
  readAuthorizationRecord,
  type CapturedRequest,
} from './response-vault-regression-helpers'

export {
  CLIENT_ORIGIN,
  DISCOVERY_URL,
  ISSUER,
  OPAQUE_A,
  OPAQUE_B,
  OPAQUE_C,
  OPAQUE_D,
  REDIRECT,
  REQUEST_URI,
  activeReference,
  completeGrantPublication,
  discoveryDocument,
  expectNoActiveReference,
  noContent,
  readAuthorizationRecord,
}
export type { CapturedRequest }

export const DPOP_NONCE = 'N'.repeat(54)
export const PAR_PATH = '/auth/browser/v1/pushed-authorization-requests'
export const ORGANIZATION_ID = '01KV4BNVVNZ4TNY0PP0CVXPZWP'

export const BOOTSTRAP_TERMINAL_PROOF =
  'oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoQ'
export const TERMINAL_PROOF =
  'srKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysg'
const originalCrypto = globalThis.crypto

export function jsonResponse(
  body: Record<string, unknown> | string,
  status: number,
  headers: Record<string, string> = {},
): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json',
      ...headers,
    },
  })
}

export function bootstrap(csrfToken: string): Response {
  return jsonResponse(
    {
      version: 1,
      csrf_token: csrfToken,
      expires_in: 60,
      bootstrap_terminal_proof: BOOTSTRAP_TERMINAL_PROOF,
    },
    201,
  )
}

export function issuerBootstrap(csrfToken: string): Response {
  return jsonResponse(
    { version: 1, csrf_token: csrfToken, expires_in: 60 },
    201,
  )
}

export function pushed(): Response {
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
}

export function relaySuccess(csrfToken = OPAQUE_D): Response {
  return jsonResponse(
    {
      version: 1,
      access_token: 'access-token',
      token_type: 'DPoP',
      expires_in: 3600,
      id_token: 'id-token',
      scope: 'openid profile email',
      csrf_token: csrfToken,
    },
    200,
    { 'DPoP-Nonce': DPOP_NONCE },
  )
}

export function newVault(
  overrides: Partial<ResponseVaultConfig> = {},
): ResponseVault {
  return new ResponseVault({
    issuer: ISSUER,
    clientId: 'example-spa',
    redirectUri: REDIRECT,
    audience: 'https://api.example.com',
    scope: 'openid profile email',
    iframeTimeoutMs: 500,
    ...overrides,
  })
}

export function installFetch(
  responses: Array<
    | Response
    | Error
    | ((request: CapturedRequest) => Response | Promise<Response>)
  >,
  discovery: Response | Partial<ResponseVaultConfig> = {},
): CapturedRequest[] {
  const captured: CapturedRequest[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input) === DISCOVERY_URL) {
        return discovery instanceof Response
          ? discovery
          : jsonResponse(discoveryDocument(discovery), 200)
      }
      const rawBody = typeof init?.body === 'string' ? init.body : '{}'
      const request: CapturedRequest = {
        url: String(input),
        init: init ?? {},
        body: JSON.parse(rawBody) as Record<string, unknown>,
      }
      if (
        request.url ===
          `${CLIENT_ORIGIN}/auth/browser/v1/bootstrap` &&
        !request.body.attempt_capability
      ) {
        return bootstrapAttemptChallenge()
      }
      captured.push(request)
      if (request.url === `${CLIENT_ORIGIN}/auth/browser/v1/finalize`) {
        return noContent()
      }
      const next = responses.shift()
      if (!next) throw new Error(`unexpected fetch: ${request.url}`)
      if (next instanceof Error) throw next
      return typeof next === 'function' ? await next(request) : next
    }),
  )
  return captured
}

export function proofParts(proof: unknown): {
  header: Record<string, unknown>
  payload: Record<string, unknown>
} {
  if (typeof proof !== 'string') {
    throw new Error('test proof is missing')
  }
  const [header, payload] = proof.split('.')
  return {
    header: JSON.parse(Buffer.from(header, 'base64url').toString()) as Record<
      string,
      unknown
    >,
    payload: JSON.parse(Buffer.from(payload, 'base64url').toString()) as Record<
      string,
      unknown
    >,
  }
}

function deleteDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error('response-vault test database remained blocked')),
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
    request.onblocked = () => undefined
  })
}

export function installResponseVaultProtocolHooks(): void {
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
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(async () => {
    if (activeReference()) {
      await newVault()
        .invalidateLifecycle()
        .catch(() => undefined)
    }
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
}
