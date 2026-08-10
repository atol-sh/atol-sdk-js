import 'fake-indexeddb/auto'
import { webcrypto as nodeWebCrypto } from 'node:crypto'
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  expect,
  vi,
} from 'vitest'
import {
  ResponseVault,
  type ResponseVaultConfig,
  type ResponseVaultGrant,
} from '../../src/oidc/response-vault'
import { installResponseVaultLockManager } from './response-vault-lock-test-support'

export const ISSUER = 'https://id.example.com'
export const CLIENT_ORIGIN = 'https://app.example.com'
export const REDIRECT = `${CLIENT_ORIGIN}/callback`
export const OPAQUE_A = 'A'.repeat(43)
export const OPAQUE_B = 'B'.repeat(43)
export const OPAQUE_C = 'C'.repeat(43)
export const OPAQUE_D = 'D'.repeat(43)
export const BOOTSTRAP_TERMINAL_PROOF =
  'oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoQ'
export const TERMINAL_PROOF =
  'srKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysg'
export const REQUEST_URI =
  `urn:ietf:params:oauth:request_uri:${OPAQUE_B}`
export const DISCOVERY_URL =
  `${ISSUER}/.well-known/openid-configuration`

export interface CapturedRequest {
  url: string
  init: RequestInit
  body: Record<string, unknown>
}

type FetchRouter = (
  request: CapturedRequest,
) => Response | Promise<Response>

const originalCrypto = globalThis.crypto
const createdVaults = new Set<ResponseVault>()

export function newVault(
  overrides: Partial<ResponseVaultConfig> = {},
): ResponseVault {
  const vault = new ResponseVault({
    issuer: ISSUER,
    clientId: 'example-spa',
    redirectUri: REDIRECT,
    audience: 'https://api.example.com',
    scope: 'openid profile email',
    iframeTimeoutMs: 500,
    operationTimeoutMs: 50,
    ...overrides,
  })
  createdVaults.add(vault)
  return vault
}

export function jsonResponse(
  body: Record<string, unknown>,
  status: number,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json',
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

export function bootstrapAttemptChallenge(): Response {
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

export function relaySuccess(): Response {
  return jsonResponse(
    {
      version: 1,
      access_token: 'access-token',
      token_type: 'DPoP',
      expires_in: 3600,
      id_token: 'id-token',
      scope: 'openid profile email',
      csrf_token: OPAQUE_D,
    },
    200,
  )
}

export function terminalRelay(error: string): Response {
  return jsonResponse(
    {
      version: 1,
      error,
      csrf_token: OPAQUE_D,
    },
    400,
  )
}

export function tombstone(): Response {
  return jsonResponse({ version: 1, error: 'invalid_request' }, 400)
}

export function noContent(): Response {
  return new Response(null, { status: 204 })
}

export function discoveryDocument(
  configOverrides: Partial<ResponseVaultConfig> = {},
  metadataOverrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const issuer = configOverrides.issuer ?? ISSUER
  const clientId = configOverrides.clientId ?? 'example-spa'
  const redirectUri = configOverrides.redirectUri ?? REDIRECT
  const audience =
    configOverrides.audience ?? 'https://api.example.com'
  const clientOrigin = new URL(redirectUri).origin
  return {
    issuer,
    authorization_endpoint: `${issuer}/auth/authorize`,
    token_endpoint: `${issuer}/auth/token`,
    response_modes_supported: ['query', 'atol_console_vault'],
    atol_console_browser_authorization: {
      version: 1,
      response_mode: 'atol_console_vault',
      client_id: clientId,
      redirect_uri: redirectUri,
      audience,
      console_origin: clientOrigin,
      bootstrap_endpoint: `${clientOrigin}/auth/browser/v1/bootstrap`,
      pushed_authorization_request_endpoint:
        `${clientOrigin}/auth/browser/v1/pushed-authorization-requests`,
      issuer_bootstrap_endpoint:
        `${issuer}/auth/browser/v1/issuer-bootstrap`,
      authorization_init_endpoint:
        `${issuer}/auth/browser/v1/authorization-init`,
      authorization_endpoint: `${issuer}/auth/authorize`,
      relay_endpoint: `${clientOrigin}/auth/browser/v1/relay`,
      acknowledgement_endpoint:
        `${clientOrigin}/auth/browser/v1/acknowledge`,
      finalization_endpoint:
        `${clientOrigin}/auth/browser/v1/finalize`,
      rejection_endpoint: `${clientOrigin}/auth/browser/v1/reject`,
      ...metadataOverrides,
    },
  }
}

export function discoveryResponse(
  configOverrides: Partial<ResponseVaultConfig> = {},
  metadataOverrides: Record<string, unknown> = {},
): Response {
  return jsonResponse(
    discoveryDocument(configOverrides, metadataOverrides),
    200,
  )
}

export function protocolStartResponse(
  request: CapturedRequest,
): Response | undefined {
  if (request.url === `${CLIENT_ORIGIN}/auth/browser/v1/bootstrap`) {
    return request.body.attempt_capability
      ? bootstrap(OPAQUE_A)
      : bootstrapAttemptChallenge()
  }
  if (
    request.url ===
    `${CLIENT_ORIGIN}/auth/browser/v1/pushed-authorization-requests`
  ) {
    return pushed()
  }
  if (request.url === `${ISSUER}/auth/browser/v1/issuer-bootstrap`) {
    return issuerBootstrap(OPAQUE_C)
  }
  if (request.url === `${ISSUER}/auth/browser/v1/authorization-init`) {
    return noContent()
  }
  if (request.url === `${CLIENT_ORIGIN}/auth/browser/v1/finalize`) {
    return noContent()
  }
  return undefined
}

export async function completeGrantPublication(
  grant: ResponseVaultGrant,
): Promise<void> {
  await grant.acknowledge()
  await grant.finalize()
  await grant.completePublication()
}

export function installFetchRouter(
  router: FetchRouter,
  discoveryResponses: Response[] = [],
): CapturedRequest[] {
  const captured: CapturedRequest[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input) === DISCOVERY_URL) {
        return discoveryResponses.shift() ?? discoveryResponse()
      }
      const rawBody = typeof init?.body === 'string' ? init.body : '{}'
      const request: CapturedRequest = {
        url: String(input),
        init: init ?? {},
        body: JSON.parse(rawBody) as Record<string, unknown>,
      }
      captured.push(request)
      return router(request)
    }),
  )
  return captured
}

export function rejectWhenAborted(
  request: CapturedRequest,
  onAbort?: () => void,
): Promise<Response> {
  return new Promise((_resolve, reject) => {
    const signal = request.init.signal
    if (!signal) {
      reject(new Error('test fetch did not receive an AbortSignal'))
      return
    }
    const abort = () => {
      onAbort?.()
      reject(new DOMException('The operation was aborted', 'AbortError'))
    }
    if (signal.aborted) {
      abort()
      return
    }
    signal.addEventListener('abort', abort, { once: true })
  })
}

export function activeReference(): string | undefined {
  return (
    sessionStorage.getItem('atol:response-vault:v1:active') ??
    undefined
  )
}

export function expectNoActiveReference(): void {
  expect(activeReference()).toBeUndefined()
}

export function readAuthorizationRecord(
  id: string,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('atol-sdk-response-vault', 5)
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const db = open.result
      const tx = db.transaction('authorizations', 'readonly')
      const request = tx.objectStore('authorizations').get(id)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        resolve(request.result as Record<string, unknown>)
      }
      tx.oncomplete = () => db.close()
      tx.onerror = () => reject(tx.error)
    }
  })
}

export function readAuthorizationSlots(): Promise<
  Array<Record<string, unknown>>
> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('atol-sdk-response-vault', 5)
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const db = open.result
      const tx = db.transaction('authorization-slots', 'readonly')
      const request = tx.objectStore('authorization-slots').getAll()
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        resolve(request.result as Array<Record<string, unknown>>)
      }
      tx.oncomplete = () => db.close()
      tx.onerror = () => reject(tx.error)
    }
  })
}

function deleteDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error('response-vault regression database remained blocked')),
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

export function installResponseVaultRegressionHooks(): void {
  beforeAll(() => {
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: nodeWebCrypto,
    })
  })

  beforeEach(() => {
    installResponseVaultLockManager()
    createdVaults.clear()
    localStorage.clear()
    sessionStorage.clear()
    window.history.replaceState({}, '', '/callback')
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(async () => {
    await Promise.all(
      [...createdVaults].map((vault) =>
        vault.invalidateLifecycle().catch(() => undefined),
      ),
    )
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
