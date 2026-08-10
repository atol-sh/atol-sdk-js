/**
 * @vitest-environment jsdom
 * @vitest-environment-options {"url":"https://app.example.com/callback"}
 */

import 'fake-indexeddb/auto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createAtolBrowserAuth,
  makeJWT,
  manager,
} from './browser-auth-harness'
import {
  rotateLogoutGeneration,
  type CredentialGenerationBinding,
} from '../../src/oidc/credential-generation'
import { installResponseVaultLockManager } from '../oidc/response-vault-lock-test-support'

const ISSUER = 'https://id.example.com'
const CLIENT_ID = 'example-spa'
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
const binding: CredentialGenerationBinding = {
  issuer: ISSUER,
  clientId: CLIENT_ID,
  redirectUri: REDIRECT,
}

interface RequestCapture {
  url: string
  body: Record<string, unknown>
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
        client_id: CLIENT_ID,
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

function client() {
  return createAtolBrowserAuth({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT,
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT,
    audience: 'https://api.example.com',
    scopes: 'openid profile email',
    dpop: { required: true },
    responseVault: true,
  })
}

function installAuthorizationFetch(): RequestCapture[] {
  const captured: RequestCapture[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const request = {
        url: String(input),
        body: JSON.parse(
          typeof init?.body === 'string' ? init.body : '{}',
        ) as Record<string, unknown>,
      }
      captured.push(request)
      switch (request.url) {
        case `${ISSUER}/.well-known/openid-configuration`:
          return discovery()
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
          return new Response(null, { status: 204 })
        case `${CLIENT_ORIGIN}/auth/browser/v1/relay`: {
          const pushed = [...captured].reverse().find(({ url }) =>
            url.endsWith('/pushed-authorization-requests'),
          )
          const jkt = pushed?.body.dpop_jkt
          return jsonResponse(
            {
              version: 1,
              access_token: makeJWT({
                sub: 'user-1',
                exp: Math.floor(Date.now() / 1000) + 3600,
                cnf: { jkt },
              }),
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
        case `${CLIENT_ORIGIN}/auth/browser/v1/finalize`:
        case `${CLIENT_ORIGIN}/auth/browser/v1/reject`:
          return new Response(null, { status: 204 })
        default:
          throw new Error(`unexpected fetch ${request.url}`)
      }
    }),
  )
  return captured
}

function activePointer(): { key: string; id: string } {
  const key = 'atol:response-vault:v1:active'
  const id = sessionStorage.getItem(key)
  if (id) return { key, id }
  throw new Error('response-vault pointer is missing')
}

function storageKey(storage: Storage, marker: string): string {
  for (let index = 0; index < storage.length; index++) {
    const key = storage.key(index)
    if (key?.includes(marker)) return key
  }
  throw new Error(`storage key ${marker} is missing`)
}

function corruptAuthorizationRecord(id: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('atol-sdk-response-vault', 5)
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const db = open.result
      const tx = db.transaction('authorizations', 'readwrite')
      const store = tx.objectStore('authorizations')
      const read = store.get(id)
      read.onerror = () => reject(read.error)
      read.onsuccess = () => {
        const record = read.result as Record<string, unknown>
        store.put({
          ...record,
          lifecycleEpoch: 'corrupt',
          credentialGeneration: {
            logout: 'corrupt',
            tabOwner: 'corrupt',
          },
        })
      }
      tx.oncomplete = () => {
        db.close()
        resolve()
      }
      tx.onerror = () => {
        db.close()
        reject(tx.error)
      }
    }
  })
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

beforeEach(() => {
  installResponseVaultLockManager()
  localStorage.clear()
  sessionStorage.clear()
  window.history.replaceState({}, '', '/callback')
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
})

afterEach(async () => {
  await new Promise((resolve) => setTimeout(resolve, 10))
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  await deleteDatabase()
})

describe('createAtolBrowserAuth response-vault generation fencing', () => {
  it('rejects a rotated callback before the first relay request', async () => {
    const captured = installAuthorizationFetch()
    const original = client()
    await original.beginLogin()
    rotateLogoutGeneration(binding)

    // A new client represents a callback reload that did not receive the
    // logout signal. The durable authorization still carries the old pair.
    const reloaded = client()
    await expect(reloaded.completeLogin()).rejects.toThrow(
      'OIDC callback failed. Please sign in again.',
    )

    expect(
      captured.filter(({ url }) =>
        url.endsWith('/auth/browser/v1/relay'),
      ),
    ).toHaveLength(0)
    const pushed = captured.find(({ url }) =>
      url.endsWith('/pushed-authorization-requests'),
    )
    const rejection = captured.find(({ url }) =>
      url.endsWith('/auth/browser/v1/reject'),
    )
    expect(rejection?.body).toEqual({
      version: 1,
      mode: 'reject',
      transaction_id: OPAQUE_A,
      tab_secret: pushed?.body.tab_secret,
      cancellation_secret: pushed?.body.cancellation_secret,
    })
    expect(manager.storeUser).not.toHaveBeenCalled()
    reloaded.destroy()
    original.destroy()
  })

  it('fails live credentials closed after the origin generation rotates', async () => {
    const captured = installAuthorizationFetch()
    const auth = client()
    await auth.beginLogin()

    await expect(auth.completeLogin()).resolves.toMatchObject({
      isAuthenticated: true,
    })
    expect(await auth.getAccessToken()).toBeDefined()
    const pushed = captured.find(({ url }) =>
      url.endsWith('/pushed-authorization-requests'),
    )
    const finalization = captured.find(({ url }) =>
      url.endsWith('/auth/browser/v1/finalize'),
    )
    expect(finalization?.body).toEqual({
      version: 1,
      transaction_id: OPAQUE_A,
      tab_secret: pushed?.body.tab_secret,
      cancellation_secret: pushed?.body.cancellation_secret,
    })

    rotateLogoutGeneration(binding)

    await expect(auth.getAccessToken()).rejects.toThrow(
      'credential transaction was superseded',
    )
    await expect(auth.getAccessToken()).resolves.toBeUndefined()
    expect(auth.getIdToken()).toBeUndefined()
    await vi.waitFor(() =>
      expect(manager.removeUser).toHaveBeenCalled(),
    )
    auth.destroy()
    await vi.waitFor(() =>
      expect(
        captured.filter(({ url }) =>
          url.endsWith('/auth/browser/v1/reject'),
        ),
      ).toHaveLength(1),
    )
  })

  it('does not let corrupt custody state block cleanup or signout', async () => {
    installAuthorizationFetch()
    const auth = client()
    await auth.beginLogin()
    const pointer = activePointer()

    rotateLogoutGeneration(binding)
    const logoutKey = storageKey(localStorage, ':logout:')
    const tabOwnerKey = storageKey(sessionStorage, ':tab-owner:')
    await corruptAuthorizationRecord(pointer.id)
    localStorage.setItem(logoutKey, 'corrupt')
    sessionStorage.setItem(tabOwnerKey, 'corrupt')
    sessionStorage.setItem(pointer.key, 'corrupt')

    const logoutError = await auth.logout().then(
      () => undefined,
      (error: unknown) => error,
    )

    expect(manager.removeUser).toHaveBeenCalledTimes(1)
    expect(manager.signoutRedirect).toHaveBeenCalledWith(expect.objectContaining({
      post_logout_redirect_uri: POST_LOGOUT_REDIRECT,
      state: {
        atol_browser_auth_logout: {
          logout_generation: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
          version: 1,
        },
      },
    }))
    expect(sessionStorage.getItem(pointer.key)).toBeNull()
    expect(JSON.parse(localStorage.getItem(logoutKey)!)).toMatchObject({
      version: 1,
      generation: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      status: 'signed_out',
    })
    expect(sessionStorage.getItem(tabOwnerKey)).toMatch(
      /^[A-Za-z0-9_-]{43}$/,
    )
    if (logoutError !== undefined) {
      expect(logoutError).toBeInstanceOf(Error)
    }
    auth.destroy()
  })
})
