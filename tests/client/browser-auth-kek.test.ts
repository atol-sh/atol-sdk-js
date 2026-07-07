/**
 * Zero-knowledge KEK/DEK orchestration inside createAtolBrowserAuth.
 *
 * The core client owns the encryption-key flow now (it moved out of the
 * React provider): on a fresh login-callback it captures the KEK from the
 * URL fragment BEFORE the callback URL is stripped, provisions the
 * device-bound vault, and unwraps the DEK from the ID token's
 * `atol:wrapped_dek` claim; on a restore/renew it rehydrates from the vault.
 *
 * These tests are adversarial: they assert
 *   - success: a correctly-wrapped DEK surfaces as encryptionKey (session
 *     payload + getEncryptionKey accessor), no error;
 *   - TAMPER: an AES-GCM auth-tag failure surfaces as encryptionError and
 *     leaves NO key (fail loud, never a silently-wrong key);
 *   - feature OFF: no key, no error, and the URL fragment is never read;
 *   - fragment ordering: the KEK is captured before the callback URL is
 *     stripped (the whole reason this moved into the core);
 *   - rehydrate across a silent renew keeps the key;
 *   - missing wrapped_dek claim: graceful (no key, no crash);
 *   - logout clears the key.
 *
 * Runs under fake-indexeddb (vault I/O) and Node's real WebCrypto (jsdom has
 * no usable crypto.subtle).
 */
import 'fake-indexeddb/auto'
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
import { webcrypto as nodeWebCrypto } from 'node:crypto'
import { makeAccessToken, makeIDToken } from '../helpers'

// Real WebCrypto: the vault's device key + AES-GCM unwrap need a working
// crypto.subtle, which jsdom does not provide.
const originalCrypto = globalThis.crypto
beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: nodeWebCrypto })
})
afterAll(() => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: originalCrypto })
})

// ---- Mock the oidc-client-ts UserManager wrapper (same shape as the main
// browser-auth test). ----
type ManagerSpies = {
  signinRedirect: ReturnType<typeof vi.fn>
  signinRedirectCallback: ReturnType<typeof vi.fn>
  signoutRedirect: ReturnType<typeof vi.fn>
  getUser: ReturnType<typeof vi.fn>
  storeUser: ReturnType<typeof vi.fn>
  removeUser: ReturnType<typeof vi.fn>
}

let manager: ManagerSpies

function freshManager(): ManagerSpies {
  return {
    signinRedirect: vi.fn().mockResolvedValue(undefined),
    signinRedirectCallback: vi.fn().mockResolvedValue(null),
    signoutRedirect: vi.fn().mockResolvedValue(undefined),
    getUser: vi.fn().mockResolvedValue(null),
    storeUser: vi.fn().mockResolvedValue(undefined),
    removeUser: vi.fn().mockResolvedValue(undefined),
  }
}

vi.mock('../../src/oidc/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/oidc/oidc')>()
  return {
    ...actual,
    createUserManager: () => manager as unknown as object,
    getAccessToken: (u: { access_token?: string } | null) => u?.access_token,
    getIdToken: (u: { id_token?: string } | null) => u?.id_token,
    userFromTokenResponse: (tokens: {
      access_token: string
      id_token?: string
      refresh_token?: string
    }) => ({
      access_token: tokens.access_token,
      id_token: tokens.id_token,
      refresh_token: tokens.refresh_token,
      expired: false,
    }),
  }
})

vi.mock('../../src/oidc/silent-renew', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/oidc/silent-renew')>()
  return {
    ...actual,
    silentAuthorizeWithRetry: vi.fn(),
    exchangeCode: vi.fn(),
    refreshTokenGrant: vi.fn(),
    revokeToken: vi.fn().mockResolvedValue(undefined),
  }
})

import { createAtolBrowserAuth } from '../../src/client/browser-auth'
import {
  silentAuthorizeWithRetry,
  exchangeCode,
} from '../../src/oidc/silent-renew'
import * as encryptionModule from '../../src/crypto/encryption'

const mockAuthorize = vi.mocked(silentAuthorizeWithRetry)
const mockExchange = vi.mocked(exchangeCode)

const ISSUER = 'https://auth.atol.test'
const CLIENT_ID = 'atol_kid_test'
const REDIRECT = 'https://app.test/cb'

// ---- KEK/DEK fixtures. Wrapping is a REAL AES-256-GCM encrypt so the
// client's unwrap succeeds/fails authentically (auth-tag verified). ----

function fixtureKEK(): Uint8Array {
  const b = new Uint8Array(32)
  for (let i = 0; i < 32; i++) b[i] = (i + 1) & 0xff
  return b
}
function fixtureDEK(): Uint8Array {
  const b = new Uint8Array(32)
  for (let i = 0; i < 32; i++) b[i] = (255 - i) & 0xff
  return b
}
function fixtureNonce(): Uint8Array {
  const n = new Uint8Array(12)
  for (let i = 0; i < 12; i++) n[i] = (7 * i + 3) & 0xff
  return n
}
function toBase64(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!)
  return btoa(s)
}
function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Wrap `dek` under `kek` (AES-256-GCM) -> base64(nonce || ciphertext||tag). */
async function wrapDEK(
  kek: Uint8Array,
  dek: Uint8Array,
  nonce: Uint8Array,
): Promise<string> {
  const key = await nodeWebCrypto.subtle.importKey('raw', kek, { name: 'AES-GCM' }, false, [
    'encrypt',
  ])
  const ciphertext = new Uint8Array(
    await nodeWebCrypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, dek),
  )
  const out = new Uint8Array(nonce.length + ciphertext.length)
  out.set(nonce, 0)
  out.set(ciphertext, nonce.length)
  return toBase64(out)
}

/** An ID token carrying the wrapped-DEK claim (or no claim when omitted). */
function idTokenWith(wrappedDEK?: string): string {
  return wrappedDEK
    ? makeIDToken({ 'atol:wrapped_dek': wrappedDEK })
    : makeIDToken()
}

function makeClient(deriveEncryptionKey = true, useRefreshTokens = false) {
  return createAtolBrowserAuth({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT,
    deriveEncryptionKey,
    useRefreshTokens,
  })
}

/** Wipe the vault DB between tests so rehydrate/provision start clean. */
function resetVaultDB(): Promise<void> {
  return new Promise((resolve) => {
    const req = indexedDB.deleteDatabase('atol-sdk')
    req.onsuccess = () => resolve()
    req.onerror = () => resolve()
    req.onblocked = () => resolve()
  })
}

beforeEach(async () => {
  manager = freshManager()
  sessionStorage.clear()
  globalThis.localStorage?.clear()
  window.history.replaceState({}, '', '/')
  window.location.hash = ''
  await resetVaultDB()
})

afterEach(async () => {
  vi.clearAllMocks()
  vi.restoreAllMocks()
  await resetVaultDB()
})

describe('createAtolBrowserAuth -- KEK/DEK on a fresh login callback', () => {
  it('unwraps the DEK and surfaces it as encryptionKey (no error)', async () => {
    const dek = fixtureDEK()
    const wrapped = await wrapDEK(fixtureKEK(), dek, fixtureNonce())
    // Callback URL carries the KEK in the fragment + the code in the query.
    window.history.replaceState(
      {},
      '',
      `/cb?code=authcode&state=xyz#atol_enc_key=${encodeURIComponent(toBase64Url(fixtureKEK()))}`,
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idTokenWith(wrapped),
    })

    const client = makeClient()
    const session = await client.init()

    expect(session.isAuthenticated).toBe(true)
    expect(session.encryptionKey).toBeInstanceOf(Uint8Array)
    expect(Array.from(session.encryptionKey!)).toEqual(Array.from(dek))
    expect(session.encryptionError).toBeUndefined()
    // Accessor mirrors the session payload.
    expect(Array.from(client.getEncryptionKey()!)).toEqual(Array.from(dek))
    expect(client.getEncryptionError()).toBeUndefined()
    client.destroy()
  })

  it('TAMPER: an auth-tag failure surfaces encryptionError and yields NO key', async () => {
    // Correctly wrap, then flip a ciphertext byte so the GCM tag fails.
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    const raw = Uint8Array.from(atob(wrapped), (c) => c.charCodeAt(0))
    raw[20] ^= 0x01
    const tampered = toBase64(raw)

    window.history.replaceState(
      {},
      '',
      `/cb?code=authcode&state=xyz#atol_enc_key=${encodeURIComponent(toBase64Url(fixtureKEK()))}`,
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idTokenWith(tampered),
    })

    const client = makeClient()
    const session = await client.init()

    // Fail loud: error present, key ABSENT (never a silently-wrong key).
    expect(session.isAuthenticated).toBe(true)
    expect(session.encryptionKey).toBeUndefined()
    expect(session.encryptionError).toBeInstanceOf(Error)
    expect(client.getEncryptionKey()).toBeUndefined()
    expect(client.getEncryptionError()).toBeInstanceOf(Error)
    client.destroy()
  })

  it('TAMPER: a wrong KEK (auth-tag mismatch) surfaces encryptionError, no key', async () => {
    // Wrap under the real KEK but hand the client a DIFFERENT KEK in the
    // fragment -> the wrapped-DEK auth tag fails to verify.
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    const wrongKEK = new Uint8Array(32).fill(0xaa)
    window.history.replaceState(
      {},
      '',
      `/cb?code=authcode&state=xyz#atol_enc_key=${encodeURIComponent(toBase64Url(wrongKEK))}`,
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idTokenWith(wrapped),
    })

    const client = makeClient()
    const session = await client.init()

    expect(session.encryptionKey).toBeUndefined()
    expect(session.encryptionError).toBeInstanceOf(Error)
    client.destroy()
  })

  it('missing wrapped_dek claim: graceful (no key, no error, no crash)', async () => {
    window.history.replaceState(
      {},
      '',
      `/cb?code=authcode&state=xyz#atol_enc_key=${encodeURIComponent(toBase64Url(fixtureKEK()))}`,
    )
    // ID token WITHOUT the atol:wrapped_dek claim.
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idTokenWith(undefined),
    })

    const client = makeClient()
    const session = await client.init()

    expect(session.isAuthenticated).toBe(true)
    expect(session.encryptionKey).toBeUndefined()
    expect(session.encryptionError).toBeUndefined()
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- fragment KEK is captured BEFORE the URL is stripped', () => {
  it('extracts the fragment KEK before completeLogin strips the callback URL', async () => {
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    const extractSpy = vi.spyOn(encryptionModule, 'extractKEKFromFragment')

    // signinRedirectCallback asserts the fragment KEK was ALREADY captured
    // by the time the callback runs (i.e. extract ran before it). Ordering
    // is the whole reason this logic moved into the core.
    manager.signinRedirectCallback.mockImplementation(async () => {
      expect(extractSpy).toHaveBeenCalledTimes(1)
      return { access_token: makeAccessToken(), id_token: idTokenWith(wrapped) }
    })

    window.history.replaceState(
      {},
      '',
      `/cb?code=authcode&state=xyz#atol_enc_key=${encodeURIComponent(toBase64Url(fixtureKEK()))}`,
    )

    const client = makeClient()
    const session = await client.init()

    // extract ran before the callback, and the callback cleared the query.
    const extractOrder = extractSpy.mock.invocationCallOrder[0]
    const callbackOrder = manager.signinRedirectCallback.mock.invocationCallOrder[0]
    expect(extractOrder).toBeLessThan(callbackOrder)
    expect(window.location.search).toBe('')
    // The fragment KEK survived long enough to derive the key.
    expect(session.encryptionKey).toBeInstanceOf(Uint8Array)
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- deriveEncryptionKey OFF', () => {
  it('never reads the fragment and exposes no key/error', async () => {
    const extractSpy = vi.spyOn(encryptionModule, 'extractKEKFromFragment')
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    window.history.replaceState(
      {},
      '',
      `/cb?code=authcode&state=xyz#atol_enc_key=${encodeURIComponent(toBase64Url(fixtureKEK()))}`,
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idTokenWith(wrapped),
    })

    const client = makeClient(false) // feature OFF
    const session = await client.init()

    expect(session.isAuthenticated).toBe(true)
    // No fragment read, no derived state whatsoever.
    expect(extractSpy).not.toHaveBeenCalled()
    expect(session.encryptionKey).toBeUndefined()
    expect(session.encryptionError).toBeUndefined()
    expect(client.getEncryptionKey()).toBeUndefined()
    expect(client.getEncryptionError()).toBeUndefined()
    client.destroy()
  })
})

describe('createAtolBrowserAuth -- rehydrate across a silent renew keeps the key', () => {
  it('provisions on the callback then rehydrates the same DEK on a later renew', async () => {
    const dek = fixtureDEK()
    const wrapped = await wrapDEK(fixtureKEK(), dek, fixtureNonce())

    // 1) Fresh callback provisions the vault from the fragment KEK.
    window.history.replaceState(
      {},
      '',
      `/cb?code=authcode&state=xyz#atol_enc_key=${encodeURIComponent(toBase64Url(fixtureKEK()))}`,
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(30), // stale -> a forceRenew will rotate
      id_token: idTokenWith(wrapped),
    })
    const client = makeClient()
    await client.init()
    expect(Array.from(client.getEncryptionKey()!)).toEqual(Array.from(dek))

    // 2) A silent renew arrives with NO fragment (renew never has one) but the
    // wrapped-DEK claim rides the fresh ID token again. The key must persist:
    // the provider used to re-derive here; the core keeps the already-derived
    // key (deriveEncKey is a no-op when a key is present) and, on a fresh
    // client with cleared state, rehydrates from the vault.
    window.history.replaceState({}, '', '/') // no callback, no fragment
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
    mockExchange.mockResolvedValue({
      access_token: makeAccessToken(3600),
      id_token: idTokenWith(wrapped),
      refresh_token: undefined,
      token_type: 'bearer',
      expires_in: 3600,
    })
    const token = await client.forceRenew()
    expect(typeof token).toBe('string')
    // Same DEK still present after the renew.
    expect(Array.from(client.getEncryptionKey()!)).toEqual(Array.from(dek))
    expect(client.getEncryptionError()).toBeUndefined()
    client.destroy()
  })

  it('a fresh client with an existing vault rehydrates the DEK on restore (no fragment)', async () => {
    const dek = fixtureDEK()
    const wrapped = await wrapDEK(fixtureKEK(), dek, fixtureNonce())

    // Seed the vault via a first client's login-callback.
    window.history.replaceState(
      {},
      '',
      `/cb?code=authcode&state=xyz#atol_enc_key=${encodeURIComponent(toBase64Url(fixtureKEK()))}`,
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idTokenWith(wrapped),
    })
    const first = makeClient()
    await first.init()
    expect(first.getEncryptionKey()).toBeInstanceOf(Uint8Array)
    first.destroy()

    // A SECOND client on the same origin (page reload) with NO fragment:
    // restore via silent renew, then rehydrate the DEK from the vault.
    manager = freshManager()
    window.history.replaceState({}, '', '/')
    window.location.hash = ''
    mockAuthorize.mockResolvedValue({ code: 'silent', state: 's', codeVerifier: 'v' })
    mockExchange.mockResolvedValue({
      access_token: makeAccessToken(3600),
      id_token: idTokenWith(wrapped),
      refresh_token: undefined,
      token_type: 'bearer',
      expires_in: 3600,
    })
    const second = makeClient()
    const session = await second.init()
    expect(session.isAuthenticated).toBe(true)
    expect(Array.from(second.getEncryptionKey()!)).toEqual(Array.from(dek))
    expect(second.getEncryptionError()).toBeUndefined()
    second.destroy()
  })
})

describe('createAtolBrowserAuth -- logout clears the encryption key', () => {
  it('drops encryptionKey and wipes the vault on logout', async () => {
    const wrapped = await wrapDEK(fixtureKEK(), fixtureDEK(), fixtureNonce())
    window.history.replaceState(
      {},
      '',
      `/cb?code=authcode&state=xyz#atol_enc_key=${encodeURIComponent(toBase64Url(fixtureKEK()))}`,
    )
    manager.signinRedirectCallback.mockResolvedValue({
      access_token: makeAccessToken(),
      id_token: idTokenWith(wrapped),
    })
    manager.getUser.mockResolvedValue({ id_token: idTokenWith(wrapped) })

    const client = makeClient()
    await client.init()
    expect(client.getEncryptionKey()).toBeInstanceOf(Uint8Array)

    let lastSession = client.getEncryptionKey()
    client.onSessionChange((s) => {
      lastSession = s.encryptionKey
    })

    await client.logout()
    // Key gone from both the accessor and the emitted session.
    expect(client.getEncryptionKey()).toBeUndefined()
    expect(client.getEncryptionError()).toBeUndefined()
    expect(lastSession).toBeUndefined()
    client.destroy()
  })
})
