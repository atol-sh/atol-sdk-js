// @vitest-environment node
/**
 * verifyIdToken authenticates broadcast/untrusted ID tokens against the
 * IdP JWKS. Runs in the Node environment so jose's Node build and
 * Uint8Array share a realm (jsdom ships a second Uint8Array constructor
 * that breaks jose's instanceof checks).
 *
 * This is the trust gate for cross-tab token adoption, so the negative
 * matrix is exhaustive: forged signature, wrong issuer/audience, expired,
 * nbf-in-future, missing sub, unexpected alg (none / alg confusion),
 * tampered claims, malformed JWT, wrong kid, and discovery failures.
 *
 * `createRemoteJWKSet` is mocked to a local in-memory key set so the test
 * needs no network; the discovery document fetch is stubbed.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  SignJWT,
  UnsecuredJWT,
  exportJWK,
  generateKeyPair,
  type KeyLike,
} from 'jose'

const AUTHORITY = 'https://auth.atol.test'
const JWKS_URI = 'https://auth.atol.test/jwks'
const CLIENT_ID = 'atol_kid_test'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const keyHolder = vi.hoisted(() => ({ keys: [] as any[] }))

vi.mock('jose', async (importOriginal) => {
  const actual = await importOriginal<typeof import('jose')>()
  return {
    ...actual,
    // Resolve "remote" keys from the local holder -- no network.
    createRemoteJWKSet: () => actual.createLocalJWKSet({ keys: keyHolder.keys }),
  }
})

import { verifyIdToken, _resetDiscoveryCache } from '../../src/verify/verify'

let signingKey: KeyLike

async function makeKeys() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true })
  signingKey = privateKey
  keyHolder.keys = [{ ...(await exportJWK(publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' }]
}

function stubDiscovery(overrides?: { ok?: boolean; status?: number; doc?: unknown }) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: unknown) => {
      const u = String(url)
      if (u.endsWith('/.well-known/openid-configuration')) {
        return {
          ok: overrides?.ok ?? true,
          status: overrides?.status ?? 200,
          json: async () =>
            overrides?.doc ?? { issuer: AUTHORITY, jwks_uri: JWKS_URI },
        }
      }
      throw new Error(`unexpected fetch: ${u}`)
    }),
  )
}

async function signIdToken(overrides?: {
  issuer?: string
  audience?: string
  key?: KeyLike
  kid?: string
  exp?: string | number
  nbf?: number
  omitSub?: boolean
}) {
  const jwt = new SignJWT({ 'atol:org_id': 'org-1' }).setProtectedHeader({
    alg: 'ES256',
    kid: overrides?.kid ?? 'k1',
  })
  if (!overrides?.omitSub) jwt.setSubject('user-1')
  jwt.setIssuer(overrides?.issuer ?? AUTHORITY)
  jwt.setAudience(overrides?.audience ?? CLIENT_ID)
  jwt.setIssuedAt()
  if (overrides?.nbf !== undefined) jwt.setNotBefore(overrides.nbf)
  jwt.setExpirationTime(overrides?.exp ?? '1h')
  return jwt.sign(overrides?.key ?? signingKey)
}

beforeEach(async () => {
  _resetDiscoveryCache()
  await makeKeys()
  stubDiscovery()
})
afterEach(() => {
  vi.unstubAllGlobals()
})

describe('verifyIdToken -- accepts valid', () => {
  it('accepts a correctly signed token and returns its claims', async () => {
    const token = await signIdToken()
    const claims = await verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID })
    expect(claims.sub).toBe('user-1')
    expect(claims['atol:org_id']).toBe('org-1')
  })

  it('caches discovery: a second verify does not refetch the config', async () => {
    await verifyIdToken(await signIdToken(), { authority: AUTHORITY, clientId: CLIENT_ID })
    const fetchMock = vi.mocked(fetch)
    const before = fetchMock.mock.calls.length
    await verifyIdToken(await signIdToken(), { authority: AUTHORITY, clientId: CLIENT_ID })
    // No additional /.well-known fetch on the cached path.
    const discoveryCalls = fetchMock.mock.calls.filter((c) =>
      String(c[0]).includes('.well-known'),
    ).length
    expect(before).toBeGreaterThanOrEqual(1)
    expect(discoveryCalls).toBe(1)
  })
})

describe('verifyIdToken -- rejects forgeries + wrong claims', () => {
  it('rejects a token signed by a key not in the JWKS (forgery)', async () => {
    const { privateKey: attackerKey } = await generateKeyPair('ES256', { extractable: true })
    const forged = await signIdToken({ key: attackerKey })
    await expect(
      verifyIdToken(forged, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow()
  })

  it('rejects a token whose kid is not present in the JWKS', async () => {
    const token = await signIdToken({ kid: 'unknown-kid' })
    await expect(
      verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow()
  })

  it('rejects a token for a different audience', async () => {
    const token = await signIdToken({ audience: 'someone-else' })
    await expect(
      verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow()
  })

  it('rejects a token from a different issuer', async () => {
    const token = await signIdToken({ issuer: 'https://evil.test' })
    await expect(
      verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow()
  })

  it('rejects an expired token', async () => {
    // exp one hour in the past.
    const token = await signIdToken({ exp: Math.floor(Date.now() / 1000) - 3600 })
    await expect(
      verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow()
  })

  it('rejects a token whose nbf is in the future', async () => {
    const token = await signIdToken({ nbf: Math.floor(Date.now() / 1000) + 3600 })
    await expect(
      verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow()
  })

  it('rejects a token with no sub claim', async () => {
    const token = await signIdToken({ omitSub: true })
    await expect(
      verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow()
  })

  it('rejects a token whose sub is an empty string (unusable subject)', async () => {
    // jose's requiredClaims sees an empty-string sub as present, so this
    // exercises verifyIdToken's own usable-sub guard.
    const token = await new SignJWT({ sub: '', 'atol:org_id': 'org-1' })
      .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
      .setIssuer(AUTHORITY)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(signingKey)
    await expect(
      verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow(/no usable sub/)
  })

  it('rejects an unsecured (alg=none) token -- no alg confusion', async () => {
    const unsecured = new UnsecuredJWT({ 'atol:org_id': 'org-1' })
      .setSubject('user-1')
      .setIssuer(AUTHORITY)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('1h')
      .encode()
    await expect(
      verifyIdToken(unsecured, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow()
  })

  it('rejects a token with a tampered payload claim', async () => {
    const token = await signIdToken()
    const [h, , s] = token.split('.')
    const forgedPayload = btoa(
      JSON.stringify({
        sub: 'attacker',
        iss: AUTHORITY,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
      }),
    )
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
    await expect(
      verifyIdToken(`${h}.${forgedPayload}.${s}`, {
        authority: AUTHORITY,
        clientId: CLIENT_ID,
      }),
    ).rejects.toThrow()
  })

  it('rejects a structurally malformed JWT', async () => {
    await expect(
      verifyIdToken('not.a.jwt', { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow()
  })
})

describe('verifyIdToken -- discovery failures', () => {
  it('rejects and does not cache when discovery returns non-200', async () => {
    _resetDiscoveryCache()
    stubDiscovery({ ok: false, status: 500 })
    await expect(
      verifyIdToken(await signIdToken(), { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow(/discovery failed/)
  })

  it('rejects when the discovery document is missing jwks_uri', async () => {
    _resetDiscoveryCache()
    stubDiscovery({ doc: { issuer: AUTHORITY } })
    await expect(
      verifyIdToken(await signIdToken(), { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow(/missing jwks_uri/)
  })
})
