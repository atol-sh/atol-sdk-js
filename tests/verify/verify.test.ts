// @vitest-environment node
/**
 * verifyIdToken authenticates callback/renewal ID tokens against the IdP
 * JWKS. Runs in the Node environment so jose's Node build and
 * Uint8Array share a realm (jsdom ships a second Uint8Array constructor
 * that breaks jose's instanceof checks).
 *
 * This is the identity-token trust gate, so the negative matrix is
 * exhaustive: forged signature, wrong issuer/audience/nonce, expired,
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
const RESOURCE_AUDIENCE = 'https://api.example.com'

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

import {
  verifyAccessToken,
  verifyIdToken,
  _resetDiscoveryCache,
} from '../../src/verify/verify'

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
  audience?: string | string[]
  key?: KeyLike
  kid?: string
  exp?: string | number
  nbf?: number
  omitSub?: boolean
  nonce?: string
  azp?: string
}) {
  const jwt = new SignJWT({
    'atol:org_id': 'org-1',
    ...(overrides?.nonce ? { nonce: overrides.nonce } : {}),
    ...(overrides?.azp ? { azp: overrides.azp } : {}),
  }).setProtectedHeader({
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

async function signAccessToken(overrides?: {
  issuer?: string
  audience?: string | string[]
  key?: KeyLike
  exp?: string | number
  omitSub?: boolean
  typ?: string | null
}) {
  const jwt = new SignJWT({ 'atol:org_id': '01KV4BNVVNZ4TNY0PP0CVXPZWP' })
    .setProtectedHeader({
      alg: 'ES256',
      kid: 'k1',
      ...(overrides?.typ === null ? {} : { typ: overrides?.typ ?? 'at+jwt' }),
    })
    .setIssuer(overrides?.issuer ?? AUTHORITY)
    .setAudience(overrides?.audience ?? RESOURCE_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(overrides?.exp ?? '1h')
  if (!overrides?.omitSub) jwt.setSubject('user-1')
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

  it('accepts a callback token whose nonce matches stored OIDC state', async () => {
    const token = await signIdToken({ nonce: 'stored-nonce' })
    await expect(
      verifyIdToken(token, {
        authority: AUTHORITY,
        clientId: CLIENT_ID,
        nonce: 'stored-nonce',
      }),
    ).resolves.toMatchObject({ nonce: 'stored-nonce' })
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

describe('[R35] verifyAccessToken', () => {
  it('accepts only a signed, current token for the configured resource audience', async () => {
    const token = await signAccessToken()
    await expect(
      verifyAccessToken(token, {
        authority: AUTHORITY,
        audience: RESOURCE_AUDIENCE,
      }),
    ).resolves.toMatchObject({
      sub: 'user-1',
      aud: RESOURCE_AUDIENCE,
    })
  })

  it.each([
    ['wrong issuer', { issuer: 'https://evil.test' }],
    ['wrong audience', { audience: 'another-api' }],
    ['expired', { exp: Math.floor(Date.now() / 1000) - 60 }],
    ['missing subject', { omitSub: true }],
  ])('rejects %s', async (_name, overrides) => {
    const token = await signAccessToken(overrides)
    await expect(
      verifyAccessToken(token, {
        authority: AUTHORITY,
        audience: RESOURCE_AUDIENCE,
      }),
    ).rejects.toThrow()
  })

  it('rejects an access token signed by a key outside the issuer JWKS', async () => {
    const { privateKey: attackerKey } = await generateKeyPair('ES256', {
      extractable: true,
    })
    const token = await signAccessToken({ key: attackerKey })
    await expect(
      verifyAccessToken(token, {
        authority: AUTHORITY,
        audience: RESOURCE_AUDIENCE,
      }),
    ).rejects.toThrow()
  })

  it.each([
    ['an ID-token type', 'JWT'],
    ['no explicit type', null],
  ])('[R47] rejects %s even when every claim and signature is valid', async (_name, typ) => {
    const token = await signAccessToken({ typ })
    await expect(
      verifyAccessToken(token, {
        authority: AUTHORITY,
        audience: RESOURCE_AUDIENCE,
      }),
    ).rejects.toThrow(/access token type/)
  })

  it('rejects an access token whose subject is present but empty', async () => {
    const token = await new SignJWT({ sub: '' })
      .setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'at+jwt' })
      .setIssuer(AUTHORITY)
      .setAudience(RESOURCE_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(signingKey)
    await expect(
      verifyAccessToken(token, {
        authority: AUTHORITY,
        audience: RESOURCE_AUDIENCE,
      }),
    ).rejects.toThrow(/no usable sub/)
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

  it('rejects a callback token whose nonce does not match stored state', async () => {
    const token = await signIdToken({ nonce: 'different-nonce' })
    await expect(
      verifyIdToken(token, {
        authority: AUTHORITY,
        clientId: CLIENT_ID,
        nonce: 'stored-nonce',
      }),
    ).rejects.toThrow(/nonce mismatch/)
  })

  it('rejects a token whose authorized party is a different client', async () => {
    const token = await signIdToken({ azp: 'other-client' })
    await expect(
      verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow(/authorized party mismatch/)
  })

  it('rejects multiple audiences without this client as authorized party', async () => {
    const token = await signIdToken({ audience: [CLIENT_ID, 'another-client'] })
    await expect(
      verifyIdToken(token, { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow(/multiple audiences/)
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
  it('rejects an invalid configured authority before attempting transport', async () => {
    _resetDiscoveryCache()
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await expect(
      verifyIdToken(await signIdToken(), {
        authority: 'not an absolute URL',
        clientId: CLIENT_ID,
      }),
    ).rejects.toThrow(/valid absolute URL/)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('normalizes a discovery transport rejection as a network error', async () => {
    _resetDiscoveryCache()
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    await expect(
      verifyIdToken(await signIdToken(), { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toMatchObject({ name: 'NetworkError' })
  })

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

  it('rejects when the discovery document is missing issuer', async () => {
    _resetDiscoveryCache()
    stubDiscovery({ doc: { jwks_uri: JWKS_URI } })
    await expect(
      verifyIdToken(await signIdToken(), { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow(/missing issuer/)
  })

  it('rejects when discovery advertises a different issuer', async () => {
    _resetDiscoveryCache()
    stubDiscovery({ doc: { issuer: 'https://evil.test', jwks_uri: JWKS_URI } })
    await expect(
      verifyIdToken(await signIdToken(), { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow(/issuer does not match configured authority/)
  })

  it('rejects a discovery document with a non-absolute jwks_uri', async () => {
    _resetDiscoveryCache()
    stubDiscovery({ doc: { issuer: AUTHORITY, jwks_uri: '/relative-jwks' } })
    await expect(
      verifyIdToken(await signIdToken(), { authority: AUTHORITY, clientId: CLIENT_ID }),
    ).rejects.toThrow(/jwks_uri is not a valid absolute URL/)
  })
})
