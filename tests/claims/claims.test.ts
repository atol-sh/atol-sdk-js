import { describe, it, expect } from 'vitest'
import {
  parseAtolUser,
  decodeJWTPayload,
  getTokenExpiry,
} from '../../src/claims/claims'

function makeJWT(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
  const sig = btoa('fake-signature')
  return `${header}.${body}.${sig}`
}

describe('parseAtolUser', () => {
  it('parses all Atol claims', () => {
    const token = makeJWT({
      sub: 'usr_01JQXYZ',
      email: 'remi@example.com',
      name: 'Remi',
      'atol:org_id': 'org_01ABC',
      'atol:plan': 'pro',
      'atol:roles': ['admin', 'editor'],
      'atol:auth_method': 'oidc',
      'atol:mfa_verified': true,
      email_verified: true,
    })

    const user = parseAtolUser(token)

    expect(user.id).toBe('usr_01JQXYZ')
    expect(user.email).toBe('remi@example.com')
    expect(user.emailVerified).toBe(true)
    expect(user.name).toBe('Remi')
    expect(user).not.toHaveProperty('orgId')
    expect(user).not.toHaveProperty('plan')
    expect(user).not.toHaveProperty('roles')
    expect(user.authMethod).toBe('oidc')
    expect(user.mfaVerified).toBe(true)
  })

  it('handles missing optional claims', () => {
    const token = makeJWT({ sub: 'usr_123' })
    const user = parseAtolUser(token)

    expect(user.id).toBe('usr_123')
    expect(user.email).toBe('')
    expect(user.emailVerified).toBe(false)
    expect(user.name).toBe('')
    expect(user).not.toHaveProperty('orgId')
    expect(user).not.toHaveProperty('plan')
    expect(user).not.toHaveProperty('roles')
    expect(user.authMethod).toBe('')
    expect(user.mfaVerified).toBe(false)
  })

  it('does not expose role claims as user identity', () => {
    const token = makeJWT({ sub: 'usr_123', 'atol:roles': 'not-an-array' })
    expect(parseAtolUser(token)).not.toHaveProperty('roles')
  })

  it('coerces a non-string sub to the empty id (rejected as user)', () => {
    const token = makeJWT({ sub: 12345 })
    expect(parseAtolUser(token).id).toBe('')
  })

  it('throws on invalid JWT format', () => {
    expect(() => parseAtolUser('not-a-jwt')).toThrow('Invalid JWT')
  })
})

describe('decodeJWTPayload', () => {
  it('decodes a base64url payload with claims', () => {
    const token = makeJWT({ sub: 'x', foo: 'bar', n: 42 })
    const payload = decodeJWTPayload(token)
    expect(payload.sub).toBe('x')
    expect(payload.foo).toBe('bar')
    expect(payload.n).toBe(42)
  })

  it('throws when the token does not have three segments', () => {
    expect(() => decodeJWTPayload('a.b')).toThrow(/expected 3 parts/)
  })
})

describe('getTokenExpiry', () => {
  it('returns exp in milliseconds', () => {
    const exp = Math.floor(Date.now() / 1000) + 100
    expect(getTokenExpiry(makeJWT({ sub: 'x', exp }))).toBe(exp * 1000)
  })

  it('returns null when exp is absent', () => {
    expect(getTokenExpiry(makeJWT({ sub: 'x' }))).toBeNull()
  })

  it('returns null when exp is not numeric', () => {
    expect(getTokenExpiry(makeJWT({ sub: 'x', exp: 'soon' }))).toBeNull()
  })

  it('returns null on a malformed token instead of throwing', () => {
    expect(getTokenExpiry('garbage')).toBeNull()
  })
})
