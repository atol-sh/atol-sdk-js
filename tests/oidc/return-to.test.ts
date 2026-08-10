import { describe, expect, it } from 'vitest'
import { normalizeSameOriginReturnTo } from '../../src/oidc/return-to'

const REDIRECT_URI = 'https://app.atol.test/callback'

describe('normalizeSameOriginReturnTo', () => {
  it('accepts and canonicalizes a same-origin absolute-path reference', () => {
    expect(
      normalizeSameOriginReturnTo(
        '/organizations/01ABC/../01XYZ?tab=members#invite',
        REDIRECT_URI,
      ),
    ).toBe('/organizations/01XYZ?tab=members#invite')
  })

  it.each([
    ['', 'empty'],
    ['dashboard', 'relative'],
    ['https://evil.test/dashboard', 'absolute URL'],
    ['//evil.test/dashboard', 'network-path reference'],
    ['/\\evil.test/dashboard', 'backslash authority'],
    [`/dashboard\u0000`, 'control character'],
    [`/${'a'.repeat(2048)}`, 'overlong route'],
  ])('rejects an unsafe %s (%s)', (value) => {
    expect(() =>
      normalizeSameOriginReturnTo(value, REDIRECT_URI),
    ).toThrow(/same-origin absolute path/)
  })

  it('rejects an invalid redirect binding', () => {
    expect(() =>
      normalizeSameOriginReturnTo('/dashboard', 'not a URL'),
    ).toThrow(/same-origin absolute path/)
  })

  it('preserves an absent route', () => {
    expect(normalizeSameOriginReturnTo(undefined, REDIRECT_URI)).toBeUndefined()
  })
})
